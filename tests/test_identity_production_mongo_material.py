"""Offline, ephemeral PKI tests for Mongo host TLS material admission."""
import base64
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_material",
    ROOT / "scripts/identity_production_mongo_material.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MaterialTests(unittest.TestCase):
    def openssl(self, *args):
        p = subprocess.run(["openssl", *args], check=False,
                           capture_output=True, timeout=20)
        self.assertEqual(p.returncode, 0, "synthetic fixture construction failed")

    def setUp(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL native CLI missing")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.offline = root / "offline"
        self.private = root / "a1"
        self.offline.mkdir(mode=0o700)
        self.private.mkdir(mode=0o700)

        self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt",
                     "ec_paramgen_curve:P-256", "-out", str(self.offline / "ca.key"))
        self.openssl("req", "-new", "-x509", "-key", str(self.offline / "ca.key"),
                     "-subj", "/CN=Production-Only-Mongo-CA",
                     "-days", "90", "-sha256",
                     "-addext", "basicConstraints=critical,CA:TRUE",
                     "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                     "-out", str(self.private / "ca.pem"))
        self.issue_cert()
        (self.private / "replica.key").write_bytes(
            base64.b64encode(os.urandom(384)) + b"\n"
        )
        self.patches = [
            patch.object(m.host, "inspect_private_files", return_value=None),
            patch.object(m, "CA", self.private / "ca.pem"),
            patch.object(m, "CERT_KEY", self.private / "mongo.pem"),
            patch.object(m, "REPLICA_KEY", self.private / "replica.key"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def issue_cert(self, *, sans="DNS:identity-mongo-production,DNS:localhost,IP:127.0.0.1",
                   days=60, new_key=True):
        key = self.offline / "server.key"
        if new_key:
            self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt",
                         "ec_paramgen_curve:P-256", "-out", str(key))
        self.openssl("req", "-new", "-key", str(key), "-subj",
                     "/CN=identity-mongo-production",
                     "-out", str(self.offline / "server.csr"))
        ext = self.offline / "server.ext"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=" + sans + "\n"
        )
        self.openssl("x509", "-req", "-in", str(self.offline / "server.csr"),
                     "-CA", str(self.private / "ca.pem"),
                     "-CAkey", str(self.offline / "ca.key"),
                     "-set_serial", "0x1234", "-days", str(days), "-sha256",
                     "-extfile", str(ext), "-out", str(self.offline / "server.crt"))
        (self.private / "mongo.pem").write_bytes(
            (self.offline / "server.crt").read_bytes() + key.read_bytes()
        )

    def test_real_cert_chain_dns_ip_key_and_replica_pass(self):
        m.verify_material(euid=0, env={})

    def test_invalid_server_san_rejected(self):
        self.issue_cert(sans="DNS:other-mongo,DNS:localhost,IP:127.0.0.1", new_key=False)
        with self.assertRaises(m.Refused):
            m.verify_material(euid=0, env={})

    def test_missing_ip_san_rejected(self):
        self.issue_cert(sans="DNS:identity-mongo-production,DNS:localhost", new_key=False)
        with self.assertRaises(m.Refused):
            m.verify_material(euid=0, env={})

    def test_wrong_key_material_rejected(self):
        rogue = self.offline / "rogue.key"
        self.openssl("genpkey", "-algorithm", "EC", "-pkeyopt",
                     "ec_paramgen_curve:P-256", "-out", str(rogue))
        leaf = (self.private / "mongo.pem").read_bytes().split(b"-----BEGIN PRIVATE KEY-----")[0]
        (self.private / "mongo.pem").write_bytes(leaf + rogue.read_bytes())
        with self.assertRaises(m.Refused):
            m.verify_material(euid=0, env={})

    def test_near_expiry_refused(self):
        self.issue_cert(days=7, new_key=False)
        with self.assertRaises(m.Refused):
            m.verify_material(euid=0, env={})

    def test_replica_malformed_weak_or_excessive_rejected(self):
        path = self.private / "replica.key"
        valid = path.read_bytes()
        for bad in (b"", b"tiny\n", b"a"*500, b"!"*400,
                    b"A"*2200, b"\x00"*500, b"\r"*500,
                    b"mongo-staging-key-file"):
            with self.subTest(bad=bad[:10]):
                path.write_bytes(bad)
                with self.assertRaises(m.Refused):
                    m.verify_material(euid=0, env={})
        path.write_bytes(valid)
        m.verify_material(euid=0, env={})

    def test_ca_signing_key_must_remain_off_host(self):
        (self.private / "ca.key").write_bytes(b"example")
        with self.assertRaises(m.Refused):
            m.verify_material(euid=0, env={})

    def test_ci_and_unprivileged_denied_before_files(self):
        with patch.object(m.host, "inspect_private_files") as inspect:
            with self.assertRaises(m.Refused):
                m.verify_material(euid=1001, env={})
            with self.assertRaises(m.Refused):
                m.verify_material(euid=0, env={"CI": "true"})
            inspect.assert_not_called()

    def test_plan_and_host_verify_make_operators(self):
        p = subprocess.run(["python3", "-I",
                            str(ROOT / "scripts/identity_production_mongo_material.py"),
                            "plan"], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("inspection=read-only", p.stdout)
        for target, mode in (
            ("identity-prod-mongo-material-plan", "plan"),
            ("identity-prod-mongo-material-verify", "verify"),
        ):
            q = subprocess.run(["make", "--no-print-directory", "-n", target],
                               cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(q.returncode, 0, q.stderr)
            self.assertIn("identity_production_mongo_material.py " + mode, q.stdout)
            self.assertNotIn("docker", q.stdout)
            self.assertNotIn("sudo ", q.stdout)

    def test_ci_verify_is_fail_closed_and_never_prints_secrets(self):
        with patch.dict(os.environ, {"CI": "true"}), \
             redirect_stderr(io.StringIO()) as err, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["verify"]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue().strip(), "IDENTITY_PRODUCTION_MONGO_MATERIAL_REFUSED")


if __name__ == "__main__":
    unittest.main()
