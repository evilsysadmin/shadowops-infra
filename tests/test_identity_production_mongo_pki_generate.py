"""Private workstation Mongo PKI generator; real native OpenSSL synthetic CI."""
import base64
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_pki_generate",
    ROOT / "scripts/identity_production_mongo_pki_generate.py",
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PKIGenerationTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL native CLI missing")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def test_real_offline_generation_crypto_and_separation(self):
        destination = self.home / "private-production-mongo"
        m.create_local_bundle(destination, ca_passphrase=b'test_only_43_char_offline_CA_passphrase_for_CI_2026')
        offline = destination / "offline-ca-KEEP-LOCAL"
        transfer = destination / "transfer-THREE-FILES-ONLY"
        self.assertTrue((offline / "ca-private.key").is_file())
        self.assertTrue((offline / "ca-private.key").read_bytes().startswith(
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        good = subprocess.run(
            ["openssl", "pkey", "-in", str(offline / "ca-private.key"),
             "-passin", "stdin", "-noout"],
            input=b'test_only_43_char_offline_CA_passphrase_for_CI_2026' + b"\n", capture_output=True, timeout=10,
        )
        self.assertEqual(good.returncode, 0)
        wrong = subprocess.run(
            ["openssl", "pkey", "-in", str(offline / "ca-private.key"),
             "-passin", "stdin", "-noout"],
            input=b"incorrect-secrets-must-never-pass" + b"\n",
            capture_output=True, timeout=10,
        )
        self.assertNotEqual(wrong.returncode, 0)
        self.assertEqual({p.name for p in offline.iterdir()}, {"ca-private.key"})
        self.assertEqual({p.name for p in transfer.iterdir()}, set(m.NAMES))
        self.assertNotIn("ca-private.key", {p.name for p in transfer.iterdir()})
        for p in (destination, offline, transfer):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700)
        for p in (*offline.iterdir(), *transfer.iterdir()):
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        for hostname in m.CERT_DNS:
            self.assertEqual(subprocess.run(
                ["openssl", "verify", "-CAfile", str(transfer / "ca.pem"),
                 "-purpose", "sslserver", "-verify_hostname", hostname,
                 str(transfer / "mongo.pem")],
                capture_output=True, timeout=10,
            ).returncode, 0)
        self.assertEqual(subprocess.run(
            ["openssl", "verify", "-CAfile", str(transfer / "ca.pem"),
             "-purpose", "sslserver", "-verify_ip", m.CERT_IP,
             str(transfer / "mongo.pem")],
            capture_output=True, timeout=10,
        ).returncode, 0)
        self.assertEqual(len(base64.b64decode(
            (transfer / "replica.key").read_bytes().strip(), validate=True
        )), 384)

    def test_new_bundle_is_never_overwritten(self):
        target = self.home / "bundle"
        m.create_local_bundle(target, ca_passphrase=b'test_only_43_char_offline_CA_passphrase_for_CI_2026')
        before = (target / "offline-ca-KEEP-LOCAL" / "ca-private.key").read_bytes()
        with self.assertRaises(m.Refused):
            m.create_local_bundle(target, ca_passphrase=b'test_only_43_char_offline_CA_passphrase_for_CI_2026')
        after = (target / "offline-ca-KEEP-LOCAL" / "ca-private.key").read_bytes()
        self.assertEqual(before, after)

    def test_operator_home_parent_and_symlink_boundary(self):
        good = m.output_path(str(self.home / "fresh"), home=self.home,
                             euid=os.geteuid())
        self.assertEqual(good, self.home / "fresh")
        (self.home / "fresh").mkdir()
        with self.assertRaises(m.Refused):
            m.output_path(str(self.home / "fresh"), home=self.home,
                          euid=os.geteuid())
        external = tempfile.TemporaryDirectory()
        self.addCleanup(external.cleanup)
        (self.home / "foreign").symlink_to(external.name)
        with self.assertRaises(m.Refused):
            m.output_path(str(self.home / "foreign" / "new"),
                          home=self.home, euid=os.geteuid())
        with self.assertRaises(m.Refused):
            m.output_path("relative-folder", home=self.home, euid=os.geteuid())
        with self.assertRaises(m.Refused):
            m.output_path(str(self.home / "nested" / "missing"),
                          home=self.home, euid=os.geteuid())

    def test_passphrase_is_masked_double_entered_and_required(self):
        secret = "strong-private-CA-only-passphrase-2026-signature"
        self.assertEqual(m.passphrase_from_tty(prompt=lambda _: secret), secret.encode())
        for pair in (("mismatch-password-A-32-characters", "mismatch-password-B-32-characters"),
                     ("weak", "weak"), ("bad\nnewline" * 5, "bad\nnewline" * 5)):
            answers = iter(pair)
            with self.subTest(pair=pair), self.assertRaises(m.Refused):
                m.passphrase_from_tty(prompt=lambda _: next(answers))
        target = self.home / "must-not-exist-without-passphrase"
        with self.assertRaises(TypeError):
            m.create_local_bundle(target)
        self.assertFalse(target.exists())

    def test_ca_passphrase_uses_stdin_only_and_failed_openssl_is_refused(self):
        secret = b"synthetic-secret-only-for-CI-test-more-than-32-bytes"
        with mock.patch.object(m.subprocess, "run",
                               return_value=SimpleNamespace(returncode=0)) as run:
            m.run_openssl_secret(
                "genpkey", "-aes-256-cbc", "-pass", "stdin",
                ca_passphrase=secret,
            )
        args, kwargs = run.call_args
        self.assertEqual(args[0][:2], ["openssl", "genpkey"])
        self.assertNotIn(secret.decode(), " ".join(args[0]))
        self.assertEqual(kwargs["input"], secret + bytes([10]))
        self.assertNotIn("env", kwargs)
        self.assertIs(kwargs["stdout"], subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"], subprocess.DEVNULL)
        with mock.patch.object(m.subprocess, "run",
                               return_value=SimpleNamespace(returncode=1)), \
             self.assertRaises(m.Refused):
            m.run_openssl_secret("genpkey", "-pass", "stdin",
                                 ca_passphrase=secret)
        for invalid in (b"weak", b"bad" + bytes([10]) + b"Z" * 40):
            with mock.patch.object(m.subprocess, "run") as run, \
                 self.assertRaises(m.Refused):
                m.run_openssl_secret("genpkey", ca_passphrase=invalid)
            run.assert_not_called()

    def test_root_ci_tty_and_confirmation_gates(self):
        tty = SimpleNamespace(isatty=lambda: True)
        bad = SimpleNamespace(isatty=lambda: False)
        for reason, config in (
            ("root", dict(euid=0, stdin=tty, stdout=tty, env={})),
            ("ci", dict(euid=1001, stdin=tty, stdout=tty, env={"CI": "1"})),
            ("no-input-tty", dict(euid=1001, stdin=bad, stdout=tty, env={})),
            ("no-output-tty", dict(euid=1001, stdin=tty, stdout=bad, env={})),
            ("wrong-ack", dict(euid=1001, stdin=tty, stdout=tty, env={})),
        ):
            with self.subTest(reason=reason), self.assertRaises(m.Refused):
                m.authorization(prompt=lambda _: "WRONG" if reason=="wrong-ack" else m.ACK,
                                **config)

    def test_generated_files_are_synthetic_not_in_ci_or_repo(self):
        p = subprocess.run([
            "python3", "-I", str(ROOT / "scripts/identity_production_mongo_pki_generate.py"),
            "generate", str(self.home / "should-not-exist"),
        ], capture_output=True, text=True, timeout=10,
            env={"CI": "true", "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertNotIn("ca-private.key", p.stdout + p.stderr)
        self.assertFalse((self.home / "should-not-exist").exists())
        plan = subprocess.run([
            "python3", "-I", str(ROOT / "scripts/identity_production_mongo_pki_generate.py"),
            "plan"], capture_output=True, text=True, timeout=10,
            env={"CI": "true", "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        self.assertEqual(plan.returncode, 0, plan.stderr)
        self.assertIn("ca_private=encrypted-offline-only", plan.stdout)
        self.assertIn("overwrite=no remote=no", plan.stdout)

    def test_make_targets_cannot_run_generate_automatically(self):
        targets = (
            ("identity-prod-mongo-pki-plan", "plan"),
            ("identity-prod-mongo-pki-generate", "generate"),
        )
        for target, mode in targets:
            with self.subTest(target=target):
                p = subprocess.run(["make", "-n", "--no-print-directory", target],
                                   cwd=ROOT, capture_output=True, text=True, timeout=10)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertIn("identity_production_mongo_pki_generate.py " + mode, p.stdout)
                self.assertNotIn("sudo", p.stdout)
                self.assertNotIn("ssh", p.stdout)
                self.assertNotIn("docker", p.stdout)


if __name__ == "__main__":
    unittest.main()
