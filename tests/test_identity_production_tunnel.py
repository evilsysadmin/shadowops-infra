"""Offline production tunnel/Cloudflare origin contracts. Never use real secrets."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_production_tunnel_preflight",
    ROOT / "scripts/identity_production_tunnel_preflight.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
DIGEST = "sha256:" + "a" * 64
CONFIG = """tunnel: 123e4567-e89b-42d3-a456-426614174000
credentials-file: /run/secrets/identity-tunnel-credentials.json
ingress:
  - hostname: id.shadowops.dpdns.org
    service: https://identity-production:9443
    originRequest:
      originServerName: id.shadowops.dpdns.org
      httpHostHeader: id.shadowops.dpdns.org
      caPool: /run/secrets/identity-tunnel-origin-ca.pem
  - service: http_status:404
"""

class TunnelTests(unittest.TestCase):
    def test_strict_one_host_and_deny_all_fallback(self):
        m.validate_config(CONFIG)
        bad = (
            CONFIG.replace("id.shadowops.dpdns.org", "id-staging.shadowops.dpdns.org"),
            CONFIG.replace("id.shadowops.dpdns.org", "*.shadowops.dpdns.org"),
            CONFIG.replace("https://identity-production:9443", "http://identity-production:9443"),
            CONFIG.replace("https://identity-production:9443", "https://127.0.0.1:9443"),
            CONFIG.replace("http_status:404", "http_status:200"),
            CONFIG.replace("http_status:404", "https://malicious.example"),
            CONFIG.replace("originServerName: id.shadowops.dpdns.org", "noTLSVerify: true"),
            CONFIG.replace("httpHostHeader: id.shadowops.dpdns.org", "httpHostHeader: evil.test"),
            CONFIG.replace("caPool: /run/secrets/identity-tunnel-origin-ca.pem", "noTLSVerify: true"),
            CONFIG.replace("  - service: http_status:404",
                           "  - hostname: other.example\n    service: http_status:200\n  - service: http_status:404"),
            CONFIG.replace("tunnel: 123e4567-e89b-42d3-a456-426614174000", "tunnel: not-a-uuid"),
            CONFIG.replace("credentials-file: /run/secrets/identity-tunnel-credentials.json",
                           "credentials-file: /tmp/public.json"),
            CONFIG + "protocol: http2\n",
        )
        for value in bad:
            with self.subTest(candidate=value[-90:]), self.assertRaises(m.Refused):
                m.validate_config(value)

    def test_digest_and_compose_surface(self):
        m.validate_overlay()
        for digest in ("", "latest", "sha256:" + "f"*63, "sha256:" + "F"*64,
                       "sha256:" + "f"*64 + "x"):
            with self.subTest(digest=digest), self.assertRaises(m.Refused):
                m.validate(digest, "/never", "/never", "/never")
        self.assertEqual(m.main([]), 2)

    def test_private_inputs_and_certificate_admission(self):
        with tempfile.TemporaryDirectory(prefix="identity-prod-tunnel-test-") as tmp:
            root = Path(tmp)
            config, credentials, ca = [root / x for x in ("config.yml", "credentials.json", "origin-ca.pem")]
            config.write_text(CONFIG)
            credentials.write_text("SYNTHETIC_CONTENT_NOT_TO_BE_PARSED")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                            "-nodes", "-days", "1", "-keyout", str(root/"key.pem"),
                            "-out", str(ca), "-subj", "/CN=synthetic-test-ca"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for p in (config, credentials, ca): p.chmod(0o600)
            def good():
                return m.validate(DIGEST, str(config), str(credentials), str(ca),
                                  expected_uid=os.geteuid())
            good()
            for bad_mode in (0o644, 0o640, 0o200):
                credentials.chmod(bad_mode)
                with self.subTest(mode=bad_mode), self.assertRaises(m.Refused):
                    good()
                credentials.chmod(0o600)
            config.write_text(CONFIG.replace("http_status:404", "http_status:200"))
            with self.assertRaises(m.Refused): good()
            config.write_text(CONFIG)
            ca.write_text("NOT_A_CERTIFICATE")
            with self.assertRaises(m.Refused): good()
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                            "-nodes", "-days", "1", "-keyout", str(root/"key2.pem"),
                            "-out", str(ca), "-subj", "/CN=synthetic-test-ca"],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ca.chmod(0o600)
            good()
            link = root / "config-link.yml"
            link.symlink_to(config)
            with self.assertRaises(m.Refused):
                m.validate(DIGEST, str(link), str(credentials), str(ca),
                           expected_uid=os.geteuid())
            with self.assertRaises(m.Refused):
                m.validate(DIGEST, str(config), str(config), str(ca),
                           expected_uid=os.geteuid())
            with self.assertRaises(m.Refused):
                m.validate(DIGEST, str(config), "relative.json", str(ca),
                           expected_uid=os.geteuid())

    def test_reject_compose_drift_in_tunnel_privileges(self):
        with tempfile.TemporaryDirectory() as temp:
            source = m.OVERLAY.read_text()
            target = Path(temp)/"overlay.yaml"
            for altered in (
                source.replace("read_only: true", "read_only: false", 1),
                source.replace("internal: true", "internal: false"),
                source.replace('profiles: ["production-tunnel"]', 'profiles: ["production"]'),
                source.replace("identity-tunnel-egress]", "identity-mongo-egress]"),
                source.replace('    restart: "no"', '    restart: unless-stopped'),
                source.replace("        read_only: true", "        read_only: false", 1),
            ):
                target.write_text(altered)
                with mock.patch.object(m, "OVERLAY", target):
                    with self.assertRaises(m.Refused):
                        m.validate_overlay()

if __name__ == "__main__":
    unittest.main()
