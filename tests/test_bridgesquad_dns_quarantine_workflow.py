"""CI guard: the DNS step may never publish game assets or expose secrets to PRs."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
YAML = ROOT / ".github/workflows/bridgesquad-dns-quarantine.yml"
MODULE = ROOT / "scripts/bridgesquad_dns_quarantine.py"
WATCHDOG = ROOT / "scripts/bridgesquad_alias_watchdog.py"


class BridgeSquadDNSQuarantineWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = YAML.read_text(encoding="utf-8")
        cls.testjob, cls.job = cls.code.split("\n  attach:\n", 1)
        cls.script = MODULE.read_text(encoding="utf-8")
        cls.watchdog = WATCHDOG.read_text(encoding="utf-8")

    def test_identity_safety_contract_precedes_production_writes(self):
        self.assertIn("needs: contracts", self.job)
        self.assertIn("node --test tests/bridgesquad-identity-gate.test.mjs", self.testjob)
        self.assertIn("test_bridgesquad_dns_quarantine.py", self.testjob)
        self.assertIn("test_bridgesquad_alias_bootstrap.py", self.testjob)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", self.job)
        self.assertIn("github.ref == 'refs/heads/main'", self.job)
        self.assertNotIn("github.event_name == 'pull_request'", self.job)

    def test_credentials_only_in_main_protected_job(self):
        self.assertNotIn("secrets.CLOUDFLARE", self.testjob)
        self.assertIn("environment:\n      name: staging", self.job)
        self.assertIn("CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}", self.job)
        self.assertIn("CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}", self.job)
        self.assertNotIn("\\${{", self.job)
        self.assertIn("permissions:\n      contents: read", self.job)
        self.assertNotIn("continue-on-error", self.code)

    def test_preflight_before_owner_writes_and_dns_http_proof_last(self):
        ordered = [
            "scripts/bridgesquad_dns_quarantine.py preflight",
            "scripts/bridgesquad_dns_quarantine.py attach",
            "scripts/bridgesquad_dns_quarantine.py audit",
            "BRIDGESQUAD_QUARANTINE_DNS_READY",
        ]
        offsets = [self.job.index(x) for x in ordered]
        self.assertEqual(offsets, sorted(offsets))
        self.assertIn("https=401-login-shell game=locked", self.job)
        self.assertIn("exit 1", self.job)
        self.assertNotIn("CLOUDFLARE_API_TOKEN: ", self.testjob)

    def test_source_has_only_scoped_cloudflare_writes(self):
        self.assertIn('is_domain = method == "POST"', self.script)
        self.assertIn('is_dns = (method == "POST"', self.script)
        self.assertIn('"proxied": True, "ttl": 1', self.script)
        self.assertIn('raise QuarantineError("Noncanonical Cloudflare mutation denied")', self.script)
        for forbidden in ("wrangler pages deploy", "/pages/deployments", "gh api", "OCI_PRIVATE_KEY",
                          'method="PUT"', 'method="PATCH"', 'method="DELETE"'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden.lower(), self.script.lower())

    def test_watchdog_remains_active_when_dns_becomes_present(self):
        self.assertIn("quarantine.audit(client, guest=probe", self.watchdog)
        self.assertIn("bootstrap.postflight(client, sha, status=probe)", self.watchdog)
        self.assertIn('if inventory["domain"] == "present" and inventory["dns"] == "present"', self.watchdog)
        self.assertIn("NoRedirect", self.script)
        self.assertIn("socket.getaddrinfo(HOST, 443", self.script)


if __name__ == "__main__":
    unittest.main()
