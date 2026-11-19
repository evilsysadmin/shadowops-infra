"""Production Identity bootstrap must never publish or mutate real environments."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/identity-production-bootstrap.yml"
ENTRY = ROOT / "services/identity/cmd/service-production/main.go"
BOOTSTRAP = ROOT / "services/identity/production/bootstrap.go"


class ProductionBootstrapWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text()
        cls.main = ENTRY.read_text()
        cls.bootstrap = BOOTSTRAP.read_text()

    def test_no_secrets_cloud_deploy_or_idp_staging_reuse(self):
        for disallowed in (
            "secrets.", "environment: staging", "CLOUDFLARE_", "OCI_", "wrangler",
            "docker/build-push-action", "docker/login-action", "upload-artifact",
            "pages deploy", "wrangler deploy", "kubectl apply", "GH_TOKEN", "curl", "ssh", "workflow_call",
        ):
            with self.subTest(disallowed=disallowed):
                self.assertNotIn(disallowed.lower(), self.workflow.lower())
        self.assertIn("go test -race -count=1 ./production ./cmd/service-production", self.workflow)
        self.assertIn("GOARCH=\"$arch\" go build", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)

    def test_explicit_start_only_and_hard_unready_routes(self):
        self.assertIn('os.Args[1]!="preflight" && os.Args[1]!="serve-unready"', self.main)
        self.assertIn('production.LoadBundle(path)', self.main)
        self.assertIn('production.NewUnreadyServer(cert)', self.main)
        self.assertIn('http.StatusServiceUnavailable', self.bootstrap)
        self.assertIn('r.Host != Host', self.bootstrap)
        self.assertNotIn("NewStagingService", self.main)
        self.assertNotIn("NewStagingIssuer", self.main)
        self.assertNotIn("NewStagingServiceHandler", self.main)

    def test_production_issuer_bundle_and_consumer_are_distinct(self):
        for expected in (
            'Host     = "id.shadowops.dpdns.org"',
            'Database = "shadowops_identity_production"',
            'Audience = "bridgesquad"',
            'b.Environment != "production"',
            'if !filepath.IsAbs(path)',
            'info.Mode().Perm()&0077 != 0',
            'url.ParseQuery(uri.RawQuery)',
            'core.New("production", seed)',
            'if err := leaf.VerifyHostname(Host)',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.bootstrap)


if __name__ == "__main__":
    unittest.main()
