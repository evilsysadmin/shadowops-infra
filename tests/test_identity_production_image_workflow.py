"""Contract for a separate deployable, inert production Identity image."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCKER = (ROOT / "services/identity/Dockerfile.production").read_text()
WORKFLOW = (ROOT / ".github/workflows/identity-production-image.yml").read_text()


class ProductionImageContractTests(unittest.TestCase):
    def test_no_staging_identity_or_untrusted_runtime_default(self):
        self.assertIn("FROM scratch", DOCKER)
        self.assertIn("USER 65532:65532", DOCKER)
        self.assertIn("EXPOSE 9443", DOCKER)
        self.assertIn("ENV IDENTITY_PRODUCTION_CONFIG_FILE=/run/secrets/identity-production.json", DOCKER)
        self.assertIn("go build -trimpath", DOCKER)
        self.assertIn("./cmd/service-production", DOCKER)
        self.assertIn('ENTRYPOINT ["/app/identity-production"]', DOCKER)
        self.assertNotIn("./cmd/service-staging", DOCKER)
        self.assertNotIn(" CMD ", DOCKER.replace("# No CMD:", "# "))
        self.assertNotIn("\nCMD ", DOCKER)
        for name in ("serve-ready", "serve-unready", "preflight", "provision-native-account"):
            self.assertNotIn("CMD [\""+name+"\"", DOCKER)

    def test_no_private_secrets_baked_into_candidate(self):
        for forbidden in (
            "soc1_", "BEGIN PRIVATE KEY", "mongodb://",
            "SHADOWOPS_BRIDGESQUAD_SERVICE_CREDENTIAL",
            "COPY config/", "COPY .env", "IDENTITY_PRODUCTION_CONFIG_FILE=/tmp",
            "ARG IDENTITY_PRODUCTION", "PASSWORD=",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, DOCKER)
        self.assertIn("ARG IDENTITY_SOURCE_SHA", DOCKER)
        self.assertIn("org.opencontainers.image.revision=", DOCKER)

    def test_ci_never_deploys_or_grants_production_identity(self):
        for forbidden in (
            "CLOUDFLARE_API_TOKEN", "OCI_PRIVATE_KEY", "ssh ", "kubectl ",
            "wrangler ", "workflow_dispatch:", "environment: production",
            "identity-production.json:", "createUser(", "createRole(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden.lower(), WORKFLOW.lower())
        self.assertIn("go test -race -count=1 ./production ./cmd/service-production", WORKFLOW)
        self.assertIn('if docker run --rm "$image" serve-ready', WORKFLOW)
        self.assertIn("github.event_name == 'push'", WORKFLOW)
        self.assertIn("github.ref == 'refs/heads/main'", WORKFLOW)
        self.assertIn("needs: candidate-contracts", WORKFLOW)
        self.assertIn("packages: write", WORKFLOW)
        self.assertIn("linux/arm64,linux/amd64", WORKFLOW)
        self.assertIn("tags: ${{ env.IMAGE }}:sha-${{ github.sha }}", WORKFLOW)
        self.assertNotIn(":latest", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
