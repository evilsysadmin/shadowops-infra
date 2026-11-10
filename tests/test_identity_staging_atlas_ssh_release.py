"""The human SSH fallback must remain a single fixed staging-only operation."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "host/identity-staging-atlas-release-over-ssh.sh"


class AtlasSSHReleaseFallbackContracts(unittest.TestCase):
    def test_shell_syntax_and_exact_fixed_root_operator(self):
        subprocess.run(["bash", "-n", str(PATH)], check=True, timeout=10)
        text = PATH.read_text()
        self.assertIn("[[ $# == 0 ]]", text)
        self.assertIn("shadowops-identity-atlas-deploy", text)
        self.assertIn("ProxyCommand=cloudflared access ssh --hostname %h", text)
        self.assertIn("sudo --non-interactive $wrapper deploy $digest $source_sha", text)
        self.assertIn("IDENTITY_ATLAS_SSH_PUBLIC_SNOOKER_READY", text)
        self.assertIn("SNOOKER_IDENTITY_PUBLIC_CHECK login=snooker-target-present", text)

    def test_pinned_source_custody_and_no_unsafe_fallback(self):
        text = PATH.read_text()
        for pin in (
            "4a48dff49c4a77703c6f4b164120d3cef8e77e76",
            "sha256:6534fb861d3201ab9697b6b84d58a157af748b36c8e96482afd7ea8ca5cddb91",
            "ssh-chess-studio-staging.shadowops.dpdns.org",
            "git ls-remote --exit-code",
            "stale-main",
            "dirty-checkout",
        ):
            self.assertIn(pin, text)
        self.assertNotIn("docker compose", text)
        self.assertNotIn("sudo docker", text)
        self.assertNotIn("rm -f", text)
        self.assertNotIn("atlas-active'", text)
        self.assertNotIn("github.com/evilsysadmin/football", text)
        self.assertNotIn("deploy $1", text)
        self.assertNotIn("password=", text)


if __name__ == "__main__":
    unittest.main()
