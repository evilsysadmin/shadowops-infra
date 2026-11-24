"""Offline pinned Star Adventures workflow and OCI handoff contracts."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from test_identity_staging_atlas_release_handoff import sdk_with_result

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_staging_release as r


class StarAdvsHandoffTests(unittest.TestCase):
    def test_source_guard_and_pinned_command(self):
        vault = "ocid1.vault.oc1." + "v" * 24
        hashes = r.canary_source_digests(sources=r.STARADVS_RELEASE_SOURCES)
        cmd = r.staradvs_release_host_command(r.STARADVS_RELEASE_DIGEST, r.STARADVS_RELEASE_SHA, vault, hashes)
        self.assertIn("sha256sum --check --status", cmd)
        self.assertIn("sudo --non-interactive /usr/local/sbin/shadowops-identity-atlas-staradvs deploy "
                      + vault + " " + r.STARADVS_RELEASE_DIGEST + " " + r.STARADVS_RELEASE_SHA, cmd)
        for digest, sha, v in (("sha256:" + "a"*64, r.STARADVS_RELEASE_SHA, vault),
                               (r.STARADVS_RELEASE_DIGEST, "a"*40, vault),
                               (r.STARADVS_RELEASE_DIGEST, r.STARADVS_RELEASE_SHA, vault+";id")):
            with self.assertRaises(r.ReleaseError):
                r.staradvs_release_host_command(digest, sha, v, hashes)

    def test_exact_receipt_only(self):
        expected = "IDENTITY_ATLAS_STARADVS_DEPLOY_OK source_sha=" + r.STARADVS_RELEASE_SHA + " digest=" + r.STARADVS_RELEASE_DIGEST
        for output in (expected, "", "synthetic-private"):
            sdk, observed = sdk_with_result(output=output)
            with patch.object(r, "inspect"), patch.object(r, "resolve_existing_host", return_value=("compartment", "host")), patch.object(r, "resolve_vault", return_value=("ocid1.vault.oc1."+"v"*24, None, None)):
                if output == expected:
                    self.assertEqual(r.execute_staradvs_release(sdk, {}, r.STARADVS_RELEASE_DIGEST, r.STARADVS_RELEASE_SHA), expected)
                else:
                    with self.assertRaises(r.ReleaseError) as e:
                        r.execute_staradvs_release(sdk, {}, r.STARADVS_RELEASE_DIGEST, r.STARADVS_RELEASE_SHA)
                    self.assertNotIn("synthetic-private", str(e.exception))
            self.assertEqual(observed[0].display_name, "identity-staging-atlas-staradvs-release")

    def test_workflow_manual_only_and_recovery_first(self):
        workflow = (ROOT / ".github/workflows/identity-staging-operations.yml").read_text()
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.action == 'atlas-staradvs-release'", workflow)
        section = workflow.split("  atlas-staradvs-release:\n", 1)[1].split("  deploy:\n", 1)[0]
        self.assertIn("needs: admit", section)
        self.assertIn("environment: staging", section)
        self.assertIn("group: shadowops-oci-host-operations", section)
        self.assertLess(section.index("atlas-backup"), section.index("atlas-restore-rehearsal"))
        self.assertLess(section.index("atlas-restore-rehearsal"), section.index("identity_staging_release.py atlas-staradvs-release"))
        self.assertIn("IDENTITY_ATLAS_PUBLIC_STARADVS_READY", section)


if __name__ == "__main__":
    unittest.main()
