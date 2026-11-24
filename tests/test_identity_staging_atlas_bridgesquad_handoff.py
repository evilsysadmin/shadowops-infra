"""Offline one-click Bridge Squad workflow and pinned OCI handoff contracts."""
import importlib.util
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch
from test_identity_staging_atlas_release_handoff import sdk_with_result

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_staging_release as r

spec = importlib.util.spec_from_file_location("pins_operator", ROOT / "host/identity-atlas-staging-staradvs.py")
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
VAULT = "ocid1.vault.oc1." + "v" * 24
WORKFLOW = (ROOT / ".github/workflows/identity-staging-operations.yml").read_text()


class BridgeSquadHandoffTests(unittest.TestCase):
    def test_single_pinned_image_everywhere(self):
        digest, sha = r.EXTENSION_RELEASE_DIGEST, r.EXTENSION_RELEASE_SHA
        self.assertRegex(digest, r"^sha256:[a-f0-9]{64}$")
        self.assertRegex(sha, r"^[a-f0-9]{40}$")
        self.assertEqual((op.PINNED_DIGEST, op.PINNED_SHA), (digest, sha))
        self.assertEqual((r.STARADVS_RELEASE_DIGEST, r.STARADVS_RELEASE_SHA), (digest, sha))
        sudoers = (ROOT / "host/identity-staging.sudoers").read_text()
        for name in ("staradvs", "bridgesquad"):
            self.assertIn("/usr/local/sbin/shadowops-identity-atlas-" + name + " deploy ocid1.vault.* sha256\\:"
                          + digest.split(":", 1)[1] + " " + sha + "\n", sudoers)
        self.assertEqual(set(re.findall(r"sha256\\:([a-f0-9]{64})", sudoers)), {digest.split(":", 1)[1]})
        self.assertIn("'" + sha + "'", WORKFLOW)
        self.assertIn("'" + digest + "'", WORKFLOW)

    def test_source_guard_and_pinned_command(self):
        hashes = r.canary_source_digests(sources=r.BRIDGESQUAD_RELEASE_SOURCES)
        cmd = r.extension_release_host_command("bridgesquad", r.EXTENSION_RELEASE_DIGEST,
                                                r.EXTENSION_RELEASE_SHA, VAULT, hashes)
        self.assertIn("sha256sum --check --status", cmd)
        self.assertIn("/usr/local/sbin/shadowops-identity-atlas-bridgesquad", cmd)
        self.assertIn("/usr/local/lib/shadowops/identity_staging_atlas_extension.py", cmd)
        self.assertTrue(cmd.endswith("sudo --non-interactive /usr/local/sbin/shadowops-identity-atlas-bridgesquad deploy "
                                     + VAULT + " " + r.EXTENSION_RELEASE_DIGEST + " " + r.EXTENSION_RELEASE_SHA + "\n"))
        for audience, digest, sha, v in (
                ("snooker", r.EXTENSION_RELEASE_DIGEST, r.EXTENSION_RELEASE_SHA, VAULT),
                ("bridgesquad", "sha256:" + "a" * 64, r.EXTENSION_RELEASE_SHA, VAULT),
                ("bridgesquad", r.EXTENSION_RELEASE_DIGEST, "a" * 40, VAULT),
                ("bridgesquad", r.EXTENSION_RELEASE_DIGEST, r.EXTENSION_RELEASE_SHA, VAULT + ";id")):
            with self.assertRaises(r.ReleaseError):
                r.extension_release_host_command(audience, digest, sha, v, hashes)

    def test_exact_receipt_only(self):
        d, s = r.EXTENSION_RELEASE_DIGEST, r.EXTENSION_RELEASE_SHA
        expected = "IDENTITY_ATLAS_BRIDGESQUAD_DEPLOY_OK source_sha=" + s + " digest=" + d
        staradvs = "IDENTITY_ATLAS_STARADVS_DEPLOY_OK source_sha=" + s + " digest=" + d
        for output in (expected, staradvs, "", "synthetic-private"):
            sdk, observed = sdk_with_result(output=output)
            with patch.object(r, "inspect"), \
                    patch.object(r, "resolve_existing_host", return_value=("compartment", "host")), \
                    patch.object(r, "resolve_vault", return_value=(VAULT, None, None)):
                if output == expected:
                    self.assertEqual(r.execute_extension_release(sdk, {}, "bridgesquad", d, s), expected)
                else:
                    with self.assertRaises(r.ReleaseError) as e:
                        r.execute_extension_release(sdk, {}, "bridgesquad", d, s)
                    self.assertNotIn("synthetic-private", str(e.exception))
            self.assertEqual(observed[0].display_name, "identity-staging-atlas-bridgesquad-release")

    def test_one_click_workflow_is_manual_ordered_and_only_enables_bridgesquad(self):
        self.assertIn("bridgesquad-activate", WORKFLOW.split("options: [provision", 1)[1].split("]", 1)[0])
        provision = WORKFLOW.split("  provision:\n", 1)[1].split("\n  atlas-", 1)[0]
        self.assertIn("inputs.action == 'bridgesquad-activate'", provision)
        self.assertIn("IDENTITY_STAGING_BRIDGESQUAD: ${{ inputs.action == 'bridgesquad-activate' && 'enable'", provision)
        for other in ("FOOTBALL", "PAWN_ACTION", "SNOOKER", "STARADVS", "ADMIN_INVENTORY"):
            line = next(l for l in provision.splitlines() if "IDENTITY_STAGING_" + other + ":" in l)
            self.assertNotIn("bridgesquad-activate", line)
        section = WORKFLOW.split("  atlas-bridgesquad-release:\n", 1)[1].split("\n  deploy:\n", 1)[0]
        self.assertIn("needs: [admit, provision]", section)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.action == 'bridgesquad-activate'", section)
        self.assertIn("environment: staging", section)
        self.assertIn("group: shadowops-oci-host-operations", section)
        self.assertLess(section.index("atlas-backup"), section.index("atlas-restore-rehearsal"))
        self.assertLess(section.index("atlas-restore-rehearsal"),
                        section.index("identity_staging_release.py atlas-bridgesquad-release"))
        self.assertIn("IDENTITY_ATLAS_PUBLIC_BRIDGESQUAD_READY", section)


if __name__ == "__main__":
    unittest.main()
