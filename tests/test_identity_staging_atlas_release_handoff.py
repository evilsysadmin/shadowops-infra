"""No OCI/Atlas/Cloudflare writes: exact Atlas-only delivery contracts."""
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_staging_release as release

DIGEST = "sha256:" + "a" * 64
SHA = "b" * 40


def sdk_with_result(status="SUCCEEDED", exit_code=0, output=None):
    observed = []
    if output is None:
        output = "IDENTITY_ATLAS_DEPLOY_OK source_sha=" + SHA + " digest=" + DIGEST
    def model(**kwargs):
        return SimpleNamespace(**kwargs)
    client = SimpleNamespace(
        create_instance_agent_command=lambda **kw: (
            observed.append(kw["create_instance_agent_command_details"])
            or SimpleNamespace(data=SimpleNamespace(id="fixture"))),
        get_instance_agent_command_execution=lambda **kw: SimpleNamespace(
            data=SimpleNamespace(lifecycle_state=status,
                                 content=SimpleNamespace(text=output, exit_code=exit_code))))
    models = SimpleNamespace(**{name: model for name in (
        "CreateInstanceAgentCommandDetails", "InstanceAgentCommandTarget",
        "InstanceAgentCommandContent", "InstanceAgentCommandSourceViaTextDetails",
        "InstanceAgentCommandOutputViaTextDetails")})
    sdk = SimpleNamespace(compute_instance_agent=SimpleNamespace(
        models=models, ComputeInstanceAgentCommandDetails=model,
        ComputeInstanceAgentClient=lambda config: client))
    return sdk, observed


class AtlasReleaseHandoffTests(unittest.TestCase):
    def test_installed_hashes_guard_and_single_fixed_root_operator(self):
        sources = release.ATLAS_RELEASE_SOURCES
        self.assertIn("host/identity-atlas-staging-deploy.py", sources)
        self.assertIn("scripts/identity_staging_atlas_transition.py", sources)
        self.assertIn("scripts/shared_a1_host_guard.py", sources)
        hashes = release.canary_source_digests(sources=sources)
        command = release.atlas_release_host_command(DIGEST, SHA, hashes)
        self.assertIn("sha256sum --check --status", command)
        self.assertIn(
            "sudo --non-interactive /usr/local/sbin/shadowops-identity-atlas-deploy deploy "
            + DIGEST + " " + SHA + "\n", command)
        self.assertNotIn("docker compose", command)
        self.assertNotIn("atlas-active", command)

    def test_invalid_and_mismatched_installed_source_inputs_fail_before_oci(self):
        sources = release.ATLAS_RELEASE_SOURCES
        hashes = release.canary_source_digests(sources=sources)
        for bad_digest, bad_sha in (("latest", SHA), (DIGEST, "main"), (DIGEST, SHA + ";id")):
            with self.subTest(bad_digest=bad_digest, bad_sha=bad_sha):
                with self.assertRaises(release.ReleaseError):
                    release.atlas_release_host_command(bad_digest, bad_sha, hashes)
        with self.assertRaises(release.ReleaseError):
            release.atlas_release_host_command(DIGEST, SHA, {"foreign.py": "c" * 64})

    def test_only_exact_root_receipt_is_success_and_host_output_stays_private(self):
        for state, code, output, accepted in (
            ("SUCCEEDED", 0, "IDENTITY_ATLAS_DEPLOY_OK source_sha=" + SHA + " digest=" + DIGEST, True),
            ("SUCCEEDED", 0, "", False),
            ("SUCCEEDED", 0, "synthetic-private-data", False),
            ("FAILED", 1, "synthetic-private-data", False),
            ("SUCCEEDED", 0, "IDENTITY_ATLAS_DEPLOY_OK source_sha=" + "c" * 40 + " digest=" + DIGEST, False),
        ):
            sdk, observed = sdk_with_result(state, code, output)
            with patch.object(release, "inspect"), patch.object(
                    release, "resolve_existing_host", return_value=("compartment", "host")):
                if accepted:
                    self.assertEqual(release.execute_atlas_release(sdk, {}, DIGEST, SHA), output)
                else:
                    with self.assertRaises(release.ReleaseError) as blocked:
                        release.execute_atlas_release(sdk, {}, DIGEST, SHA)
                    self.assertNotIn("synthetic-private-data", str(blocked.exception))
            self.assertEqual(observed[0].target.instance_id, "host")
            self.assertEqual(observed[0].display_name, "identity-staging-atlas-release")

    def test_protected_workflow_requires_pinned_digest_and_never_push_deploy(self):
        workflow = (ROOT / ".github/workflows/identity-staging-operations.yml").read_text()
        self.assertIn("inputs.action == 'atlas-release'", workflow)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.action == 'atlas-release'", workflow)
        self.assertIn("IDENTITY_ATLAS_RELEASE_DIGEST_REQUIRED", workflow)
        self.assertIn("EXPECTED_ATLAS_DIGEST", workflow)
        self.assertIn("IDENTITY_ATLAS_PUBLIC_SNOOKER_READY", workflow)
        installer = (ROOT / "host/install-identity-staging.sh").read_text()
        sudoers = (ROOT / "host/identity-staging.sudoers").read_text()
        self.assertIn("shadowops-identity-atlas-deploy", installer)
        self.assertIn("identity_staging_atlas_transition", installer)
        self.assertIn("/usr/local/sbin/shadowops-identity-atlas-deploy deploy *", sudoers)


if __name__ == "__main__":
    unittest.main()
