"""Prove signed web release admission and fixed OCI wrapper dispatch without secrets."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from oci_control_plane import InventoryError, config_from_env
import oci_chronicles_web_release as remote
import chronicles_web_release_admission as admission
from test_oci_host_probe import HostSDK, ENV as OCI_ENV
from test_oci_web_staging_preflight import (
    SHA, DIGEST, RUN_ID, ENV, read, Runner,
)
from oci_web_staging_preflight import WebPreflightError


class SignedChroniclesReleaseTests(unittest.TestCase):
    def test_admission_proves_exact_source_signature_manifest_and_compose(self):
        fake = Runner()
        result = admission.admit(SHA, DIGEST, RUN_ID, env=ENV,
                                 read=read, runner=fake)
        self.assertIn(SHA, result)
        self.assertIn(DIGEST, result)
        self.assertEqual(len(fake.commands), 3)
        self.assertEqual(fake.commands[0][:3], ["gh", "attestation", "verify"])
        self.assertIn("--source-digest", fake.commands[0])
        self.assertIn("--bundle-from-oci", fake.commands[0])
        self.assertEqual(fake.commands[1][:3], ["docker", "buildx", "imagetools"])
        self.assertEqual(fake.commands[2][:3], ["docker", "compose", "-f"])

    def test_fail_closed_errors_name_only_static_stages_not_process_output(self):
        from types import SimpleNamespace
        def rejected(*args, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="SENSITIVE_TEST_SENTINEL")
        for stage in ("signature", "manifest", "compose"):
            with self.subTest(stage=stage):
                with self.assertRaisesRegex(WebPreflightError, "Signed-release " + stage + " command failed") as caught:
                    admission.fixed_command(rejected, ["ignored"], {}, stage)
                self.assertNotIn("SENSITIVE_TEST_SENTINEL", str(caught.exception))
        with self.assertRaisesRegex(WebPreflightError, "Unknown signed-release verification stage"):
            admission.fixed_command(rejected, ["ignored"], {}, "arbitrary")

    def test_admission_failure_never_invokes_oci(self):
        for sha, digest, run_id, env in (
            ("main", DIGEST, RUN_ID, ENV),
            (SHA, "sha256:invalid", RUN_ID, ENV),
            (SHA, DIGEST, 0, ENV),
            (SHA, DIGEST, RUN_ID, {"CHRONICLES_WEB_IMAGE_DIGEST": DIGEST}),
            (SHA, DIGEST, RUN_ID, {"GH_TOKEN": "x"}),
        ):
            fake = Runner()
            with self.subTest(sha=sha, digest=digest, run_id=run_id):
                with self.assertRaises(WebPreflightError):
                    admission.admit(sha, digest, run_id, env=env,
                                    read=read, runner=fake)
                self.assertFalse(fake.commands)

    def test_only_a_fixed_restricted_root_wrapper_command_goes_to_oracle(self):
        sdk = HostSDK(output=remote.MARKER + DIGEST + "\n", code=0)
        result = remote.execute(sdk, config_from_env(sdk, OCI_ENV), DIGEST,
                                pause=lambda _:None)
        self.assertEqual(result, remote.MARKER + DIGEST)
        command = sdk.invocations[0][1]["create_instance_agent_command_details"]
        self.assertEqual(command.kwargs["target"].kwargs["instance_id"], "instance-test")
        source = command.kwargs["content"].kwargs["source"].kwargs["text"]
        self.assertEqual(source, remote.command_for(DIGEST))
        self.assertEqual(source.count("sudo --non-interactive "), 1)
        self.assertIn("/usr/local/sbin/shadowops-chronicles-web deploy", source)
        for forbidden in ("ssh ", "terraform", "chess-studio-deploy", "docker ",
                          "OCI_PRIVATE_KEY", "JWT_SECRET", "MONGO_URL"):
            self.assertNotIn(forbidden, source)

    def test_oracle_failure_or_extra_remote_output_never_passes(self):
        for options in ({"lifecycle": "FAILED"}, {"code": 1},
                        {"output": "private output"},
                        {"output": remote.MARKER + DIGEST + "\nextra"},
                        {"shape": "VM.Standard.E4.Flex"}, {"plugin": "STOPPED"}):
            with self.subTest(options=options):
                sdk = HostSDK(output=remote.MARKER + DIGEST + "\n", **options) if "output" not in options else HostSDK(**options)
                with self.assertRaises(InventoryError):
                    remote.execute(sdk, config_from_env(sdk, OCI_ENV), DIGEST,
                                   pause=lambda _:None)
                if "plugin" in options or "shape" in options:
                    self.assertFalse(sdk.invocations)

    def test_no_injected_digest_command(self):
        for value in ("latest", "sha256:" + "F"*64, DIGEST + ";sudo bash",
                      DIGEST + "\nls /", "", "sha256:" + "0"*63):
            with self.assertRaises(InventoryError):
                remote.command_for(value)

    def test_workflow_is_explicit_manual_admission_first_and_no_pr_secrets(self):
        wf = (ROOT / ".github/workflows/chronicles-web-oci-release.yml").read_text()
        self.assertIn("workflow_dispatch:", wf)
        self.assertIn("github.event_name == 'workflow_dispatch'", wf)
        self.assertIn("github.ref == 'refs/heads/main'", wf)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", wf)
        self.assertIn("needs: admit", wf)
        self.assertIn("environment:", wf)
        self.assertIn("shadowops-oci-host-operations", wf)
        self.assertIn("python3 scripts/chronicles_web_release_admission.py", wf)
        self.assertIn("python scripts/oci_chronicles_web_release.py", wf)
        self.assertNotIn("pull_request_target", wf)
        self.assertNotIn("|| github.event_name == 'push'", wf)
        self.assertNotIn("docker compose up", wf)
        self.assertIn("permissions:\n  contents: read", wf)
        self.assertIn("packages: read", wf)
        self.assertIn("docker/login-action@v3", wf)
        self.assertIn("registry: ghcr.io", wf)
        self.assertIn("password: ${{ secrets.GITHUB_TOKEN }}", wf)
        self.assertNotIn("packages: write", wf)


if __name__ == "__main__":
    unittest.main()
