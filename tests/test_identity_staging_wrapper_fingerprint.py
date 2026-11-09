import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import identity_staging_wrapper_fingerprint as probe
from oci_control_plane import InventoryError

A = "a" * 64
B = "b" * 64
C = "c" * 64


def result(text, state="SUCCEEDED", exit_code=0):
    return SimpleNamespace(lifecycle_state=state, content=SimpleNamespace(text=text, exit_code=exit_code))


class FingerprintTests(unittest.TestCase):
    def test_only_expected_installed_code_counts_as_current(self):
        prefix = "IDENTITY_WRAPPER_FINGERPRINT_SHA256 "
        self.assertEqual(probe.verdict(prefix + A + " " + B, (A, B)),
                         "IDENTITY_WRAPPER_FINGERPRINT_CURRENT")
        self.assertEqual(probe.verdict(prefix + C + " " + B, (A, B)),
                         "IDENTITY_WRAPPER_FINGERPRINT_OUTDATED_WRAPPER")
        self.assertEqual(probe.verdict(prefix + A + " " + C, (A, B)),
                         "IDENTITY_WRAPPER_FINGERPRINT_OUTDATED_BUNDLE")
        self.assertEqual(probe.verdict(prefix + C + " " + C, (A, B)),
                         "IDENTITY_WRAPPER_FINGERPRINT_OUTDATED_BOTH")

    def test_missing_unsafe_and_untrusted_output(self):
        for label in probe.VERDICTS:
            self.assertEqual(probe.verdict(label, (A, B)), label)
        for text in ("", "private host output", "IDENTITY_WRAPPER_FINGERPRINT_SHA256 " + A,
                     "IDENTITY_WRAPPER_FINGERPRINT_SHA256 " + A + " " + B + "\nsecret",
                     "IDENTITY_WRAPPER_FINGERPRINT_SHA256 " + A + " " + B + " extra"):
            with self.subTest(text=text), self.assertRaises(InventoryError):
                probe.verdict(text, (A, B))
        with self.assertRaises(InventoryError):
            probe.verdict("IDENTITY_WRAPPER_FINGERPRINT_MISSING", ("oops", B))

    def test_trusted_digests_are_computed_from_exact_repo_files(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for i, (source, _, _) in enumerate(probe.SOURCES):
                file = root / source
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("code-" + str(i))
            hashes = probe.trusted_digests(root)
            self.assertEqual(hashes, tuple(hashlib.sha256(("code-" + str(i)).encode()).hexdigest()
                                            for i in range(2)))
            (root / probe.SOURCES[0][0]).unlink()
            with self.assertRaises(InventoryError):
                probe.trusted_digests(root)

    def test_nonprivileged_fixed_observation_is_read_only_and_pinned(self):
        self.assertNotIn("sudo ", probe.OBSERVATION)
        self.assertNotIn("docker ", probe.OBSERVATION)
        self.assertNotIn("ssh ", probe.OBSERVATION)
        self.assertNotIn("secret", probe.OBSERVATION.lower())
        self.assertIn("/usr/local/sbin/shadowops-identity-staging", probe.OBSERVATION)
        self.assertIn("/usr/local/lib/shadowops/identity_staging_bundle.py", probe.OBSERVATION)
        self.assertIn("sha256sum", probe.OBSERVATION)

    def test_oci_execution_reports_only_bounded_verdict_and_never_host_output(self):
        captured = []
        def model(**kw):
            return SimpleNamespace(**kw)
        client = SimpleNamespace(
            create_instance_agent_command=lambda **kw: captured.append(kw) or SimpleNamespace(
                data=SimpleNamespace(id="command-1")
            ),
            get_instance_agent_command_execution=lambda **kw: SimpleNamespace(
                data=result("IDENTITY_WRAPPER_FINGERPRINT_SHA256 " + A + " " + B)
            ),
        )
        models = SimpleNamespace(**{name: model for name in (
            "InstanceAgentCommandContent", "InstanceAgentCommandSourceViaTextDetails",
            "InstanceAgentCommandOutputViaTextDetails", "CreateInstanceAgentCommandDetails",
            "InstanceAgentCommandTarget"
        )})
        sdk = SimpleNamespace(compute_instance_agent=SimpleNamespace(
            models=models, ComputeInstanceAgentClient=lambda _: client
        ))
        with patch.object(probe, "verified_run_command_host", return_value=("compartment", "host")):
            self.assertEqual(probe.diagnose(sdk, {}, (A, B)),
                             "IDENTITY_WRAPPER_FINGERPRINT_CURRENT")
        details = captured[0]["create_instance_agent_command_details"]
        self.assertEqual(details.target.instance_id, "host")
        self.assertEqual(details.content.source.text, probe.OBSERVATION)
        self.assertNotIn("sudo ", details.content.source.text)

    def test_failure_or_unexpected_remote_text_stays_private(self):
        def model(**kw):
            return SimpleNamespace(**kw)
        for state, code, output in [
            ("FAILED", 0, "secret-output"),
            ("SUCCEEDED", 1, "secret-output"),
            ("SUCCEEDED", None, "secret-output"),
            ("SUCCEEDED", 0, "secret-output"),
        ]:
            client = SimpleNamespace(
                create_instance_agent_command=lambda **kw: SimpleNamespace(
                    data=SimpleNamespace(id="id")
                ),
                get_instance_agent_command_execution=lambda **kw: SimpleNamespace(
                    data=result(output, state, code)
                ),
            )
            models = SimpleNamespace(**{name: model for name in (
                "InstanceAgentCommandContent", "InstanceAgentCommandSourceViaTextDetails",
                "InstanceAgentCommandOutputViaTextDetails", "CreateInstanceAgentCommandDetails",
                "InstanceAgentCommandTarget"
            )})
            sdk = SimpleNamespace(compute_instance_agent=SimpleNamespace(
                models=models, ComputeInstanceAgentCommandClient=None,
                ComputeInstanceAgentClient=lambda _: client
            ))
            with self.subTest(state=state, code=code), patch.object(
                probe, "verified_run_command_host", return_value=("compartment", "host")
            ), self.assertRaises(InventoryError) as err:
                probe.diagnose(sdk, {}, (A, B))
            self.assertNotIn("secret-output", str(err.exception))


if __name__ == "__main__":
    unittest.main()
