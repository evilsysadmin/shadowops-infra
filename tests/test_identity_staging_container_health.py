import sys
import unittest
import io
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import identity_staging_container_health as probe
from oci_control_plane import InventoryError


def lines(*values):
    return "\n".join("IDENTITY_CONTAINER service=" + service +
                     " status=" + status + " health=" + health
                     for service, status, health in values)


class StagingIdentityContainerHealthTests(unittest.TestCase):
    def test_exact_sanitized_three_service_statuses(self):
        receipt = lines(("identity-mongo", "running", "healthy"),
                        ("identity", "exited", "none"),
                        ("identity-tunnel", "created", "none"))
        self.assertEqual(probe.normalize(receipt),
                         "IDENTITY_CONTAINER_STATUS identity-mongo=running/healthy "
                         "identity=exited/none identity-tunnel=created/none")

    def test_full_service_health_is_not_assumed_from_docker_running(self):
        self.assertIn("identity=running/unhealthy",
                      probe.normalize(lines(("identity-mongo", "running", "healthy"),
                                            ("identity", "running", "unhealthy"),
                                            ("identity-tunnel", "running", "healthy"))))

    def test_tightly_limited_error_markers(self):
        for label in probe.FAILURE_MARKERS:
            self.assertEqual(probe.normalize(label), label)
        for output in (
            "",
            "private-host-debug",
            "IDENTITY_CONTAINERS_DOCKER_INACCESSIBLE\nprivate-host-debug",
            lines(("identity-mongo", "running", "healthy"),
                  ("identity", "running", "healthy")),
            lines(("identity-mongo", "running", "healthy"),
                  ("identity", "running", "healthy"),
                  ("identity", "running", "healthy")),
            lines(("identity-mongo", "running", "healthy"),
                  ("identity", "running", "healthy"),
                  ("identity-tunnel", "running", "healthy")) + "\nsecret",
            lines(("identity-mongo", "running", "healthy"),
                  ("identity", "unknown", "healthy"),
                  ("identity-tunnel", "running", "healthy")),
        ):
            with self.subTest(output=output), self.assertRaises(InventoryError):
                probe.normalize(output)

    def test_on_host_script_is_fixed_and_nondestructive(self):
        self.assertEqual(
            probe.SOURCE,
            "set -eu\nsudo --non-interactive /usr/local/sbin/shadowops-identity-staging status\n",
        )
        for forbidden in (
            "docker ", "bash ", "sh -c", "docker exec", "docker run",
            "docker logs", "docker compose", "ssh ", "curl ", "cat /etc",
        ):
            self.assertNotIn(forbidden, probe.SOURCE)

    def test_oci_command_only_returns_normalized_receipts(self):
        calls = []
        def model(**kw):
            return SimpleNamespace(**kw)
        valid = lines(("identity-mongo", "running", "healthy"),
                      ("identity", "exited", "none"),
                      ("identity-tunnel", "created", "none"))
        client = SimpleNamespace(
            create_instance_agent_command=lambda **kw: calls.append(kw) or SimpleNamespace(
                data=SimpleNamespace(id="fixture")
            ),
            get_instance_agent_command_execution=lambda **kw: SimpleNamespace(
                data=SimpleNamespace(lifecycle_state="SUCCEEDED",
                                     content=SimpleNamespace(exit_code=0, text=valid))
            ),
        )
        models = SimpleNamespace(**{name: model for name in (
            "InstanceAgentCommandContent", "InstanceAgentCommandSourceViaTextDetails",
            "InstanceAgentCommandOutputViaTextDetails", "CreateInstanceAgentCommandDetails",
            "InstanceAgentCommandTarget"
        )})
        sdk = SimpleNamespace(compute_instance_agent=SimpleNamespace(
            models=models, ComputeInstanceAgentClient=lambda _: client,
        ))
        with patch.object(probe, "verified_run_command_host",
                          return_value=("compartment", "pinned-host")):
            self.assertEqual(
                probe.observe(sdk, {}),
                "IDENTITY_CONTAINER_STATUS identity-mongo=running/healthy "
                "identity=exited/none identity-tunnel=created/none",
            )
        command = calls[0]["create_instance_agent_command_details"]
        self.assertEqual(command.target.instance_id, "pinned-host")
        self.assertEqual(command.content.source.text, probe.SOURCE)

    def test_oci_lag_budget_and_timeout_category_remain_bounded(self):
        self.assertEqual(probe.OBSERVATION_DEADLINE_SECONDS, 480)
        self.assertEqual(
            probe.PROBE_FAILURES,
            {"command-id", "remote-command", "receipt", "timeout"},
        )
        def model(**kw):
            return SimpleNamespace(**kw)
        models = SimpleNamespace(**{name: model for name in (
            "InstanceAgentCommandContent", "InstanceAgentCommandSourceViaTextDetails",
            "InstanceAgentCommandOutputViaTextDetails", "CreateInstanceAgentCommandDetails",
            "InstanceAgentCommandTarget",
        )})
        output = lines(("identity-mongo", "running", "healthy"),
                       ("identity", "running", "healthy"),
                       ("identity-tunnel", "running", "none"))
        terminal = {"value": "RUNNING"}
        client = SimpleNamespace(
            create_instance_agent_command=lambda **kw: SimpleNamespace(
                data=SimpleNamespace(id="fixture")),
            get_instance_agent_command_execution=lambda **kw: SimpleNamespace(
                data=SimpleNamespace(lifecycle_state=terminal["value"],
                                     content=SimpleNamespace(exit_code=0, text=output))),
        )
        sdk = SimpleNamespace(compute_instance_agent=SimpleNamespace(
            models=models, ComputeInstanceAgentClient=lambda _: client))
        with patch.object(probe, "verified_run_command_host",
                          return_value=("compartment", "pinned-host")):
            clock = iter((0, 479)).__next__
            terminal["value"] = "SUCCEEDED"
            self.assertEqual(
                probe.observe(sdk, {}, clock=clock, pause=lambda _: None),
                "IDENTITY_CONTAINER_STATUS identity-mongo=running/healthy "
                "identity=running/healthy identity-tunnel=running/none",
            )
            clock = iter((0, 480)).__next__
            terminal["value"] = "RUNNING"
            with self.assertRaises(probe.ProbeBlocked) as caught:
                probe.observe(sdk, {}, clock=clock, pause=lambda _: None)
            self.assertEqual(caught.exception.reason, "timeout")

    def test_oci_blocked_reason_is_finite_and_never_echoes_private_output(self):
        for category in probe.PROBE_FAILURES:
            with self.subTest(category=category):
                secret = "HOST_SECRET_123"
                stderr = io.StringIO()
                with (
                    patch.object(sys, "argv", ["probe", "run"]),
                    patch.dict(sys.modules, {"oci": SimpleNamespace()}),
                    patch.object(probe, "config_from_env", return_value={}),
                    patch.object(probe, "observe", side_effect=probe.ProbeBlocked(category)),
                    redirect_stderr(stderr),
                ):
                    self.assertEqual(probe.main(), 1)
                self.assertEqual(
                    stderr.getvalue().strip(),
                    "IDENTITY_CONTAINER_PROBE_BLOCKED type=InventoryError reason=" + category,
                )
                self.assertNotIn(secret, stderr.getvalue())
        with self.assertRaises(InventoryError):
            probe.ProbeBlocked("../untrusted-path")

    def test_private_output_and_nonzero_exit_fail_closed(self):
        def model(**kw):
            return SimpleNamespace(**kw)
        for state, code, output in [
            ("FAILED", 0, "secret-host-output"),
            ("SUCCEEDED", 1, "secret-host-output"),
            ("SUCCEEDED", None, "secret-host-output"),
            ("SUCCEEDED", 0, "secret-host-output"),
        ]:
            client = SimpleNamespace(
                create_instance_agent_command=lambda **kw: SimpleNamespace(
                    data=SimpleNamespace(id="fixture")
                ),
                get_instance_agent_command_execution=lambda **kw: SimpleNamespace(
                    data=SimpleNamespace(lifecycle_state=state,
                                         content=SimpleNamespace(exit_code=code, text=output))
                ),
            )
            models = SimpleNamespace(**{name: model for name in (
                "InstanceAgentCommandContent", "InstanceAgentCommandSourceViaTextDetails",
                "InstanceAgentCommandOutputViaTextDetails", "CreateInstanceAgentCommandDetails",
                "InstanceAgentCommandTarget"
            )})
            sdk = SimpleNamespace(compute_instance_agent=SimpleNamespace(
                models=models, ComputeInstanceAgentClient=lambda _: client,
            ))
            with self.subTest(state=state, code=code), patch.object(
                probe, "verified_run_command_host", return_value=("compartment", "host")
            ), self.assertRaises(InventoryError) as err:
                probe.observe(sdk, {})
            self.assertNotIn("secret-host-output", str(err.exception))


if __name__ == "__main__":
    unittest.main()
