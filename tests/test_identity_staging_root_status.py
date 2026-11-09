import importlib.util
import io
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import identity_staging_container_health as agent

spec = importlib.util.spec_from_file_location("identity_root_health", ROOT / "host" / "identity-staging-deploy.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class RootOwnedIdentityHealthTests(unittest.TestCase):
    def test_sudoers_grants_exact_status_not_docker(self):
        sudoers = (ROOT / "host" / "identity-staging.sudoers").read_text()
        self.assertIn(
            "Cmnd_Alias SHADOWOPS_IDENTITY_STATUS = /usr/local/sbin/shadowops-identity-staging status",
            sudoers,
        )
        self.assertIn("ocarun ALL=(root) NOPASSWD: SHADOWOPS_IDENTITY_STATUS", sudoers)
        self.assertNotIn("NOPASSWD: /usr/bin/docker", sudoers)
        self.assertNotIn("NOPASSWD: /bin/sh", sudoers)
        self.assertNotIn("/usr/local/sbin/shadowops-identity-staging status *", sudoers)

    def test_status_denied_without_root_or_docker(self):
        runner = Mock()
        self.assertEqual(host.bounded_identity_status(
            command=runner, uid=lambda: 1001, docker_available=True,
        ), host.STATUS_INACCESSIBLE)
        self.assertEqual(host.bounded_identity_status(
            command=runner, uid=lambda: 0, docker_available=False,
        ), "IDENTITY_CONTAINERS_DOCKER_UNAVAILABLE")
        runner.assert_not_called()

    def test_only_three_exact_labels_inspected_and_state_is_sanitized(self):
        expected_ids = {
            "identity-mongo": "a" * 12,
            "identity": "b" * 12,
            "identity-tunnel": "c" * 12,
        }
        statuses = {
            "identity-mongo": "running healthy",
            "identity": "exited none",
            "identity-tunnel": "created none",
        }
        calls = []

        def fake_command(args, *, timeout):
            calls.append(tuple(args))
            self.assertLessEqual(timeout, 8)
            self.assertEqual(args[0], "docker")
            if args[1] == "info":
                self.assertEqual(args, ["docker", "info", "--format", "{{.ServerVersion}}"])
                return "28.0.0"
            if args[1] == "ps":
                self.assertEqual(args[2:4], ["-aq", "--filter"])
                self.assertEqual(args[4], "label=com.docker.compose.project=shadowops-identity-staging")
                self.assertEqual(args[5], "--filter")
                service = args[6].removeprefix("label=com.docker.compose.service=")
                self.assertIn(service, host.STATUS_SERVICES)
                return expected_ids[service] + "\n"
            if args[1] == "inspect":
                self.assertEqual(args[2], "--format")
                service = next(k for k, v in expected_ids.items() if v == args[4])
                return statuses[service] + "\n"
            self.fail("unexpected Docker operation")

        receipt = host.bounded_identity_status(
            command=fake_command, uid=lambda: 0, docker_available=True,
        )
        self.assertEqual(agent.normalize(receipt),
            "IDENTITY_CONTAINER_STATUS identity-mongo=running/healthy "
            "identity=exited/none identity-tunnel=created/none")
        self.assertEqual(len(calls), 7)
        self.assertFalse(any("env" in word or "logs" in word or "exec" in word
                             for row in calls for word in row))

    def test_missing_containers_and_unsafe_docker_replies(self):
        def missing(args, *, timeout):
            return "28.0" if args[1] == "info" else ""
        result = host.bounded_identity_status(
            command=missing, uid=lambda: 0, docker_available=True,
        )
        self.assertEqual(agent.normalize(result),
            "IDENTITY_CONTAINER_STATUS identity-mongo=missing/none "
            "identity=missing/none identity-tunnel=missing/none")

        for invalid in ("not-an-id", "a" * 12 + "\n" + "b" * 12):
            def malformed(args, *, timeout):
                return invalid if args[1] == "ps" else "28.0"
            self.assertEqual(host.bounded_identity_status(
                command=malformed, uid=lambda: 0, docker_available=True,
            ), host.STATUS_COLLISION)

        def invalid_health(args, *, timeout):
            if args[1] == "ps":
                return "a" * 12
            return "running secret" if args[1] == "inspect" else "28.0"
        self.assertEqual(host.bounded_identity_status(
            command=invalid_health, uid=lambda: 0, docker_available=True,
        ), host.STATUS_INVALID)

    def test_private_errors_never_leak_to_ci(self):
        def private_error(args, *, timeout):
            raise host.DeployError("sensitive host path secret-token")
        self.assertEqual(host.bounded_identity_status(
            command=private_error, uid=lambda: 0, docker_available=True,
        ), host.STATUS_INACCESSIBLE)

        def timeout(args, *, timeout):
            raise subprocess.TimeoutExpired(args, timeout)
        self.assertEqual(host.bounded_identity_status(
            command=timeout, uid=lambda: 0, docker_available=True,
        ), host.STATUS_INACCESSIBLE)

    def test_only_exact_single_status_argument_reaches_diagnostic(self):
        output = io.StringIO()
        with patch.object(host, "trusted"), patch.object(
            host, "bounded_identity_status", return_value=host.STATUS_COLLISION
        ) as diagnostic, patch.object(sys, "argv", ["wrapper", "status"]), redirect_stdout(output):
            self.assertEqual(host.main(), 0)
        diagnostic.assert_called_once_with()
        self.assertEqual(output.getvalue().strip(), host.STATUS_COLLISION)

        output = io.StringIO()
        with patch.object(host, "bounded_identity_status") as diagnostic, patch.object(
            host, "deploy"
        ) as deploy, patch.object(sys, "argv", ["wrapper", "status", "identity"]), redirect_stdout(output):
            self.assertEqual(host.main(), 1)
        diagnostic.assert_not_called()
        deploy.assert_not_called()
        self.assertEqual(output.getvalue().strip(), "IDENTITY_STAGING_DEPLOY_BLOCKED type=DeployError")


if __name__ == "__main__":
    unittest.main()
