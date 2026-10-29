"""No-cost, no-credentials CKA staging service / source preflight contracts."""
import configparser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "host/cka-factory-staging.service"
WORKFLOW = ROOT / ".github/workflows/cka-factory-preflight.yml"
WORKSPACE = "/var/lib/shadowops/cka-factory-staging"
PYTHON = "/opt/shadowops/cka-factory-staging/venv/bin/python"


def unit():
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.optionxform = str
    parser.read_string(SERVICE.read_text(encoding="utf-8"))
    return parser


class TestCKAFactoryDryRunService(unittest.TestCase):
    def test_staging_unit_never_runs_generation_or_installs_a_timer(self):
        spec = unit()
        self.assertEqual(set(spec.sections()), {"Unit", "Service"})
        service = spec["Service"]
        self.assertEqual(service["Type"], "oneshot")
        self.assertEqual(service["User"], "shadowops-cka-factory")
        self.assertEqual(service["Group"], "shadowops-cka-factory")
        self.assertEqual(service["Environment"], "CKA_SCENARIO_PROVIDER=workers-ai")
        self.assertEqual(service["ExecStart"],
                         PYTHON + " -m cka_sim factory-run --workspace " + WORKSPACE
                         + " --count 1 --type deployment_scale")
        self.assertNotIn("--execute", SERVICE.read_text())
        for forbidden in ("--provider ollama", "CLOUDFLARE_API_TOKEN",
                          "CLOUDFLARE_ACCOUNT_ID", "EnvironmentFile",
                          "ExecStartPre", "ExecStartPost", "ExecStop", "WantedBy",
                          "ExecReload", "Timer", "Restart=", "curl ", "bash -c",
                          "kubectl", "docker", "systemctl", "/etc/shadowops/"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, SERVICE.read_text())
        self.assertEqual(spec["Unit"]["ConditionPathIsDirectory"],
                         WORKSPACE)
        self.assertEqual(spec["Unit"]["ConditionPathExists"], PYTHON)

    def test_workspace_only_writable_path_and_strict_host_limits(self):
        service = unit()["Service"]
        self.assertEqual(service["WorkingDirectory"],
                         "/opt/shadowops/cka-factory-staging")
        self.assertEqual(service["ReadWritePaths"], WORKSPACE)
        self.assertEqual(service["ProtectSystem"], "strict")
        self.assertEqual(service["ProtectHome"], "yes")
        self.assertEqual(service["PrivateNetwork"], "yes")
        self.assertEqual(service["IPAddressDeny"], "any")
        self.assertEqual(service["RestrictAddressFamilies"], "AF_UNIX")
        self.assertEqual(service["NoNewPrivileges"], "yes")
        self.assertEqual(service["CapabilityBoundingSet"], "")
        self.assertEqual(service["AmbientCapabilities"], "")
        self.assertEqual(service["UMask"], "0077")
        self.assertEqual(service["PrivateDevices"], "yes")
        self.assertEqual(service["ProtectKernelTunables"], "yes")
        self.assertEqual(service["ProtectControlGroups"], "yes")
        self.assertEqual(service["SystemCallArchitectures"], "native")
        self.assertEqual(service["MemoryMax"], "256M")
        self.assertEqual(service["TasksMax"], "32")
        self.assertEqual(service["TimeoutStartSec"], "90")
        self.assertNotIn("StateDirectory", service)
        self.assertNotIn("RootDirectory", service)

    def test_manual_source_preflight_uses_external_ephemeral_workspace(self):
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"$RUNNER_TEMP/cka-factory-preflight/workspace"', content)
        self.assertIn("mkdir -p", content)
        self.assertIn("factory-run --count 1 --type deployment_scale --workspace", content)
        self.assertIn('assert (workspace / ".local/factory.lock").is_file()', content)
        self.assertIn('assert not (workspace / ".local/factory-budget.json").exists()', content)
        self.assertIn('assert not (workspace / "scenarios/generated").exists()', content)
        self.assertIn("CLOUDFLARE_API_TOKEN: ''", content)
        self.assertNotIn("factory-run --execute", content)
        self.assertNotIn("secrets.", content)


if __name__ == "__main__":
    unittest.main()
