"""Offline proof that manual Pages SHA cannot accidentally deploy staging."""
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_pages_manual_target as gate

SHA = "a" * 40


class ManualPagesTargetTests(unittest.TestCase):
    def test_safe_manual_staging_without_source_and_production_with_exact_source(self):
        gate.validate_manual_target("workflow_dispatch", "staging", "", "false")
        gate.validate_manual_target("workflow_dispatch", "production", SHA, "false")
        gate.validate_manual_target("workflow_dispatch", "staging", SHA, "true")

    def test_entered_sha_never_silently_goes_to_staging_by_default(self):
        with self.assertRaisesRegex(gate.TargetError, "choose production explicitly"):
            gate.validate_manual_target("workflow_dispatch", "staging", SHA, "false")
        with self.assertRaisesRegex(gate.TargetError, "choose production explicitly"):
            gate.validate_manual_target("workflow_dispatch", "staging", "not-a-sha", "false")

    def test_production_requires_exact_source_and_refuses_staging_internal_mode(self):
        for sha in ("", "not-a-sha", "A" * 40, "a" * 39, SHA + "1"):
            with self.subTest(sha=sha), self.assertRaises(gate.TargetError):
                gate.validate_manual_target("workflow_dispatch", "production", sha, "false")
        with self.assertRaisesRegex(gate.TargetError, "internal staging sync"):
            gate.validate_manual_target("workflow_dispatch", "production", SHA, "true")

    def test_internal_staging_sync_requires_source_and_other_events_are_unchanged(self):
        with self.assertRaisesRegex(gate.TargetError, "exact source_sha"):
            gate.validate_manual_target("workflow_dispatch", "staging", "", "true")
        with self.assertRaisesRegex(gate.TargetError, "invalid manual"):
            gate.validate_manual_target("workflow_dispatch", "prod", SHA, "false")
        with self.assertRaisesRegex(gate.TargetError, "invalid manual"):
            gate.validate_manual_target("workflow_dispatch", "staging", SHA, "")
        for event in ("pull_request", "push", "schedule", "workflow_run"):
            gate.validate_manual_target(event, "staging", SHA, "false")

    def test_cli_suppresses_user_controlled_strings(self):
        with patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "CHRONICLES_TARGET_ENV": "staging",
            "CHRONICLES_SOURCE_SHA": "private-string-must-not-appear",
            "CHRONICLES_ONLY_IF_NEW": "false",
        }, clear=True), patch("sys.stderr", new_callable=io.StringIO) as output:
            self.assertEqual(gate.main(), 64)
            self.assertIn("CHRONICLES_PAGES_MANUAL_TARGET_BLOCKED", output.getvalue())
            self.assertNotIn("private-string-must-not-appear", output.getvalue())

    def test_workflow_gates_mutating_jobs_and_preserves_staging_automation(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/chronicles-pages-release.yml").read_text()
        self.assertIn("default: staging", workflow)
        self.assertIn("scripts/chronicles_pages_manual_target.py", workflow)
        self.assertIn("test_chronicles_pages_manual_target.py", workflow)
        contracts = workflow.split("\n  contracts:\n", 1)[1].split("\n  staging-candidate:\n", 1)[0]
        self.assertIn("if: github.event_name == 'workflow_dispatch'", contracts)
        self.assertIn("inputs.environment", contracts)
        self.assertIn("inputs.source_sha", contracts)
        self.assertIn("inputs.only_if_new", contracts)
        self.assertLess(contracts.index("run: python3 scripts/chronicles_pages_manual_target.py"),
                        contracts.index("test_pages_owner_admission.py"))
        self.assertIn("  production:\n", workflow)
        self.assertIn("inputs.environment == 'production'", workflow)
        self.assertIn("  schedule:\n", workflow)
        self.assertIn("  push:\n    branches: [main]", workflow)


if __name__ == "__main__":
    unittest.main()
