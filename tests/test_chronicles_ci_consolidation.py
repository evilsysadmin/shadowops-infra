"""Regression guard: the consolidated job must not silently lose policy coverage."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
LEGACY = ["accreditation-tests.yml","admission-tests.yml","attestation-tests.yml","deployment-state-tests.yml","github-evidence-tests.yml","release-admission-tests.yml","release-ledger-tests.yml","release-lock-tests.yml","required-checks-tests.yml","staging-read-smoke-contract.yml","staging-receipt-tests.yml"]
CASES = ["tests/accreditation.test.mjs","tests/chronicles-policy.test.mjs","tests/attestation.test.mjs","tests/github-evidence.test.mjs","tests/inspect-main-protection.test.mjs","tests/live-staging-admission-workflow.test.mjs","tests/release-admission.test.mjs","tests/staging-candidate-cli.test.mjs","tests/required-checks.test.mjs","tests/deployment-state.test.mjs","tests/chronicles-production-scheduler.test.mjs","tests/release-ledger.test.mjs","tests/release-lock.test.mjs","tests/staging-receipt.test.mjs","test_staging_read_smoke.py","scripts/staging_read_smoke.py"]

class ChroniclesPolicyConsolidationTests(unittest.TestCase):
    def test_one_owner_for_standalone_contracts(self):
        for name in LEGACY:
            with self.subTest(workflow=name):
                self.assertFalse((WORKFLOWS / name).exists(), f"duplicate old policy workflow: {name}")

    def test_contract_files_have_one_ci_owner(self):
        ci = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("name: Infrastructure contracts", ci)
        self.assertIn("  pull_request:", ci)
        self.assertIn("    branches: [main]", ci)
        self.assertIn("  contents: read", ci)
        for path in CASES:
            with self.subTest(contract=path):
                self.assertIn(path, ci, f"missing consolidated policy test: {path}")
        self.assertIn("if python3 scripts/staging_read_smoke.py --run-id fixture-run --expected-map crypt", ci)


class HistoricalGHCRTriggerTests(unittest.TestCase):
    """Historical immutable provenance should not re-run on unrelated merges."""

    def test_only_policy_changes_trigger_pr_and_push(self):
        import re
        workflow = (WORKFLOWS / "live-ghcr-attestation.yml").read_text(encoding="utf-8")
        pr = re.search(r"(?m)^  pull_request:\n    paths:\n((?:      - .+\n)+)", workflow)
        push = re.search(r"(?m)^  push:\n    branches: \[main\]\n    paths:\n((?:      - .+\n)+)", workflow)
        self.assertIsNotNone(pr, "PR must use relevant-path filtering")
        self.assertIsNotNone(push, "main push must use relevant-path filtering")
        pr_paths = set(pr.group(1).splitlines())
        push_paths = set(push.group(1).splitlines())
        self.assertEqual(pr_paths, push_paths)
        for expected in (
            "live-ghcr-attestation.yml", "policy/**",
            "scripts/verify-image-attestation.mjs",
            "scripts/check-staging-candidate.mjs",
            "tests/test_chronicles_ci_consolidation.py",
        ):
            self.assertIn(expected, pr.group(1))
        self.assertNotIn("'docs/**'", pr.group(1))
        self.assertNotIn("'**'", pr.group(1))

    def test_manual_and_periodic_checks_preserve_immutable_admission(self):
        workflow = (WORKFLOWS / "live-ghcr-attestation.yml").read_text(encoding="utf-8")
        self.assertIn("  workflow_dispatch:", workflow)
        self.assertIn("  schedule:\n    - cron: '23 5 * * 1'", workflow)
        self.assertIn("if: github.event_name == 'pull_request' || github.ref == 'refs/heads/main'", workflow)
        self.assertIn("scripts/check-staging-candidate.mjs", workflow)
        self.assertIn("verifyRequiredChecks", workflow)
        self.assertIn("verifyImage", workflow)

if __name__ == "__main__":
    unittest.main()
