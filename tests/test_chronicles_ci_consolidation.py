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

if __name__ == "__main__":
    unittest.main()
