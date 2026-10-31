"""Guard shared Chronicles admission PR path coverage without duplicating test lists."""
from pathlib import Path
import ast
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/chronicles-api-staging.yml",
    ROOT / ".github/workflows/chronicles-pages-release.yml",
)
SHARED_RUNNER = "scripts/run_chronicles_shared_contracts.py"
CRITICAL_SHARED_SOURCES = {"scripts/chronicles_staging_receipt.py"}
THIS_TEST = "tests/test_chronicles_shared_pr_paths.py"


def pr_paths(workflow: str) -> set[str]:
    match = re.search(r"(?m)^  pull_request:\n    paths:\n((?:      - .+\n)+)", workflow)
    if match is None:
        raise AssertionError("Missing explicit pull_request.paths")
    return {
        line.strip().removeprefix("- ").strip("'").strip('"')
        for line in match.group(1).splitlines()
    }


def runner_tests() -> set[str]:
    """Read the actual runner suite list, never a second manually curated copy."""
    code = ast.parse((ROOT / SHARED_RUNNER).read_text(encoding="utf-8"))
    variable = next(
        node.value for node in code.body
        if isinstance(node, ast.Assign) and
        any(isinstance(target, ast.Name) and target.id == "SHARED_TESTS"
            for target in node.targets)
    )
    names = ast.literal_eval(variable)
    if not isinstance(names, tuple) or len(names) < 5 or len(set(names)) != len(names):
        raise AssertionError("Incomplete or duplicate shared staging suite inventory")
    if not all(isinstance(name, str) and
               re.fullmatch(r"test_chronicles_[a-z0-9_]+\.py", name)
               for name in names):
        raise AssertionError("Invalid shared staging test name")
    return {"tests/" + name for name in names}


class SharedStagingPathContract(unittest.TestCase):
    def test_shared_receipt_sources_and_common_tests_trigger_both_pr_suites(self):
        texts = [path.read_text(encoding="utf-8") for path in WORKFLOWS]
        paths = [pr_paths(text) for text in texts]
        for text in texts:
            self.assertEqual(text.count("python3 " + SHARED_RUNNER), 1,
                             "Both dedicated jobs must independently run shared contracts")
        required = runner_tests() | CRITICAL_SHARED_SOURCES | {THIS_TEST, SHARED_RUNNER}
        for path in required:
            self.assertTrue((ROOT / path).is_file(), path)
            for flow, filtered in zip(WORKFLOWS, paths):
                with self.subTest(source=path, workflow=flow.name):
                    self.assertIn(path, filtered,
                                  "Source changes must run the dedicated API and Pages contracts")

    def test_shared_runner_is_not_replaced_by_inert_or_incomplete_steps(self):
        for workflow_path in WORKFLOWS:
            text = workflow_path.read_text(encoding="utf-8")
            self.assertIn("- run: python3 " + SHARED_RUNNER, text)
            for filename in runner_tests():
                self.assertNotIn("-p '" + filename.removeprefix("tests/") + "'", text,
                                 "A test must not be launched twice inside one workflow")

    def test_both_protected_main_reconciliation_triggers_remain_broad(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("  push:\n    branches: [main]", text)
            self.assertNotRegex(text, r"(?m)^  push:\n    paths:",
                                "Never limit automatic staging reconciliation to file paths")


if __name__ == "__main__":
    unittest.main()
