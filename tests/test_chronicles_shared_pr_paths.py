"""Guard shared Chronicles admission PR path coverage without duplicating test lists."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (
    ROOT / ".github/workflows/chronicles-api-staging.yml",
    ROOT / ".github/workflows/chronicles-pages-release.yml",
)
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


def contract_tests(workflow: str) -> set[str]:
    return {"tests/" + filename for filename in re.findall(
        r"-p '([^']+\.py)'", workflow,
    )}


class SharedStagingPathContract(unittest.TestCase):
    def test_shared_receipt_sources_and_common_tests_trigger_both_pr_suites(self):
        texts = [path.read_text(encoding="utf-8") for path in WORKFLOWS]
        paths = [pr_paths(text) for text in texts]
        common = contract_tests(texts[0]) & contract_tests(texts[1])
        self.assertGreaterEqual(len(common), 5, "Shared tests unexpectedly missing")
        required = common | CRITICAL_SHARED_SOURCES | {THIS_TEST}
        for path in required:
            self.assertTrue((ROOT / path).is_file(), path)
            for flow, filtered in zip(WORKFLOWS, paths):
                with self.subTest(source=path, workflow=flow.name):
                    self.assertIn(path, filtered,
                                  "Source changes must run the dedicated API and Pages contracts")

    def test_both_protected_main_reconciliation_triggers_remain_broad(self):
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            self.assertIn("  push:\n    branches: [main]", text)
            self.assertNotRegex(text, r"(?m)^  push:\n    paths:",
                                "Never limit automatic staging reconciliation to file paths")


if __name__ == "__main__":
    unittest.main()
