"""The completed first Pages upload must never become executable again."""
import unittest
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / ".github/workflows/bridgesquad-pages-bootstrap.yml"


class BootstrapWorkflowTests(unittest.TestCase):
    def test_retired_bootstrap_is_contract_only(self):
        text = PATH.read_text(encoding="utf-8")
        for forbidden in ("\n  bootstrap:\n", "secrets.", "pages deploy", "workflow_dispatch:", "environment:", "actions: write", "actions: read"):
            self.assertNotIn(forbidden, text)
        for required in ("test_bridgesquad_alias_bootstrap.py", "test_bridgesquad_source_admission.py", "test_bridgesquad_release_package.py", "bridgesquad-identity-gate.test.mjs"):
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
