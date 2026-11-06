import importlib.util
import pathlib
import unittest
from unittest.mock import patch

path = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "staradvs_infra_revision.py"
spec = importlib.util.spec_from_file_location("staradvs_infra_revision", path)
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)

PINNED = "a" * 40
CURRENT = "b" * 40
POLICY = ".github/workflows/staradvs-pages-staging.yml"
RELEVANT = "scripts/staradvs_pages.py"


def tree(files, truncated=False):
    return {"truncated": truncated, "tree": [
        {"path": path, "type": "blob", "sha": sha}
        for path, sha in files.items()
    ]}


def reader(old, new):
    return lambda sha: old if sha == PINNED else new if sha == CURRENT else None


class InfraRevisionTests(unittest.TestCase):
    def test_unrelated_chronicles_change_does_not_block_staging(self):
        old = tree({POLICY: "1" * 40, RELEVANT: "2" * 40})
        new = tree({POLICY: "1" * 40, RELEVANT: "2" * 40,
                    ".github/workflows/chronicles-r2-private-inventory.yml": "3" * 40,
                    "scripts/chronicles_r2_private_inventory.py": "4" * 40,
                    ".github/workflows/ci.yml": "5" * 40})
        self.assertEqual(app.compare(PINNED, CURRENT, reader(old, new)), (True, []))

    def test_exact_same_infra_sha_needs_no_api_calls(self):
        def unexpected(_sha):
            raise AssertionError("Should not ask GitHub when immutable SHAs match")
        self.assertEqual(app.compare(PINNED, PINNED, unexpected), (True, []))

    def test_staging_workflow_change_blocks(self):
        old = tree({POLICY: "1" * 40, RELEVANT: "2" * 40})
        new = tree({POLICY: "3" * 40, RELEVANT: "2" * 40})
        self.assertEqual(app.compare(PINNED, CURRENT, reader(old, new)), (False, [POLICY]))

    def test_staging_script_change_blocks(self):
        old = tree({POLICY: "1" * 40, RELEVANT: "2" * 40})
        new = tree({POLICY: "1" * 40, RELEVANT: "3" * 40})
        self.assertEqual(app.compare(PINNED, CURRENT, reader(old, new)), (False, [RELEVANT]))

    def test_staging_hold_or_test_change_blocks(self):
        for name in ("config/staradvs-staging-hold.json",
                     "scripts/staradvs_source_admission.py",
                     "tests/test_staradvs_pages.py",
                     "tests/staradvs-public-browser.test.mjs"):
            with self.subTest(name=name):
                old = tree({POLICY: "1" * 40, name: "2" * 40})
                new = tree({POLICY: "1" * 40, name: "3" * 40})
                self.assertEqual(app.compare(PINNED, CURRENT, reader(old, new)), (False, [name]))

    def test_added_or_deleted_staging_file_blocks(self):
        old = tree({POLICY: "1" * 40, RELEVANT: "2" * 40})
        new = tree({POLICY: "1" * 40})
        self.assertEqual(app.compare(PINNED, CURRENT, reader(old, new)), (False, [RELEVANT]))
        new = tree({POLICY: "1" * 40, RELEVANT: "2" * 40,
                    "scripts/staradvs_new_gate.py": "4" * 40})
        self.assertEqual(app.compare(PINNED, CURRENT, reader(old, new)),
                         (False, ["scripts/staradvs_new_gate.py"]))

    def test_missing_policy_or_truncated_tree_fails_closed(self):
        a = tree({POLICY: "1" * 40})
        for bad in (tree({}, False), tree({POLICY: "1" * 40}, True),
                    {"truncated": False}, {"tree": []}, None):
            with self.subTest(bad=bad), self.assertRaises(app.RevisionError):
                app.compare(PINNED, CURRENT, reader(a, bad))

    def test_malformed_staging_blob_fails_closed(self):
        a = tree({POLICY: "1" * 40})
        for item in (
            {"path": POLICY, "type": "tree", "sha": "1" * 40},
            {"path": POLICY, "type": "blob", "sha": "wrong"},
        ):
            bad = {"truncated": False, "tree": [item]}
            with self.subTest(item=item), self.assertRaises(app.RevisionError):
                app.compare(PINNED, CURRENT, reader(a, bad))

    def test_wrong_sha_rejected_before_any_api(self):
        for value in ("main", "A" * 40, "f" * 39):
            with self.subTest(value=value), self.assertRaises(app.RevisionError):
                app.compare(value, CURRENT, lambda _: None)

    def test_cli_fails_closed_when_tree_evidence_unavailable(self):
        with patch.object(app, "github_tree", side_effect=app.RevisionError("offline")):
            self.assertEqual(app.main([PINNED, CURRENT]), 1)

    def test_cli_allows_only_unrelated_advances(self):
        a = tree({POLICY: "1" * 40})
        with patch.object(app, "github_tree", side_effect=reader(a, a)):
            self.assertEqual(app.main([PINNED, CURRENT]), 0)


if __name__ == "__main__":
    unittest.main()
