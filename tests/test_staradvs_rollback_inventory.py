import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_rollback_inventory as plan

LIVE = "a" * 40
OLD = "b" * 40
OTHER = "c" * 40


def deployment(sha=OLD, **overrides):
    row = {
        "id": "e233c23e-3b66-4184-8be2-7e32ea2d64a5",
        "project_name": plan.pages.PROJECT,
        "environment": "production",
        "latest_stage": {"status": "success"},
        "deployment_trigger": {"metadata": {
            "branch": "main", "commit_hash": sha, "commit_dirty": False,
        }},
        "created_on": "2026-10-23T09:30:00Z",
    }
    row.update(overrides)
    return row


class ReadOnlyRollbackInventoryTests(unittest.TestCase):
    def test_only_owned_successful_main_branch_deployments_are_candidates(self):
        active = deployment(LIVE, id="4092240d-fdbb-4c7d-8f33-11a103f9c999",
                            created_on="2026-10-23T10:00:00Z")
        previous = deployment()
        report = plan.select_candidates([active, previous], LIVE)
        self.assertEqual(report["live_sha"], LIVE)
        self.assertEqual(report["matching_live_deployments"], 1)
        self.assertEqual(report["potential_previous"], [{
            "deployment_id": previous["id"],
            "source_sha": OLD,
            "created_on": previous["created_on"],
        }])
        self.assertTrue(report["incomplete_history_possible"])

    def test_refuse_preview_foreign_dirty_failed_or_untyped_candidates(self):
        active = deployment(LIVE, id="4092240d-fdbb-4c7d-8f33-11a103f9c999")
        dirty = deployment(OTHER, deployment_trigger={"metadata": {
            "branch": "main", "commit_hash": OTHER, "commit_dirty": True,
        }})
        foreign = deployment(OTHER, project_name="unrelated-pages")
        preview = deployment(OTHER, environment="preview")
        failed = deployment(OTHER, latest_stage={"status": "failure"})
        other_branch = deployment(OTHER, deployment_trigger={"metadata": {
            "branch": "dev", "commit_hash": OTHER, "commit_dirty": False,
        }})
        malformed = deployment(OTHER, id="../../staging")
        report = plan.select_candidates([active, dirty, foreign, preview, failed, other_branch, malformed], LIVE)
        self.assertEqual(report["potential_previous"], [])

    def test_no_match_to_live_public_sha_fails_closed(self):
        with self.assertRaisesRegex(plan.pages.AdmissionError, "absent from owned"):
            plan.select_candidates([deployment(OLD)], LIVE)
        for broken in ([], {}, None):
            with self.assertRaises(plan.pages.AdmissionError):
                plan.select_candidates(broken, LIVE)
        with self.assertRaisesRegex(plan.pages.AdmissionError, "SHA"):
            plan.select_candidates([deployment(OLD)], "main")

    def test_duplicate_revision_is_not_an_additional_rollback_choice(self):
        active = deployment(LIVE, id="4092240d-fdbb-4c7d-8f33-11a103f9c999")
        duplicate = deployment(OLD, id="db566ef1-bd8c-4d30-9896-8bd26857993a",
                               created_on="2026-10-22T09:00:00Z")
        report = plan.select_candidates([active, duplicate, deployment(OLD)], LIVE)
        self.assertEqual(len(report["potential_previous"]), 1)
        self.assertEqual(report["potential_previous"][0]["source_sha"], OLD)

    def test_cloudflare_and_ownership_inventory_is_get_only(self):
        class FakePages:
            account = "f" * 32
            calls = []
            def request(self, method, path, data=None):
                self.calls.append((method, path))
                if path.endswith("/deployments?env=production&per_page=50&page=1"):
                    return 200, [deployment(LIVE)]
                raise AssertionError("Unexpected endpoint " + path)
        fake = FakePages()
        with patch.object(plan.pages, "inspect", return_value=("z" * 32, {
            "project": "owned", "domain": "owned", "dns": "owned",
        })):
            result = plan.inventory(fake, LIVE)
        self.assertEqual(result["live_sha"], LIVE)
        self.assertEqual(result["potential_previous"], [])
        self.assertTrue(fake.calls)
        self.assertTrue(all(method == "GET" for method, _ in fake.calls))
        self.assertTrue(all("/pages/projects/staradvs-staging/" in path for _, path in fake.calls))

    def test_foreign_owned_staging_blocks_inventory_before_deployment_listing(self):
        class FakePages:
            account = "f" * 32
            def request(self, *_):
                raise AssertionError("Should not reach Cloudflare list")
        with patch.object(plan.pages, "inspect", return_value=("z", {
            "project": "owned", "domain": "absent", "dns": "owned",
        })):
            with self.assertRaisesRegex(plan.pages.AdmissionError, "completely owned"):
                plan.inventory(FakePages(), LIVE)


if __name__ == "__main__":
    unittest.main()
