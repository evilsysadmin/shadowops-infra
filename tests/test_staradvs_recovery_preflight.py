import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_recovery_preflight as preflight
import staradvs_pages as pages

LIVE = "a" * 40
OLD = "b" * 40
OTHER = "c" * 40
DEPLOYMENT = "e233c23e-3b66-4184-8be2-7e32ea2d64a5"


def candidate(sha=OLD):
    return {
        "source_sha": sha,
        "deployment_id": DEPLOYMENT,
        "created_on": "2026-10-22T10:00:00Z",
        "infra_publish_run_id": 339,
        "verified_receipt_id": 77,
    }


def inventory_result():
    return {"live_sha": LIVE, "potential_previous": [candidate()]}


def attested_result():
    return {"live_sha": LIVE, "receipt_backed_previous": [candidate()]}


def cloudflare_detail(sha=OLD, **overrides):
    row = {
        "id": DEPLOYMENT,
        "project_name": pages.PROJECT,
        "environment": "production",
        "latest_stage": {"status": "success"},
        "deployment_trigger": {"metadata": {
            "branch": "main", "commit_hash": sha, "commit_dirty": False,
        }},
        "created_on": "2026-10-22T10:00:00Z",
    }
    row.update(overrides)
    return row


class FakeClient:
    account = "f" * 32

    def __init__(self, row=None):
        self.calls = []
        self.row = cloudflare_detail() if row is None else row

    def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        expected = (f"/accounts/{self.account}/pages/projects/{pages.PROJECT}"
                    f"/deployments/{DEPLOYMENT}")
        if (method, path, data) != ("GET", expected, None):
            raise AssertionError("Unexpected / mutable Cloudflare request")
        return 200, self.row


class ReadOnlyRecoveryPreflightTests(unittest.TestCase):
    def run_rehearsal(self, hold=None, row=None, requested="", changes=(LIVE, LIVE)):
        client = FakeClient(row)
        snapshot = iter(changes)
        with (
            patch.object(preflight, "public_sha", side_effect=lambda: next(snapshot)),
            patch.object(preflight, "inventory", return_value=inventory_result()) as inv,
            patch.object(preflight, "corroborate", return_value=attested_result()) as evidence,
            patch.object(preflight, "verify_immutable_target", return_value="https://facecafe.staradvs-staging.pages.dev") as immutable,
        ):
            result = preflight.prepare_readonly_plan(
                client, object(), hold or {"mode": "auto"}, requested
            )
        self.assertEqual(inv.call_count, 1)
        self.assertEqual(evidence.call_count, 1)
        self.assertEqual(immutable.call_count, 1)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0][0], "GET")
        return result

    def test_default_plan_is_never_an_authorization_to_rollback(self):
        result = self.run_rehearsal()
        self.assertEqual(result["live_sha"], LIVE)
        self.assertEqual(result["target_sha"], OLD)
        self.assertEqual(result["target_deployment_id"], DEPLOYMENT)
        self.assertEqual(result["target_receipt_id"], 77)
        self.assertEqual(result["target_immutable_url"], "https://facecafe.staradvs-staging.pages.dev")
        self.assertEqual(result["forward_sha"], LIVE)
        self.assertEqual(result["hold"], "inactive")
        self.assertEqual(result["rehearsal"], "preview_only")
        self.assertIs(result["can_mutate"], False)
        self.assertEqual(result["operator_approval"], "not_given")
        self.assertEqual(result["rollback_api_method"], "POST (not called)")

    def test_explicit_valid_active_hold_is_still_only_readonly_preflight(self):
        state = {"mode": "hold", "anchor_sha": LIVE,
                 "expires_at": "2026-10-23T16:00:00Z", "issue": "#174"}
        result = self.run_rehearsal(hold=state, requested=OLD)
        self.assertEqual(result["hold"], "active")
        self.assertEqual(result["rehearsal"], "held_preflight_only")
        self.assertIs(result["can_mutate"], False)
        self.assertEqual(result["hold_anchor_sha"], LIVE)

    def test_active_hold_cannot_anchor_an_unknown_or_already_reverted_public_version(self):
        with self.assertRaisesRegex(pages.AdmissionError, "Hold anchor differs"):
            preflight.assess_hold({"mode": "hold", "anchor_sha": OTHER}, LIVE)

    def test_never_use_unattested_sha_or_current_live_sha_as_rollback(self):
        for invalid in (OTHER, LIVE, "main", "A" * 40):
            with self.subTest(sha=invalid):
                with self.assertRaises(pages.AdmissionError):
                    preflight.select_attested_candidate(attested_result(), invalid)
        with self.assertRaisesRegex(pages.AdmissionError, "No receipt-backed"):
            preflight.select_attested_candidate(
                {"live_sha": LIVE, "receipt_backed_previous": []}, ""
            )

    def test_pages_detail_with_mismatched_sha_foreign_project_or_failed_stage_blocks(self):
        variants = [
            cloudflare_detail(OTHER),
            cloudflare_detail(project_name="foreign-pages"),
            cloudflare_detail(environment="preview"),
            cloudflare_detail(latest_stage={"status": "failure"}),
            cloudflare_detail(deployment_trigger={"metadata": {
                "branch": "dev", "commit_hash": OLD, "commit_dirty": False,
            }}),
        ]
        for row in variants:
            with self.subTest(row=row):
                with self.assertRaisesRegex(pages.AdmissionError, "details disagree"):
                    preflight.confirm_exact_pages_candidate(FakeClient(row), candidate())

    def test_public_sha_change_during_inspection_blocks_potentially_stale_plan(self):
        with self.assertRaisesRegex(pages.AdmissionError, "changed during"):
            self.run_rehearsal(changes=(LIVE, OTHER))

    def test_invalid_candidate_uuid_receipt_and_ambiguous_selection_block(self):
        for altered in (
            {"deployment_id": "../evil"},
            {"infra_publish_run_id": 0},
            {"verified_receipt_id": "77"},
            {"source_sha": LIVE},
        ):
            with self.subTest(change=altered):
                item = {**candidate(), **altered}
                with self.assertRaisesRegex(pages.AdmissionError, "Malformed"):
                    preflight.select_attested_candidate(
                        {"live_sha": LIVE, "receipt_backed_previous": [item]}, ""
                    )
        with self.assertRaisesRegex(pages.AdmissionError, "not uniquely"):
            preflight.select_attested_candidate(
                {"live_sha": LIVE, "receipt_backed_previous": [candidate(), candidate()]}, OLD
            )


if __name__ == "__main__":
    unittest.main()
