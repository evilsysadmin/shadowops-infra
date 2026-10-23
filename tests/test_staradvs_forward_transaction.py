import pathlib
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_forward_transaction as tx
import staradvs_pages as pages

NOW = datetime(2026, 10, 23, 14, 0, 0, tzinfo=timezone.utc)
FORWARD = "a" * 40
RESTORED = "b" * 40
OLD_UUID = "79bc9d01-d101-4527-8071-84f24a03ec35"
FORWARD_UUID = "2dcda9c2-67b7-4f2c-be14-c7693f82fcbb"
CONFIRM = f"FORWARD {RESTORED} TO {FORWARD}"


def hold(**changes):
    obj = {
        "mode": "hold", "anchor_sha": FORWARD,
        "expires_at": "2026-10-23T16:00:00Z",
        "reason": "Reviewed isolated staging restore-and-return procedure",
        "issue": "#174",
    }
    obj.update(changes)
    return obj


def original(**changes):
    obj = {
        "live_sha": FORWARD, "forward_sha": FORWARD,
        "forward_deployment_id": FORWARD_UUID,
        "forward_immutable_url": "https://2dcda9c2.staradvs-staging.pages.dev",
        "forward_publish_run_id": 39959484119,
        "forward_receipt_id": 12504490911,
        "target_sha": RESTORED,
        "target_deployment_id": OLD_UUID,
        "target_immutable_url": "https://79bc9d01.staradvs-staging.pages.dev",
        "hold": "active", "hold_anchor_sha": FORWARD,
        "can_mutate": False, "operator_approval": "not_given",
    }
    obj.update(changes)
    return obj


def approval(**changes):
    obj = {
        "mode": "armed", "operation": "forward",
        "live_sha": RESTORED, "target_sha": FORWARD,
        "target_deployment_id": FORWARD_UUID,
        "target_publish_run_id": 39959484119,
        "target_receipt_id": 12504490911,
        "hold_issue": "#174",
        "expires_at": "2026-10-23T15:00:00Z",
    }
    obj.update(changes)
    return obj


def event(**changes):
    obj = {
        "repository": tx.REPO, "ref": "refs/heads/main",
        "event_name": "workflow_dispatch", "environment": "staging-recovery",
    }
    obj.update(changes)
    return obj


def canonical(sha=RESTORED, **changes):
    obj = {
        "id": OLD_UUID, "project_name": pages.PROJECT, "environment": "production",
        "latest_stage": {"status": "success"},
        "deployment_trigger": {"metadata": {"branch": "main", "commit_hash": sha, "commit_dirty": False}},
        "created_on": "2026-10-23T13:00:00Z",
    }
    obj.update(changes)
    return obj


class Cloudflare:
    account = "f" * 32
    def __init__(self, current=None, rollback_result=None):
        self.calls = []
        self.current = canonical() if current is None else current
        self.rollback_result = rollback_result if rollback_result is not None else {
            "project_name": pages.PROJECT, "environment": "production",
        }

    def request(self, method, path):
        self.calls.append((method, path))
        root = f"/accounts/{self.account}/pages/projects/{pages.PROJECT}"
        if method == "GET" and path == root:
            return 200, {
                "name": pages.PROJECT, "production_branch": "main",
                "canonical_deployment": self.current,
            }
        if method == "POST" and path == root + f"/deployments/{FORWARD_UUID}/rollback":
            return 200, self.rollback_result
        raise AssertionError("Unexpected Pages request " + method + " " + path)


def simulate(cf=None, auth=None, snapshot=None, reviewed_hold=None, context=None,
             confirm=CONFIRM, browser=True, public=RESTORED, changed_hold=None,
             probed_url="https://2dcda9c2.staradvs-staging.pages.dev",
             receipt=None):
    client = cf if cf is not None else Cloudflare()
    h = reviewed_hold if reviewed_hold is not None else hold()
    guards = {
        "check_main": Mock(),
        "public_sha": Mock(return_value=public),
        "public_integrity": Mock(),
        "recheck_hold": Mock(return_value=changed_hold if changed_hold is not None else h),
        "restored_browser_proof": Mock(return_value=browser),
    }
    match_receipt = receipt if receipt is not None else {
        "forward_publish_run_id": 39959484119, "forward_receipt_id": 12504490911,
    }
    with (
        patch.object(tx, "confirm_exact_pages_candidate", return_value=probed_url) as immutable,
        patch.object(tx, "forward_release_receipt", return_value=match_receipt) as receipts,
    ):
        result = tx.forward_once(
            client, object(), h, auth if auth is not None else approval(),
            snapshot if snapshot is not None else original(),
            confirm, NOW, context if context is not None else event(), **guards,
        )
    return result, client, guards, immutable, receipts


class ForwardTransactionTests(unittest.TestCase):
    def test_successful_simulation_posts_only_to_original_staging_pages_uuid(self):
        result, client, guards, immutable, receipts = simulate()
        self.assertEqual(result["status"], "original_staging_https_verified_browser_pending")
        self.assertEqual(result["forward_sha"], FORWARD)
        self.assertTrue(result["needs_separately_reviewed_hold_resume"])
        self.assertEqual([m for m, _ in client.calls], ["GET", "POST"])
        self.assertTrue(client.calls[-1][1].endswith(FORWARD_UUID + "/rollback"))
        self.assertEqual(guards["check_main"].call_count, 2)
        guards["restored_browser_proof"].assert_called_once_with(RESTORED)
        guards["public_integrity"].assert_called_once_with(FORWARD)
        immutable.assert_called_once()
        receipts.assert_called_once()

    def assert_before_post(self, **options):
        cf = options.pop("cf", None)
        if cf is None:
            cf = Cloudflare()
        with self.assertRaises(pages.AdmissionError):
            simulate(cf=cf, **options)
        self.assertFalse(any(method == "POST" for method, _ in cf.calls))

    def test_wrong_or_expired_reviewed_auth_fails_closed(self):
        for a in [
            approval(mode="disabled"),
            approval(operation="rollback"),
            approval(live_sha=FORWARD),
            approval(target_sha=RESTORED),
            approval(target_deployment_id=OLD_UUID),
            approval(target_publish_run_id=3),
            approval(target_receipt_id=0),
            approval(hold_issue="#99"),
            approval(expires_at="2026-10-23T13:00:00Z"),
            approval(expires_at="2026-10-23T16:00:01Z"),
            approval(unexpected="data"),
        ]:
            with self.subTest(approval=a):
                self.assert_before_post(auth=a)

    def test_hold_must_remain_original_version_and_unexpired(self):
        for h in [
            hold(mode="auto"),
            hold(anchor_sha=RESTORED),
            hold(issue="#99"),
            hold(expires_at="2026-10-23T13:00:00Z"),
        ]:
            with self.subTest(hold=h):
                self.assert_before_post(reviewed_hold=h)
        self.assert_before_post(changed_hold=hold(expires_at="2026-10-23T15:59:59Z"))

    def test_original_snapshot_must_match_forward_deployment_and_receipt(self):
        for record in [
            original(live_sha=RESTORED),
            original(forward_sha=RESTORED),
            original(target_sha=FORWARD),
            original(forward_deployment_id=OLD_UUID),
            original(forward_receipt_id=0),
            original(forward_publish_run_id=0),
            original(forward_immutable_url="https://main.staradvs-staging.pages.dev"),
            original(hold="inactive"),
            original(hold_anchor_sha=RESTORED),
            original(can_mutate=True),
            original(operator_approval="given"),
        ]:
            with self.subTest(snapshot=record):
                self.assert_before_post(snapshot=record)

    def test_manual_reviewed_environment_and_exact_confirmation_required(self):
        for context in [
            event(repository="foreign/repo"),
            event(ref="refs/heads/feature"),
            event(event_name="push"),
            event(environment="staging"),
        ]:
            with self.subTest(context=context):
                self.assert_before_post(context=context)
        self.assert_before_post(confirm=f"FORWARD {FORWARD} TO {RESTORED}")

    def test_no_forward_if_restored_browser_evidence_is_missing_or_incorrect(self):
        for v in [False, None, 1, "true"]:
            self.assert_before_post(browser=v)
        self.assert_before_post(public=FORWARD)

    def test_no_forward_if_cloudflare_canonical_is_not_the_historic_rollback(self):
        bad = [
            canonical(sha=FORWARD),
            canonical(project_name="other"),
            canonical(environment="preview"),
            canonical(latest_stage={"status": "failure"}),
        ]
        for row in bad:
            with self.subTest(row=row):
                cf = Cloudflare(current=row)
                self.assert_before_post(cf=cf)

    def test_no_forward_on_changed_immutable_origin_or_expired_release_receipt(self):
        self.assert_before_post(probed_url="https://deadbeef.staradvs-staging.pages.dev")
        self.assert_before_post(receipt={
            "forward_publish_run_id": 39959484119, "forward_receipt_id": 9,
        })

    def test_post_response_not_called_verified_if_wrong_environment(self):
        cf = Cloudflare(rollback_result={"project_name": "foreign", "environment": "production"})
        with self.assertRaisesRegex(pages.AdmissionError, "isolated staging"):
            simulate(cf=cf)
        self.assertEqual([op for op, _ in cf.calls], ["GET", "POST"])

    def test_absent_main_freshness_callback_is_not_accepted(self):
        with self.assertRaisesRegex(pages.AdmissionError, "callbacks"):
            tx.forward_once(
                Cloudflare(), object(), hold(), approval(), original(),
                CONFIRM, NOW, event(), check_main=None, public_sha=lambda: RESTORED,
                public_integrity=lambda _: None, recheck_hold=lambda: hold(),
                restored_browser_proof=lambda _: True,
            )

    def test_default_config_not_forward_armed(self):
        from staradvs_recovery_transaction import load_authorization
        auth = load_authorization()
        self.assertEqual(auth, {"mode": "disabled"})
        self.assert_before_post(auth=auth)


if __name__ == "__main__":
    unittest.main()
