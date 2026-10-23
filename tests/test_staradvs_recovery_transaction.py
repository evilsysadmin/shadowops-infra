import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_pages as pages
import staradvs_recovery_transaction as tx

NOW = datetime(2026, 10, 23, 14, 0, 0, tzinfo=timezone.utc)
LIVE = "a" * 40
TARGET = "b" * 40
UUID = "79bc9d01-d101-4527-8071-84f24a03ec35"
ORIGIN = "https://79bc9d01.staradvs-staging.pages.dev"


def approval(**changes):
    data = {
        "mode": "armed",
        "operation": "rollback",
        "live_sha": LIVE,
        "target_sha": TARGET,
        "target_deployment_id": UUID,
        "target_publish_run_id": 39954612779,
        "target_receipt_id": 12501479242,
        "hold_issue": "#174",
        "expires_at": "2026-10-23T15:00:00Z",
    }
    data.update(changes)
    return data


def hold(**changes):
    data = {
        "mode": "hold",
        "anchor_sha": LIVE,
        "expires_at": "2026-10-23T16:00:00Z",
        "reason": "Controlled recovery rehearsal with explicit review",
        "issue": "#174",
    }
    data.update(changes)
    return data


def plan(**changes):
    data = {
        "hold": "active",
        "hold_anchor_sha": LIVE,
        "live_sha": LIVE,
        "forward_sha": LIVE,
        "target_sha": TARGET,
        "target_deployment_id": UUID,
        "target_release_run_id": 39954612779,
        "target_receipt_id": 12501479242,
        "target_immutable_url": ORIGIN,
        "can_mutate": False,
        "operator_approval": "not_given",
    }
    data.update(changes)
    return data


def event(**changes):
    data = {
        "repository": tx.REPO,
        "ref": "refs/heads/main",
        "event_name": "workflow_dispatch",
        "environment": "staging-recovery",
    }
    data.update(changes)
    return data


CONFIRM = f"ROLLBACK {LIVE} TO {TARGET}"


class Client:
    account = "f" * 32
    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply if reply is not None else {
            "project_name": pages.PROJECT,
            "environment": "production",
        }

    def request(self, method, path):
        self.calls.append((method, path))
        if method != "POST" or path != (
            f"/accounts/{self.account}/pages/projects/{pages.PROJECT}"
            f"/deployments/{UUID}/rollback"
        ):
            raise AssertionError("Unexpected Pages mutation or wrong project")
        return 200, self.reply


def simulate(client=None, approve=None, current_hold=None, current_plan=None,
             confirm=CONFIRM, ctx=None, read_public=LIVE, fresh_hold=None):
    pages_client = client if client is not None else Client()
    hold_data = current_hold if current_hold is not None else hold()
    auth_data = approve if approve is not None else approval()
    plan_data = current_plan if current_plan is not None else plan()
    guards = {
        "plan_builder": Mock(return_value=plan_data),
        "check_main": Mock(),
        "public_sha": Mock(return_value=read_public),
        "public_integrity": Mock(),
        "recheck_hold": Mock(return_value=fresh_hold if fresh_hold is not None else hold_data),
    }
    result = tx.rollback_once(
        pages_client, object(), hold_data, auth_data, confirm, NOW,
        ctx if ctx is not None else event(), **guards
    )
    return result, pages_client, guards


class RecoveryTransactionTests(unittest.TestCase):
    def test_default_authorization_is_explicitly_disabled(self):
        actual = tx.load_authorization()
        self.assertEqual(actual, {"mode": "disabled"})
        with self.assertRaisesRegex(pages.AdmissionError, "disabled"):
            tx.authorize_rollback(actual, hold(), plan(), CONFIRM, NOW, event())

    def test_one_exact_reviewed_rollback_reaches_only_owned_cloudflare_endpoint(self):
        output, client, guards = simulate()
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(client.calls[0][0], "POST")
        self.assertEqual(output["restored_sha"], TARGET)
        self.assertEqual(output["source_sha"], LIVE)
        self.assertTrue(output["needs_public_browser_verification"])
        self.assertTrue(output["needs_explicit_forward_recovery"])
        self.assertEqual(guards["plan_builder"].call_args.args[-1], TARGET)
        self.assertEqual(guards["check_main"].call_count, 2)
        guards["public_integrity"].assert_called_once_with(TARGET)
        guards["recheck_hold"].assert_called_once()

    def test_fail_closed_on_hold_expired_absent_wrong_anchor_or_issue(self):
        bad_states = [
            {"mode": "auto"},
            hold(expires_at="2026-10-23T13:00:00Z"),
            hold(anchor_sha="c" * 40),
            hold(issue="#175"),
        ]
        for state in bad_states:
            with self.subTest(hold=state):
                client = Client()
                with self.assertRaises(pages.AdmissionError):
                    simulate(client=client, current_hold=state)
                self.assertEqual(client.calls, [])

    def test_fail_closed_on_missing_expired_or_wrong_approval(self):
        bad = [
            {"mode": "disabled"},
            approval(expires_at="2026-10-23T13:00:00Z"),
            approval(expires_at="2026-10-23T16:00:01Z"),
            approval(target_sha="c" * 40),
            approval(live_sha="c" * 40),
            approval(target_deployment_id="../foreign"),
            approval(target_publish_run_id=0),
            approval(target_receipt_id=False),
            approval(hold_issue="#175"),
            approval(operation="forward"),
            approval(extra="unexpected"),
        ]
        for a in bad:
            with self.subTest(approval=a):
                client = Client()
                with self.assertRaises(pages.AdmissionError):
                    simulate(client=client, approve=a)
                self.assertEqual(client.calls, [])

    def test_fail_closed_on_stale_receipt_plan_wrong_immutable_url(self):
        for bad in [
            plan(target_receipt_id=999),
            plan(target_deployment_id="00000000-0000-4000-8000-000000000000"),
            plan(target_sha="c" * 40),
            plan(live_sha="c" * 40),
            plan(target_immutable_url="https://main.staradvs-staging.pages.dev"),
            plan(can_mutate=True),
            plan(operator_approval="given"),
        ]:
            with self.subTest(plan=bad):
                client = Client()
                with self.assertRaises(pages.AdmissionError):
                    simulate(client=client, current_plan=bad)
                self.assertEqual(client.calls, [])

    def test_manual_main_and_reviewed_environment_are_mandatory(self):
        for ctx in [
            event(repository="attacker/fork"),
            event(ref="refs/heads/feature"),
            event(event_name="push"),
            event(environment="staging"),
        ]:
            with self.subTest(event=ctx):
                client = Client()
                with self.assertRaisesRegex(pages.AdmissionError, "dedicated manual"):
                    simulate(client=client, ctx=ctx)
                self.assertEqual(client.calls, [])

    def test_exact_two_shas_operator_confirmation_required(self):
        client = Client()
        with self.assertRaisesRegex(pages.AdmissionError, "confirmation"):
            simulate(client=client, confirm="ROLLBACK")
        self.assertEqual(client.calls, [])

    def test_pre_post_guards_cannot_be_absent_or_ignored(self):
        with self.assertRaisesRegex(pages.AdmissionError, "callbacks"):
            tx.rollback_once(Client(), object(), hold(), approval(), CONFIRM, NOW, event(),
                             plan_builder=None, check_main=lambda: None,
                             public_sha=lambda: LIVE, public_integrity=lambda _: None,
                             recheck_hold=lambda: hold())
        client = Client()
        with self.assertRaisesRegex(pages.AdmissionError, "changed before"):
            simulate(client=client, fresh_hold=hold(expires_at="2026-10-23T15:59:59Z"))
        self.assertEqual(client.calls, [])
        client = Client()
        with self.assertRaisesRegex(pages.AdmissionError, "Public release changed"):
            simulate(client=client, read_public="c" * 40)
        self.assertEqual(client.calls, [])

    def test_mutation_response_must_confirm_isolated_staging(self):
        client = Client(reply={"project_name": "chess-studio", "environment": "production"})
        with self.assertRaisesRegex(pages.AdmissionError, "isolated staging"):
            simulate(client=client)
        self.assertEqual(len(client.calls), 1)  # HTTP mutation attempted; not success.
        client = Client(reply={"project_name": pages.PROJECT, "environment": "preview"})
        with self.assertRaises(pages.AdmissionError):
            simulate(client=client)

    def test_browser_is_not_claimed_by_backend_https_success(self):
        result, _, _ = simulate()
        self.assertEqual(result["status"], "historic_staging_https_verified_browser_pending")
        self.assertNotIn("browser_verified", result)

    def test_malformed_or_missing_reviewed_auth_config_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = pathlib.Path(tmp) / "authorization.json"
            with self.assertRaisesRegex(pages.AdmissionError, "missing"):
                tx.load_authorization(file)
            file.write_text("{broken", encoding="utf-8")
            with self.assertRaisesRegex(pages.AdmissionError, "JSON"):
                tx.load_authorization(file)


if __name__ == "__main__":
    unittest.main()
