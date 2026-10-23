import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_operator_plan as plan
import staradvs_pages as pages

LIVE = "a" * 40
TARGET = "b" * 40
CONFIRM = f"PLAN {LIVE} TO {TARGET}"


def report(**changes):
    data = {
        "project": pages.PROJECT,
        "public_url": pages.BASE,
        "live_sha": LIVE,
        "forward_sha": LIVE,
        "target_sha": TARGET,
        "forward_deployment_id": "2dcda9c2-67b7-4f2c-be14-c7693f82fcbb",
        "target_deployment_id": "79bc9d01-d101-4527-8071-84f24a03ec35",
        "forward_immutable_url": "https://2dcda9c2.staradvs-staging.pages.dev",
        "target_immutable_url": "https://79bc9d01.staradvs-staging.pages.dev",
        "forward_publish_run_id": 39959484119,
        "forward_receipt_id": 12504490911,
        "target_release_run_id": 39954612779,
        "target_receipt_id": 12501479242,
        "rollback_api_method": "POST (not called)",
        "hold": "inactive",
        "rehearsal": "preview_only",
        "operator_approval": "not_given",
        "can_mutate": False,
    }
    data.update(changes)
    return data


def log(data=None):
    return "Proof of immutable JS verified\n" + plan.PREFIX + json.dumps(
        report() if data is None else data, sort_keys=True
    ) + "\n"


class OperatorReadOnlyContractTests(unittest.TestCase):
    def test_successful_explicit_plan_is_not_mutation_approval(self):
        result = plan.validate_operator_plan(log(), LIVE, TARGET, CONFIRM)
        self.assertEqual(result["mode"], "read_only_operator_plan")
        self.assertEqual(result["hold"], "inactive")
        self.assertIs(result["can_mutate"], False)

    def test_active_hold_anchor_can_be_inspected_but_cannot_authorize_post(self):
        active = report(hold="active", rehearsal="held_preflight_only", hold_anchor_sha=LIVE)
        result = plan.validate_operator_plan(log(active), LIVE, TARGET, CONFIRM)
        self.assertEqual(result["hold"], "active")
        self.assertIs(result["can_mutate"], False)

    def test_exact_confirmation_and_distinct_full_sha_required(self):
        for kwargs in [
            {"confirmation": "EXECUTE"},
            {"expected_live_sha": "a" * 39},
            {"target_sha": LIVE},
            {"target_sha": "B" * 40},
        ]:
            args = {"log": log(), "expected_live_sha": LIVE,
                    "target_sha": TARGET, "confirmation": CONFIRM}
            args.update(kwargs)
            with self.subTest(args=kwargs):
                with self.assertRaises(pages.AdmissionError):
                    plan.validate_operator_plan(**args)

    def test_readonly_and_owned_recovery_identifiers_are_nonnegotiable(self):
        changes = [
            {"project": "other-pages"},
            {"public_url": "https://production.invalid"},
            {"live_sha": TARGET},
            {"forward_sha": TARGET},
            {"target_sha": LIVE},
            {"can_mutate": True},
            {"operator_approval": "given"},
            {"rollback_api_method": "POST"},
            {"forward_deployment_id": "invalid"},
            {"target_deployment_id": "../foreign"},
            {"target_deployment_id": "2dcda9c2-67b7-4f2c-be14-c7693f82fcbb"},
            {"forward_immutable_url": "https://main.staradvs-staging.pages.dev"},
            {"target_immutable_url": "https://79bc9d01.another-project.pages.dev"},
            {"forward_publish_run_id": 0},
            {"forward_receipt_id": True},
            {"target_release_run_id": 0},
            {"target_receipt_id": False},
        ]
        for change in changes:
            with self.subTest(change=change):
                with self.assertRaises(pages.AdmissionError):
                    plan.validate_operator_plan(log(report(**change)), LIVE, TARGET, CONFIRM)

    def test_invalid_hold_mode_or_anchor_fail_closed(self):
        for changed in [
            {"hold": "unknown"},
            {"hold": "inactive", "rehearsal": "held_preflight_only"},
            {"hold": "active", "rehearsal": "held_preflight_only"},
            {"hold": "active", "rehearsal": "held_preflight_only", "hold_anchor_sha": TARGET},
        ]:
            with self.subTest(state=changed):
                with self.assertRaises(pages.AdmissionError):
                    plan.validate_operator_plan(log(report(**changed)), LIVE, TARGET, CONFIRM)

    def test_missing_ambiguous_or_malformed_report_blocks(self):
        samples = [
            "",
            "Some other unrelated output\n",
            log() + log(),
            plan.PREFIX + "{bad json}\n",
            plan.PREFIX + "null\n",
        ]
        for raw in samples:
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(pages.AdmissionError):
                    plan.validate_operator_plan(raw, LIVE, TARGET, CONFIRM)


if __name__ == "__main__":
    unittest.main()
