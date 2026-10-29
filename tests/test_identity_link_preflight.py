"""Synthetic fixtures only; exercise account link safety without credentials."""
import copy
from pathlib import Path
import subprocess
import sys
import unittest

from scripts.identity_link_preflight import PlanError, validate_isolated_plans, validate_plan

U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"
U3 = "33333333-3333-4333-8333-333333333333"
ISSUE = "https://github.com/evilsysadmin/shadowops-infra/issues/287"


def row(source, username, subject, review=None):
    return {"source": source, "username": username, "subject": subject, "link_review_ref": review}


def plan(env, *rows):
    return {"schema_version": 1, "environment": env, "entries": list(rows)}


def denied(fn, message=None):
    with unittest.TestCase().assertRaises(PlanError) as exc:
        fn()
    if message:
        assert message in str(exc.exception)


class IdentityLinkPreflightTests(unittest.TestCase):
    def test_staging_only_does_not_claim_production_was_checked(self):
        result = validate_isolated_plans(plan("staging", row("chess-studio", "alice", U1)))
        self.assertEqual(result["staging"]["accounts"], 1)
        self.assertEqual(result["production"], "not-audited")

    def test_staging_and_production_same_username_but_separate_subject(self):
        result = validate_isolated_plans(
            plan("staging", row("chess-studio", "alice", U1)),
            plan("production", row("chess-studio", "alice", U2)),
        )
        self.assertEqual(result["production"]["subjects"], 1)

    def test_staging_and_prod_cannot_share_same_stable_identity(self):
        denied(lambda: validate_isolated_plans(
            plan("staging", row("chess-studio", "alice", U1)),
            plan("production", row("chess-studio", "alice", U1)),
        ), "overlap")

    def test_never_implicitly_link_accounts_with_same_username(self):
        result = validate_isolated_plans(plan("staging",
            row("chess-studio", "matthias", U1),
            row("chronicles", "matthias", U2)))
        self.assertEqual(result["staging"]["subjects"], 2)
        self.assertEqual(result["staging"]["cross_product_links_requiring_manual_review"], 0)

    def test_explicit_same_subject_requires_common_review_reference(self):
        denied(lambda: validate_plan(plan("staging",
            row("chess-studio", "alice", U1),
            row("chronicles", "alice", U1)), "staging"), "review")
        stat, _ = validate_plan(plan("staging",
            row("chess-studio", "alice", U1, ISSUE),
            row("chronicles", "alice", U1, ISSUE)), "staging")
        self.assertEqual(stat["cross_product_links_requiring_manual_review"], 1)
        denied(lambda: validate_plan(plan("staging",
            row("chess-studio", "alice", U1, ISSUE),
            row("chronicles", "alice", U1, "https://github.com/evilsysadmin/shadowops-infra/issues/288")), "staging"))

    def test_prohibits_username_normalization_collision_within_one_source(self):
        for left, right in [("Alice", "alice"), ("K", "K"), ("A", "Ａ")]:
            denied(lambda: validate_plan(plan("staging",
                row("chess-studio", left, U1), row("chess-studio", right, U2)), "staging"))

    def test_rejects_duplicate_subject_for_two_accounts_in_same_product(self):
        denied(lambda: validate_plan(plan("staging",
            row("chess-studio", "alice", U1), row("chess-studio", "bob", U1)), "staging"))

    def test_rejects_wrong_environment_uuid_version_and_username_inputs(self):
        denied(lambda: validate_plan(plan("staging", row("chess-studio", "alice", U1)), "production"))
        denied(lambda: validate_plan(plan("staging", row("chess-studio", "alice", "alice")), "staging"))
        denied(lambda: validate_plan(plan("staging", row("chess-studio", "alice",
            "11111111-1111-1111-8111-111111111111")), "staging"))
        denied(lambda: validate_plan(plan("staging", row("chess-studio", " ", U1)), "staging"))
        denied(lambda: validate_plan(plan("staging", row("unknown", "alice", U1)), "staging"))
        denied(lambda: validate_plan(plan("staging", row(["chess-studio"], "alice", U1)), "staging"))

    def test_rejects_extra_fields_containing_email_password_or_hashes(self):
        for extra in ("password_hash", "email", "jwt_secret", "roles"):
            item = row("chess-studio", "alice", U1)
            item[extra] = "never-check-in"
            denied(lambda: validate_plan(plan("staging", item), "staging"), "PII")
        candidate = plan("staging", row("chess-studio", "alice", U1))
        candidate["mongo_uri"] = "never-check-in"
        denied(lambda: validate_plan(candidate, "staging"), "PII")

    def test_invalid_link_review_reference_is_rejected(self):
        denied(lambda: validate_plan(plan("staging",
            row("chess-studio", "alice", U1, "https://attacker.invalid/287")), "staging"))

    def test_summary_does_not_contain_any_legacy_account_id(self):
        result = validate_isolated_plans(plan("staging", row("chess-studio", "test-account-secret", U1)))
        self.assertNotIn("test-account-secret", repr(result))
        self.assertNotIn(U1, repr(result))

    def test_empty_unknown_or_unbounded_plan_is_rejected(self):
        for value in [
            plan("staging"), {"schema_version": 1, "environment": "staging", "entries": {}},
            {"schema_version": True, "environment": "staging", "entries": [row("chess-studio", "a", U1)]}
        ]:
            denied(lambda: validate_plan(value, "staging"))

    def test_main_with_invalid_input_fails_without_echoing_filename(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory:
            path = Path(directory) / "sensitive-usernames.json"
            path.write_text("{not json", encoding="utf8")
            proc = subprocess.run(
                [sys.executable, "scripts/identity_link_preflight.py", "--staging", str(path)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertNotIn("sensitive-usernames", proc.stderr)
            self.assertIn("PREFLIGHT_FAILED", proc.stderr)


if __name__ == "__main__":
    unittest.main()
