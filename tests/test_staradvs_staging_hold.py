import pathlib
import sys
import tempfile
import json
import unittest
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_staging_hold as hold

NOW = datetime(2026, 10, 23, 13, 0, 0, tzinfo=timezone.utc)


def config(**override):
    data = {
        "mode": "hold",
        "anchor_sha": "a" * 40,
        "expires_at": "2026-10-23T15:00:00Z",
        "reason": "Controlled staging-only rollback drill; block automatic publication",
        "issue": "#174",
    }
    data.update(override)
    return data


class HoldGateTests(unittest.TestCase):
    def test_auto_mode_is_exact_and_inactive_by_default(self):
        self.assertEqual(hold.parse_hold({"mode": "auto"}, NOW), {"mode": "auto"})
        with self.assertRaisesRegex(hold.HoldConfigError, "no extra"):
            hold.parse_hold({"mode": "auto", "issue": "#174"}, NOW)

    def test_active_hold_is_a_bounded_auditable_gate(self):
        state = hold.parse_hold(config(), NOW)
        self.assertEqual(state["anchor_sha"], "a" * 40)
        self.assertEqual(state["mode"], "hold")
        self.assertEqual(state["expires_at"], "2026-10-23T15:00:00Z")

    def test_expiry_is_fail_closed_even_one_second_after_deadline(self):
        expiry = datetime(2026, 10, 23, 15, 0, 0, tzinfo=timezone.utc)
        with self.assertRaisesRegex(hold.HoldConfigError, "expired"):
            hold.parse_hold(config(), expiry)
        with self.assertRaisesRegex(hold.HoldConfigError, "expired"):
            hold.parse_hold(config(), expiry + timedelta(seconds=1))

    def test_unknown_mode_invalid_shas_bad_reason_issue_and_extra_fields_fail(self):
        cases = [
            {"mode": "resume"},
            {"anchor_sha": "main"},
            {"anchor_sha": "A" * 40},
            {"reason": "short"},
            {"reason": "injection\nnext"},
            {"issue": "https://github.com/a/b"},
            {"issue": "#0"},
            {"unexpected": "yes"},
        ]
        for change in cases:
            with self.subTest(change=change):
                with self.assertRaises(hold.HoldConfigError):
                    hold.parse_hold(config(**change), NOW)

    def test_hold_requires_valid_utc_timestamp_and_24_hour_limit(self):
        for expiry in [
            "2026-10-24T13:00:01Z",
            "2026-10-23T15:00:00+02:00",
            "2026-13-23T15:00:00Z",
            "2099-12-31T23:59:59Z",
            "2026-10-22T15:00:00Z",
        ]:
            with self.subTest(expiry=expiry):
                with self.assertRaises(hold.HoldConfigError):
                    hold.parse_hold(config(expires_at=expiry), NOW)
        approved = hold.parse_hold(config(expires_at="2026-10-24T13:00:00Z"), NOW)
        self.assertEqual(approved["mode"], "hold")

    def test_missing_malformed_oversized_files_block_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "hold.json"
            with self.assertRaisesRegex(hold.HoldConfigError, "absent"):
                hold.load_hold(path, NOW)
            path.write_text("{bad", encoding="utf-8")
            with self.assertRaisesRegex(hold.HoldConfigError, "not valid JSON"):
                hold.load_hold(path, NOW)
            path.write_text("x" * 4097, encoding="utf-8")
            with self.assertRaisesRegex(hold.HoldConfigError, "oversized"):
                hold.load_hold(path, NOW)
            path.write_text(json.dumps(config()), encoding="utf-8")
            self.assertEqual(hold.load_hold(path, NOW)["mode"], "hold")

    def test_default_repo_state_leaves_existing_automatic_staging_enabled(self):
        state = hold.load_hold(ROOT / "config" / "staradvs-staging-hold.json", NOW)
        self.assertEqual(state, {"mode": "auto"})


if __name__ == "__main__":
    unittest.main()
