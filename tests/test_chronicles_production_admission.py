"""Production never promotes a SHA without two exact trusted staging receipts."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_production_admission as promotion

SHA = "a" * 40
TOKEN = "read-only-token"


def fake_get(*, missing=None, corrupt=None, ancestor=True):
    calls = []
    def get(path, token):
        assert token == TOKEN
        calls.append(path)
        if "/compare/" in path:
            return {"status": "ahead" if ancestor else "diverged"}
        if "/actions/artifacts?" in path:
            kind = "api" if "chronicles-api-staging-" in path else "pages"
            return {"total_count": 0 if kind == missing else 1,
                    "artifacts": [] if kind == missing else [{
                        "name": promotion.RECEIPTS[kind][1] + SHA,
                        "expired": False,
                        "workflow_run": {"id": 1 if kind == "api" else 2, "head_branch": "main"},
                    }]}
        if "/actions/runs/" in path:
            kind = "api" if path.endswith("/1") else "pages"
            row = {"id": 1 if kind == "api" else 2, "status": "completed",
                   "conclusion": "success", "path": promotion.RECEIPTS[kind][0],
                   "head_branch": "main", "repository": {"full_name": promotion.INFRA},
                   "event": "workflow_dispatch"}
            if kind == corrupt:
                row["conclusion"] = "failure"
            return row
        raise AssertionError(path)
    return get, calls


class PromotionGateTests(unittest.TestCase):
    def test_admits_only_two_successful_receipts_and_green_source(self):
        get, calls = fake_get()
        promotion.admit(SHA, TOKEN, read=get, source_ci=lambda *_: "ready")
        self.assertEqual(sum("/actions/artifacts?" in p for p in calls), 2)
        for kind in ("api", "pages"):
            with self.subTest(kind=kind):
                get, _ = fake_get(missing=kind)
                with self.assertRaisesRegex(promotion.PromotionError, "Missing successful"):
                    promotion.admit(SHA, TOKEN, read=get, source_ci=lambda *_: "ready")
                get, _ = fake_get(corrupt=kind)
                with self.assertRaisesRegex(promotion.PromotionError, "Missing successful"):
                    promotion.admit(SHA, TOKEN, read=get, source_ci=lambda *_: "ready")

    def test_older_main_commit_allowed_but_unmerged_sha_rejected(self):
        get, _ = fake_get()
        promotion.admit(SHA, TOKEN, read=get, source_ci=lambda *_: "ready")
        get, _ = fake_get(ancestor=False)
        with self.assertRaisesRegex(promotion.PromotionError, "protected main"):
            promotion.admit(SHA, TOKEN, read=get, source_ci=lambda *_: "ready")

    def test_refuses_missing_sha_token_and_failed_source_ci(self):
        get, _ = fake_get()
        for sha, token in (("", TOKEN), ("b" * 39, TOKEN), (SHA, "")):
            with self.subTest(sha=sha):
                with self.assertRaises(promotion.PromotionError):
                    promotion.admit(sha, token, read=get, source_ci=lambda *_: "ready")
        with self.assertRaisesRegex(promotion.PromotionError, "required CI"):
            promotion.admit(SHA, TOKEN, read=get, source_ci=lambda *_: "blocked")

    def test_rejects_untrusted_run_identity_and_artifact_status(self):
        for kind in ("api", "pages"):
            get, _ = fake_get()
            def untrusted(path, token):
                data = get(path, token)
                if "/actions/runs/" in path:
                    data["repository"]["full_name"] = promotion.SOURCE
                return data
            self.assertFalse(promotion.verified_receipt(SHA, kind, TOKEN, untrusted))
            def expired(path, token):
                data = get(path, token)
                if "/actions/artifacts?" in path:
                    for item in data["artifacts"]:
                        item["expired"] = True
                return data
            self.assertFalse(promotion.verified_receipt(SHA, kind, TOKEN, expired))


if __name__ == "__main__":
    unittest.main()
