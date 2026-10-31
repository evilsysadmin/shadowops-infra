"""Offline source CI workflow identity and verdict tests."""
import io
import json
import pathlib
import sys
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import cka_account_source_ci as ci

SHA = "a" * 40
TOKEN = "test-read-token"


def run(workflow_id, *, state="completed", conclusion="success", **changes):
    name, path = ci.REQUIRED[workflow_id]
    out = {
        "id": workflow_id,
        "workflow_id": workflow_id,
        "name": name,
        "path": path,
        "head_sha": SHA,
        "event": "push",
        "head_branch": "main",
        "repository": {"full_name": ci.SOURCE},
        "status": state,
        "conclusion": conclusion,
    }
    out.update(changes)
    return out


def read(rows):
    return lambda sha, token: {"total_count": len(rows), "workflow_runs": rows}


class VerifyExactSourceCI(unittest.TestCase):
    def setUp(self):
        self.rows = [run(i) for i in ci.REQUIRED]

    def test_authenticated_source_read_is_exact_https_with_redirects_blocked(self):
        payload = {"workflow_runs": self.rows, "total_count": len(self.rows)}
        seen = []
        class Response:
            status = 200
            def __init__(self, req, *, final=None, status=200):
                self.status = status
                self.final = req.full_url if final is None else final
                self.body = io.BytesIO(json.dumps(payload).encode("utf-8"))
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return self.final
            def read(self, amount=-1):
                return self.body.read(amount)

        class Opener:
            def open(self, req, timeout):
                seen.append((req, timeout))
                return Response(req)
        def new_opener(*handlers):
            self.assertEqual(len(handlers), 1)
            blocker = handlers[0]
            self.assertIsInstance(blocker, ci.RejectGithubRedirects)
            dummy = urllib.request.Request(
                "https://api.github.com", headers={"Authorization": "Bearer TOKEN"})
            for code in (301, 302, 303, 307, 308):
                self.assertIsNone(blocker.redirect_request(
                    dummy, None, code, "redirect",
                    {"Location": "https://malicious.invalid/collect"},
                    "https://malicious.invalid/collect"))
            return Opener()

        with patch.object(ci.urllib.request, "build_opener", side_effect=new_opener):
            self.assertEqual(ci.github_runs(SHA, TOKEN), payload)
        self.assertEqual(len(seen), 1)
        request, timeout = seen[0]
        self.assertEqual(timeout, 20)
        self.assertEqual(request.get_header("Authorization"), "Bearer " + TOKEN)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(
            request.full_url,
            "https://api.github.com/repos/" + ci.SOURCE +
            "/actions/runs?head_sha=" + SHA + "&event=push&per_page=100"
        )

    def test_redirect_or_foreign_success_is_not_accepted_as_source_evidence(self):
        body = json.dumps({"workflow_runs": self.rows, "total_count": 3}).encode()
        class Response:
            status = 200
            def __init__(self, req, final):
                self.final = final
                self.body = io.BytesIO(body)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def geturl(self):
                return self.final
            def read(self, amount=-1):
                return self.body.read(amount)

        for target in ("https://github.com/login",
                       "https://attacker.invalid/not-the-api",
                       "https://api.github.com/repos/another/repository/actions/runs"):
            with self.subTest(target=target):
                class Opener:
                    def open(self, req, timeout):
                        return Response(req, target)
                with patch.object(ci.urllib.request, "build_opener",
                                  return_value=Opener()):
                    with self.assertRaisesRegex(ci.AdmissionError, "response URL"):
                        ci.github_runs(SHA, TOKEN)

        class RedirectOpener:
            def open(self, req, timeout):
                raise urllib.error.HTTPError(
                    req.full_url, 302, "Moved", {"Location": "https://evil.invalid/"}, None)
        with patch.object(ci.urllib.request, "build_opener",
                          return_value=RedirectOpener()):
            with self.assertRaisesRegex(ci.AdmissionError, "HTTP 302"):
                ci.github_runs(SHA, TOKEN)

    def test_source_ci_reader_rejects_missing_token_or_invalid_sha_before_http(self):
        with patch.object(ci.urllib.request, "build_opener") as opener:
            for sha, token in (("main", TOKEN), (SHA, ""), ("B" * 40, TOKEN)):
                with self.subTest(sha=sha, token=bool(token)):
                    with self.assertRaises(ci.AdmissionError):
                        ci.github_runs(sha, token)
            opener.assert_not_called()

    def test_three_successful_source_main_push_workflows_admit(self):
        self.assertEqual(ci.inspect(SHA, TOKEN, read(self.rows)), "ready")

    def test_missing_or_in_progress_workflow_is_pending(self):
        self.assertEqual(ci.inspect(SHA, TOKEN, read(self.rows[:-1])), "pending")
        rows = list(self.rows)
        rows[1] = run(400786032, state="in_progress", conclusion=None)
        self.assertEqual(ci.inspect(SHA, TOKEN, read(rows)), "pending")

    def test_failure_or_cancellation_blocks_release(self):
        for failure in ("failure", "cancelled", "timed_out", "skipped"):
            with self.subTest(failure=failure):
                rows = list(self.rows)
                rows[0] = run(400311458, conclusion=failure)
                self.assertEqual(ci.inspect(SHA, TOKEN, read(rows)), "blocked")

    def test_source_identity_spoof_and_fork_fail_closed(self):
        for change in (
            {"head_sha": "b" * 40}, {"event": "pull_request"},
            {"head_branch": "develop"}, {"path": ".github/workflows/other.yml"},
            {"repository": {"full_name": "attacker/repo"}}, {"name": "Fake CI"},
        ):
            with self.subTest(change=change):
                rows = list(self.rows)
                rows[1] = run(400786032, **change)
                with self.assertRaises(ci.AdmissionError):
                    ci.inspect(SHA, TOKEN, read(rows))

    def test_newer_failed_run_cannot_be_masked_by_older_success(self):
        rows = list(self.rows) + [run(400786032, id=999999999, conclusion="failure")]
        self.assertEqual(ci.inspect(SHA, TOKEN, read(rows)), "blocked")

    def test_bad_sha_or_token_and_truncated_response_rejected(self):
        with self.assertRaises(ci.AdmissionError):
            ci.inspect("main", TOKEN, read(self.rows))
        with self.assertRaises(ci.AdmissionError):
            ci.inspect(SHA, "", read(self.rows))
        with self.assertRaises(ci.AdmissionError):
            ci.inspect(SHA, TOKEN, lambda sha, token: {"total_count": 101, "workflow_runs": self.rows})


if __name__ == "__main__":
    unittest.main()
