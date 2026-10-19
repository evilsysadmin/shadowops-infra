"""GitHub-only fake admission tests: no real providers and no mutation."""
import base64
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import pages_owner_admission as a

OWNER_SHA = "a" * 40
SOURCE_SHA = "b" * 40
ENV = {
    "GITHUB_REPOSITORY": a.OWNER,
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_SHA": OWNER_SHA,
    "CHRONICLES_SOURCE_SHA": SOURCE_SHA,
    "GH_TOKEN": "unit-test-token",
}


class Read:
    def __init__(self, *, owner_protected=True, source_protected=True,
                 old_workflow=False, stale=False, duplicate_publisher=False):
        self.calls = []
        self.owner_protected = owner_protected
        self.source_protected = source_protected
        self.old_workflow = old_workflow
        self.duplicate_publisher = duplicate_publisher
        self.stale = stale

    def __call__(self, path, token):
        self.calls.append(path)
        if token != "unit-test-token":
            raise AssertionError("Wrong token")
        if path.endswith("/branches/main"):
            is_owner = ("/" + a.OWNER + "/") in path
            return 200, {
                "protected": self.owner_protected if is_owner else self.source_protected,
                "commit": {"sha": ("c" * 40 if self.stale else OWNER_SHA) if is_owner else SOURCE_SHA},
            }
        if "/contents/" + a.OLD_PUBLISHER in path:
            return (200, {"path": a.OLD_PUBLISHER}) if self.old_workflow else (404, {"message": "Not Found"})
        if "/contents/" + a.SOURCE_FRONTEND_CI in path:
            source = "jobs:\n  build:\n"
            if self.duplicate_publisher:
                source += "  deploy-staging:\n    uses: cloudflare/wrangler-action@v3\n"
            return 200, {"encoding": "base64", "content": base64.b64encode(source.encode()).decode()}
        raise AssertionError("Unapproved request " + path)


class TestPagesHandoff(unittest.TestCase):
    def test_accepts_only_protected_current_main_and_retired_publisher(self):
        read = Read()
        self.assertEqual(a.admit(ENV, read), SOURCE_SHA)
        self.assertEqual(len(read.calls), 4)
        self.assertEqual(read.calls[-1].split("?")[0], f"/repos/{a.SOURCE}/contents/{a.SOURCE_FRONTEND_CI}")

    def test_allows_protected_main_push_from_owner_for_first_release(self):
        read = Read()
        self.assertEqual(a.admit({**ENV, "GITHUB_EVENT_NAME": "push"}, read), SOURCE_SHA)
        self.assertEqual(len(read.calls), 4)

    def test_protected_owner_schedule_is_an_admitted_trigger(self):
        read = Read()
        self.assertEqual(a.admit({**ENV, "GITHUB_EVENT_NAME": "schedule"}, read), SOURCE_SHA)
        self.assertEqual(len(read.calls), 4)

    def test_fail_closed_if_protection_is_disabled_or_previous_owner_remains(self):
        for case in (
            {"owner_protected": False}, {"source_protected": False},
            {"old_workflow": True}, {"duplicate_publisher": True}, {"stale": True},
        ):
            with self.subTest(case=case):
                with self.assertRaises(a.AdmissionError):
                    a.admit(ENV, Read(**case))

    def test_fail_closed_for_other_repo_event_or_sha(self):
        for change in (
            {"GITHUB_REPOSITORY": "evilsysadmin/chess-studio"},
            {"GITHUB_REF": "refs/heads/feature"},
            {"GITHUB_EVENT_NAME": "pull_request"},
            {"GITHUB_SHA": "main"},
            {"CHRONICLES_SOURCE_SHA": ""},
            {"GH_TOKEN": ""},
        ):
            with self.subTest(change=change):
                read = Read()
                with self.assertRaises(a.AdmissionError):
                    a.admit({**ENV, **change}, read)
                self.assertEqual(read.calls, [])

    def test_no_github_writes_or_credential_echo(self):
        source = pathlib.Path(a.__file__).read_text()
        for word in ('method="POST"', 'method="PUT"', 'method="PATCH"', 'method="DELETE"',
                     "print(token)", "print(env)", "subprocess.run(", "gh secret"):
            self.assertNotIn(word, source)


if __name__ == "__main__":
    unittest.main()


class TestProductionPromotion(unittest.TestCase):
    def reader(self, compare_status):
        def read(path, token):
            if path.endswith("/branches/main"):
                is_owner = ("/" + a.OWNER + "/") in path
                return 200, {"protected": True, "commit": {"sha": OWNER_SHA if is_owner else "d" * 40}}
            if "/compare/" in path:
                return (200, {"status": compare_status}) if compare_status else (404, {"message": "Not Found"})
            if "/contents/" + a.OLD_PUBLISHER in path:
                return 404, {"message": "Not Found"}
            if "/contents/" + a.SOURCE_FRONTEND_CI in path:
                return 200, {"encoding": "base64", "content": base64.b64encode(b"jobs:\n  build:\n").decode()}
            raise AssertionError("Unapproved request " + path)
        return read

    def test_promote_accepts_an_earlier_commit_of_protected_main(self):
        env = {**ENV, "CHRONICLES_RELEASE_MODE": "promote"}
        self.assertEqual(a.admit(env, self.reader("ahead")), SOURCE_SHA)

    def test_promote_rejects_branches_and_unknown_commits(self):
        env = {**ENV, "CHRONICLES_RELEASE_MODE": "promote"}
        for status in ("diverged", "behind", None):
            with self.subTest(status=status), self.assertRaises(a.AdmissionError):
                a.admit(env, self.reader(status))

    def test_without_promote_an_earlier_commit_is_stale(self):
        with self.assertRaises(a.AdmissionError):
            a.admit(ENV, self.reader("ahead"))
