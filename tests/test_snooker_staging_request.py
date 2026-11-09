import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_staging_request as req

HEAD = "a" * 40


def context(**changes):
    data = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": req.REPO,
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": HEAD,
        "GITHUB_WORKFLOW_REF": (
            req.REPO + "/.github/workflows/" + req.WORKFLOW + "@refs/heads/main"
        ),
    }
    data.update(changes)
    return data


class OneTimeRequestTests(unittest.TestCase):
    def test_exact_additive_request_under_protected_main_is_accepted(self):
        req.verify(json.dumps(req.EXPECTED), {req.REQUEST: "A"},
                   req.BASE, HEAD, context())

    def test_changes_or_reused_request_are_rejected(self):
        for state in ("M", "D", "", "R100"):
            with self.subTest(state=state), self.assertRaises(req.RequestDenied):
                req.verify(json.dumps(req.EXPECTED), {req.REQUEST: state},
                           req.BASE, HEAD, context())
        with self.assertRaises(req.RequestDenied):
            req.verify(json.dumps(req.EXPECTED), {req.REQUEST: "A",
                                                 "edge/snooker-identity-gate.mjs": "M"},
                       req.BASE, HEAD, context())

    def test_cannot_fake_intent_or_change_base(self):
        for field, value in (("application", "football"),
                             ("environment", "production"),
                             ("base_main_sha", HEAD),
                             ("single_use", False),
                             ("issue", 528)):
            with self.subTest(field=field), self.assertRaises(req.RequestDenied):
                req.verify(json.dumps({**req.EXPECTED, field: value}),
                           {req.REQUEST: "A"}, req.BASE, HEAD, context())
        with self.assertRaises(req.RequestDenied):
            req.verify(json.dumps(req.EXPECTED), {req.REQUEST: "A"},
                       "b" * 40, HEAD, context())

    def test_only_exact_push_workflow_repo_and_main(self):
        for key, wrong in [
            ("GITHUB_ACTIONS", "false"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REPOSITORY", "evil/repo"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_SHA", "b" * 40),
            ("GITHUB_WORKFLOW_REF", "other/workflow@refs/heads/main"),
        ]:
            with self.subTest(key=key), self.assertRaises(req.RequestDenied):
                req.verify(json.dumps(req.EXPECTED), {req.REQUEST: "A"},
                           req.BASE, HEAD, context(**{key: wrong}))

    def test_contract_doc_matches_checked_in_request(self):
        request = Path(__file__).resolve().parents[1] / req.REQUEST
        self.assertEqual(json.loads(request.read_text(encoding="utf-8")),
                         req.EXPECTED)


if __name__ == "__main__":
    unittest.main()
