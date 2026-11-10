import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_atlas_preflight_request as req

HEAD = "a" * 40
ENV = {
    "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
    "GITHUB_REPOSITORY": req.REPO,
    "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": HEAD,
    "GITHUB_WORKFLOW_REF": req.REPO + "/.github/workflows/" +
                           req.WORKFLOW + "@refs/heads/main",
}


class AtlasPreflightRequestTests(unittest.TestCase):
    def valid(self):
        req.verify(json.dumps(req.INTENT, indent=2) + "\n",
                   {req.REQUEST: "A",
                    ".github/workflows/" + req.WORKFLOW: "A",
                    "scripts/snooker_atlas_preflight_request.py": "A",
                    "tests/test_snooker_atlas_preflight_request.py": "A"},
                   [req.BASE], HEAD, ENV)

    def test_exact_first_addition_and_squash_are_accepted(self):
        self.valid()

    def test_tampering_replays_ambiguous_commit_or_wrong_ref_are_refused(self):
        raw = json.dumps(req.INTENT, indent=2) + "\n"
        changes = {req.REQUEST: "A"}
        for key, value in (("source_sha", "b" * 40),
                           ("action", "deploy"),
                           ("single_use", False),
                           ("published_image_run", 1),
                           ("base_main_sha", "c" * 40),
                           ("environment", "production")):
            with self.subTest(key=key):
                altered = copy.deepcopy(req.INTENT)
                altered[key] = value
                with self.assertRaises(req.RequestBlocked):
                    req.verify(json.dumps(altered, indent=2) + "\n",
                               changes, [req.BASE], HEAD, ENV)
        for changed in (
            {req.REQUEST: "M"},
            {req.REQUEST: "A", "host/identity-staging-deploy.py": "M"},
            {req.REQUEST: "A", "foo.txt": "A"},
        ):
            with self.subTest(changes=changed), self.assertRaises(req.RequestBlocked):
                req.verify(raw, changed, [req.BASE], HEAD, ENV)
        for parents in ([], [req.BASE, req.BASE], ["b" * 40]):
            with self.assertRaises(req.RequestBlocked):
                req.verify(raw, changes, parents, HEAD, ENV)
        for key in ("GITHUB_REF", "GITHUB_REPOSITORY",
                    "GITHUB_EVENT_NAME", "GITHUB_WORKFLOW_REF"):
            altered = dict(ENV, **{key: "unexpected"})
            with self.assertRaises(req.RequestBlocked):
                req.verify(raw, changes, [req.BASE], HEAD, altered)
        with self.assertRaises(req.RequestBlocked):
            req.verify(raw, changes, [req.BASE], "invalid-head", ENV)
        with self.assertRaises(req.RequestBlocked):
            req.verify(raw + "\n", changes, [req.BASE], HEAD, ENV)


if __name__ == "__main__":
    unittest.main()
