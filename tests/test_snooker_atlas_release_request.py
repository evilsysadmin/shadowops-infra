import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_atlas_release_request as req

HEAD = "a" * 40
ENV = {
    "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push",
    "GITHUB_REPOSITORY": req.REPO,
    "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": HEAD,
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_WORKFLOW_REF": req.REPO + "/.github/workflows/" +
                           req.WORKFLOW + "@refs/heads/main",
}


class AtlasReleaseRequestTests(unittest.TestCase):
    def valid(self):
        req.verify(json.dumps(req.INTENT, indent=2) + "\n",
                   {name: "A" for name in req.FILES}, [req.BASE], HEAD, ENV)

    def test_first_addition_squash_merge_is_accepted(self):
        self.valid()

    def test_replay_mutation_wrong_context_or_multiple_parent_is_blocked(self):
        raw = json.dumps(req.INTENT, indent=2) + "\n"
        changes = {name: "A" for name in req.FILES}
        for key, val in (("source_sha", "b" * 40),
                         ("action", "deploy"),
                         ("validated_digest", "sha256:" + "f" * 64),
                         ("successful_admin_run", 1),
                         ("successful_restore_run", 1),
                         ("published_image_run", 1),
                         ("single_use", False),
                         ("base_main_sha", "b" * 40),
                         ("environment", "production")):
            with self.subTest(key=key), self.assertRaises(req.RequestBlocked):
                changed = copy.deepcopy(req.INTENT)
                changed[key] = val
                req.verify(json.dumps(changed, indent=2) + "\n",
                           changes, [req.BASE], HEAD, ENV)
        for changed in (
            dict(changes, **{req.REQUEST: "M"}),
            {req.REQUEST: "A"},
            dict(changes, **{"host/identity-atlas-staging-deploy.py": "M"}),
        ):
            with self.assertRaises(req.RequestBlocked):
                req.verify(raw, changed, [req.BASE], HEAD, ENV)
        for parents in ([], [req.BASE, req.BASE], ["b" * 40]):
            with self.assertRaises(req.RequestBlocked):
                req.verify(raw, changes, parents, HEAD, ENV)
        for field in ENV:
            with self.subTest(field=field), self.assertRaises(req.RequestBlocked):
                env = dict(ENV, **{field: "wrong"})
                req.verify(raw, changes, [req.BASE], HEAD, env)
        with self.assertRaises(req.RequestBlocked):
            req.verify(raw, changes, [req.BASE], "invalid", ENV)
        with self.assertRaises(req.RequestBlocked):
            req.verify(raw + "\n", changes, [req.BASE], HEAD, ENV)


if __name__ == "__main__":
    unittest.main()
