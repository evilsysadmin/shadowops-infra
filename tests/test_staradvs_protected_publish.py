"""Only the exact green current-run Worker package is publishable."""
from __future__ import annotations
import copy
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_protected_publish as p

INFRA = "a" * 40
GAME = "b" * 40
RUN = "45144750770"


def run():
    return {"id": int(RUN), "status": "completed", "conclusion": "success",
            "event": "push", "head_branch": "main", "head_sha": INFRA,
            "path": p.WORKFLOW, "repository": {"full_name": p.INFRA_REPO}}


def artifact():
    return {"name": p.NAME + GAME, "expired": False, "id": 555,
            "size_in_bytes": 567352,
            "workflow_run": {"id": int(RUN), "head_sha": INFRA}}


class GitHubFake:
    def __init__(self, r=None, a=None):
        self.run = run() if r is None else r
        self.artifact = artifact() if a is None else a
        self.calls = []

    def get(self, url):
        self.calls.append(url)
        if url.endswith("/artifacts?per_page=100"):
            return {"total_count": 1, "artifacts": [copy.deepcopy(self.artifact)]}
        return copy.deepcopy(self.run)


class Tests(unittest.TestCase):
    def test_exact_green_main_and_unique_immutable_artifact(self):
        fake = GitHubFake()
        with patch.object(p.source, "admit", return_value=456) as verify:
            self.assertEqual(p.admit_candidate(
                fake, RUN, GAME, INFRA, game_reader=object()), p.NAME + GAME)
            verify.assert_called_once()
        self.assertEqual(fake.calls, [
            f"/repos/{p.INFRA_REPO}/actions/runs/{RUN}",
            f"/repos/{p.INFRA_REPO}/actions/runs/{RUN}/artifacts?per_page=100",
        ])

    def test_untrusted_candidate_metadata_and_user_input_fail_closed(self):
        changes = (
            {"status": "in_progress"}, {"conclusion": "failure"},
            {"event": "pull_request"}, {"head_branch": "feature"},
            {"head_sha": "c" * 40}, {"path": "evil.yml"},
            {"repository": {"full_name": "evil/foreign"}},
            {"id": int(RUN) + 1},
        )
        for change in changes:
            fake = GitHubFake(r={**run(), **change})
            with self.subTest(change=change), patch.object(p.source, "admit", return_value=456):
                with self.assertRaises(p.ReleaseBlocked):
                    p.admit_candidate(fake, RUN, GAME, INFRA, game_reader=object())
                self.assertEqual(len(fake.calls), 1)
        for bad in ("", "0", "1;echo danger", "-4", "1/../../secret",
                    "9" * 30, "1\nX: yes"):
            with self.subTest(run_id=bad), self.assertRaises(p.ReleaseBlocked):
                p.admit_candidate(GitHubFake(), bad, GAME, INFRA,
                                  game_reader=object())

    def test_expired_foreign_or_duplicated_artifact_blocks(self):
        variants = (
            {"name": p.NAME + "c" * 40},
            {"expired": True}, {"size_in_bytes": 0},
            {"size_in_bytes": 999_999_999},
            {"workflow_run": {"id": int(RUN) + 5, "head_sha": INFRA}},
            {"workflow_run": {"id": int(RUN), "head_sha": "c" * 40}},
        )
        with patch.object(p.source, "admit", return_value=456):
            for change in variants:
                with self.subTest(change=change):
                    fake = GitHubFake(a={**artifact(), **change})
                    with self.assertRaises(p.ReleaseBlocked):
                        p.admit_candidate(fake, RUN, GAME, INFRA, game_reader=object())
            fake = GitHubFake()
            original = fake.get
            def dup(url):
                if url.endswith("/artifacts?per_page=100"):
                    return {"total_count": 2, "artifacts": [artifact(), artifact()]}
                return original(url)
            fake.get = dup
            with self.assertRaises(p.ReleaseBlocked):
                p.admit_candidate(fake, RUN, GAME, INFRA, game_reader=object())

    def test_live_cloudflare_identity_custody_required_without_activation(self):
        report = {
            "pages_project": "owned", "identity_login": "audience-recognized",
            "pages_private_policy": "configured", "pages_app_proof": "bound",
            "cloudflare_access": "restricted-policy-candidate",
            "cloudflare_access_scopes": {
                key: "restricted-policy-candidate" for key in p.readiness.ACCESS_SCOPES
            },
            "historical_enumeration_status": "reported-total-observed",
            "historical_aliases_exposed": 0,
            "historical_deployments_reported_total": 114,
        }
        evidence = {"historical": {"hosts": 114, "challenged": 114, "denied": 0},
                    "can_activate": False}
        class Client:
            account = "a" * 32
        client = Client()
        with (patch.object(p.bundle, "policy_status", return_value="pending-identity"),
              patch.object(p.readiness, "collect", return_value=report) as audit,
              patch.object(p.challenge, "collect", return_value=evidence) as second,
              patch.object(p.quarantine, "judge_guest_quarantine",
                           return_value="access-login-challenge-candidate")):
            valid = p.verify_posture(client, client)
            self.assertEqual(valid["aliases_checked"], 114)
            self.assertFalse(valid["can_activate"])
            self.assertEqual(valid["signed_in_e2e"], "not-performed")
            second.assert_called_once()
            for change in (
                {"pages_project": "foreign"},
                {"identity_login": "unavailable-or-not-provisioned"},
                {"pages_private_policy": "not-configured"},
                {"pages_app_proof": "not-bound"},
                {"cloudflare_access": "remediation-required"},
                {"historical_enumeration_status": "partial-or-unverified"},
                {"historical_aliases_exposed": 1},
                {"cloudflare_access_scopes": {"main": "restricted-policy-candidate"}},
            ):
                audit.return_value = dict(report, **change)
                with self.subTest(change=change), self.assertRaises(p.ReleaseBlocked):
                    p.verify_posture(client, client)
            audit.return_value = report
            with patch.object(p.quarantine, "judge_guest_quarantine",
                              return_value="guest-denial-unverified"):
                with self.assertRaises(p.ReleaseBlocked):
                    p.verify_posture(client, client)
        class Foreign:
            account = "b" * 32
        with self.assertRaises(p.ReleaseBlocked):
            p.verify_posture(client, Foreign())

    def test_manual_only_release_without_public_publisher_or_secrets_in_game_build(self):
        flow = (ROOT / ".github/workflows/staradvs-protected-publish.yml").read_text()
        for term in (
            "workflow_dispatch:", "inputs.operation == 'publish'",
            "STARADVS_PUBLISH_PROTECTED_WORKER",
            "github.ref == 'refs/heads/main'", "environment: staging",
            "shadowops-staradvs-staging-pages",
            "scripts/staradvs_protected_publish.py preflight",
            "scripts/staradvs_protected_publish.py postflight",
            "scripts/staradvs_protected_bundle.py verify",
            "actions/download-artifact@v4",
            "npx --yes wrangler@4.127.1 pages deploy protected-dist",
            "github-token: DOLLAR{{ github.token }}",
            "github.repository == 'evilsysadmin/shadowops-infra'",
        ):
            self.assertIn(term.replace("DOLLAR", "$"), flow, term)
        for banned in (
            "contents: write", "CLOUDFLARE_ACCESS_WRITE_TOKEN",
            "scripts/staradvs_pages.py verify",
            "staradvs_pages.py domain",
            "SHADOWOPS_STARADVS_SERVICE_CREDENTIAL: DOLLAR{{ secrets.",
            "STARADVS_STAGING_PUBLIC_READY", "npm ci", "npm run build",
        ):
            self.assertNotIn(banned.replace("DOLLAR", "$"), flow)
        self.assertIn("pending-identity", flow)
        publish = flow.split("\n  publish:\n", 1)[1]
        self.assertIn("needs: [contracts, admit, preflight]", publish)
        self.assertIn("inputs.confirm == 'STARADVS_PUBLISH_PROTECTED_WORKER'", publish)
        self.assertLess(publish.index("scripts/staradvs_protected_bundle.py verify"),
                        publish.index("npx --yes wrangler@"))
        self.assertLess(publish.index("scripts/staradvs_protected_publish.py preflight"),
                        publish.index("npx --yes wrangler@"))
        self.assertGreater(publish.index("scripts/staradvs_protected_publish.py postflight"),
                           publish.index("npx --yes wrangler@"))


if __name__ == "__main__":
    unittest.main()
