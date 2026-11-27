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
            {"path": "evil.yml"},
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

    def test_unrelated_infra_main_advance_accepts_exact_protected_blobs(self):
        pinned = "c" * 40
        data = {
            "truncated": False,
            "tree": [
                {"path": ".github/workflows/staradvs-pages-staging.yml",
                 "type": "blob", "sha": "1" * 40},
                {"path": ".github/workflows/staradvs-protected-publish.yml",
                 "type": "blob", "sha": "2" * 40},
                {"path": "edge/staradvs-identity-gate.mjs",
                 "type": "blob", "sha": "3" * 40},
            ],
        }
        class TreeReader(GitHubFake):
            def get(self, url):
                if "/git/trees/" in url:
                    self.calls.append(url)
                    return copy.deepcopy(data)
                return super().get(url)
        fake = TreeReader(r={**run(), "head_sha": pinned},
                          a={**artifact(), "workflow_run": {
                              "id": int(RUN), "head_sha": pinned,
                          }})
        with patch.object(p.source, "admit", return_value=456):
            result = p.admit_candidate(
                fake, RUN, GAME, INFRA, game_reader=object())
        self.assertEqual(result, p.NAME + GAME)
        self.assertEqual(len([url for url in fake.calls if "/git/trees/" in url]), 2)
        # The existing strict blob comparison, not a user-controlled flag,
        # authorizes the unrelated-main advance.

    def test_changed_staging_blob_or_truncated_git_tree_blocks(self):
        pinned = "c" * 40
        before = {
            "truncated": False,
            "tree": [
                {"path": ".github/workflows/staradvs-pages-staging.yml",
                 "type": "blob", "sha": "1" * 40},
                {"path": "edge/staradvs-identity-gate.mjs",
                 "type": "blob", "sha": "2" * 40},
            ],
        }
        class TreeReader(GitHubFake):
            def __init__(self, current):
                super().__init__(
                    r={**run(), "head_sha": pinned},
                    a={**artifact(), "workflow_run": {
                        "id": int(RUN), "head_sha": pinned,
                    }},
                )
                self.current = current
            def get(self, url):
                if "/git/trees/" in url:
                    self.calls.append(url)
                    return copy.deepcopy(before if pinned in url else self.current)
                return super().get(url)
        changed = copy.deepcopy(before)
        changed["tree"][1]["sha"] = "4" * 40
        cases = [changed, {"truncated": True, "tree": before["tree"]},
                 {"truncated": False, "tree": []}, {"error": "not-a-tree"}]
        with patch.object(p.source, "admit", return_value=456):
            for candidate in cases:
                with self.subTest(tree=candidate):
                    fake = TreeReader(candidate)
                    with self.assertRaises(p.ReleaseBlocked):
                        p.admit_candidate(
                            fake, RUN, GAME, INFRA, game_reader=object())
                    # Artifact download is impossible unless both trees pass.
                    self.assertNotIn(
                        f"/repos/{p.INFRA_REPO}/actions/runs/{RUN}/artifacts?per_page=100",
                        fake.calls,
                    )

    def test_immutable_run_workflow_sha_mismatch_still_rejects(self):
        pinned = "c" * 40
        fake = GitHubFake(
            r={**run(), "head_sha": pinned},
            a={**artifact(), "workflow_run": {
                "id": int(RUN), "head_sha": INFRA,
            }},
        )
        with (patch.object(p.source, "admit", return_value=456),
              patch.object(p.revision, "compare", return_value=(True, []))):
            with self.assertRaises(p.ReleaseBlocked):
                p.admit_candidate(fake, RUN, GAME, INFRA, game_reader=object())

    def test_api_reader_allows_only_run_metadata_and_exact_tree_endpoints(self):
        with patch.object(p.urllib.request, "urlopen",
                          side_effect=AssertionError("Network must not be called")):
            reader = p.GitHub("fake-test-token")
            for path in (
                "/repos/evil/repo/git/trees/" + INFRA + "?recursive=1",
                f"/repos/{p.INFRA_REPO}/git/trees/main?recursive=1",
                f"/repos/{p.INFRA_REPO}/git/trees/{INFRA}?recursive=0",
                f"/repos/{p.INFRA_REPO}/actions/runs/123/delete",
            ):
                with self.subTest(path=path), self.assertRaises(p.ReleaseBlocked):
                    reader.get(path)

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

    def test_live_identity_and_fail_closed_pages_required_without_access(self):
        class Client:
            account = "a" * 32
        client = Client()
        old = "00000000-0000-4000-8000-000000000001"
        rows = {old: {"host": "old.staradvs-staging.pages.dev", "aliases": []}}
        project = {"canonical_deployment": {"id": old}}
        with (patch.object(p, "owned_project", return_value=project),
              patch.object(p, "inventory", return_value=rows),
              patch.object(p.readiness, "read_public", return_value=(
                  200, b"https://staging.staradvs.shadowops.dpdns.org/?shadowops=central")) as probe):
            self.assertEqual(p.verify_posture(client), rows)
            probe.return_value = (401, b"")
            with self.assertRaises(p.ReleaseBlocked):
                p.verify_posture(client)

    def test_retirement_never_deletes_new_or_uninventoried_deployment(self):
        from unittest.mock import Mock
        old = "00000000-0000-4000-8000-000000000001"
        new = "00000000-0000-4000-8000-000000000002"
        foreign = "00000000-0000-4000-8000-000000000003"
        snapshot = {old: {"host": "old.staradvs-staging.pages.dev", "aliases": []}}
        current = {"host": "new.staradvs-staging.pages.dev", "aliases": []}
        client = Mock(account="a" * 32)
        client.request.return_value = (200, None)
        with (patch.object(p, "active_deployment", return_value=(new, current["host"])),
              patch.object(p, "require_denial") as denial,
              patch.object(p, "inventory", return_value={**snapshot, new: current}) as inv):
            self.assertEqual(p.retire_legacy(client, GAME, snapshot), 1)
            denial.assert_called_once()
            client.request.assert_called_once_with("DELETE",
                f"/accounts/{client.account}/pages/projects/staradvs-staging/deployments/{old}?force=true")
            client.request.reset_mock()
            inv.return_value = {**snapshot, new: current, foreign: current}
            with self.assertRaises(p.ReleaseBlocked):
                p.retire_legacy(client, GAME, snapshot)
            client.request.assert_not_called()
            inv.return_value = {**snapshot, new: current}
            denial.side_effect = p.ReleaseBlocked("guest")
            with self.assertRaises(p.ReleaseBlocked):
                p.retire_legacy(client, GAME, snapshot)
            client.request.assert_not_called()
            inv.return_value = {**snapshot, new: current}
            denial.side_effect = p.ReleaseBlocked("guest")
            with self.assertRaises(p.ReleaseBlocked):
                p.retire_legacy(client, GAME, snapshot)
            client.request.assert_not_called()

    def test_retirement_preserves_aliases_when_pages_moves_them(self):
        from unittest.mock import Mock
        old = "00000000-0000-4000-8000-000000000001"
        new = "00000000-0000-4000-8000-000000000002"
        old_alias = "previous.staradvs-staging.pages.dev"
        moved_alias = "main.staradvs-staging.pages.dev"
        snapshot = {old: {"host": "old.staradvs-staging.pages.dev", "aliases": [old_alias]}}
        current = {"host": "new.staradvs-staging.pages.dev", "aliases": [moved_alias]}
        changed_old = {"host": snapshot[old]["host"], "aliases": []}
        client = Mock(account="a" * 32)
        client.request.return_value = (200, None)
        with (patch.object(p, "active_deployment", return_value=(new, current["host"])),
              patch.object(p, "require_denial") as denial,
              patch.object(p, "inventory", return_value={old: changed_old, new: current})):
            self.assertEqual(p.retire_legacy(client, GAME, snapshot), 1)
            self.assertEqual(snapshot[old]["aliases"], [old_alias])
            denial.assert_called_once()
            client.request.assert_called_once_with("DELETE",
                f"/accounts/{client.account}/pages/projects/staradvs-staging/deployments/{old}?force=true")

        snapshot = {old: {"host": "old.staradvs-staging.pages.dev", "aliases": [old_alias]}}
        changed_old = {"host": snapshot[old]["host"], "aliases": [moved_alias]}
        client.request.reset_mock()
        with (patch.object(p, "active_deployment", return_value=(new, current["host"])),
              patch.object(p, "require_denial"),
              patch.object(p, "inventory", return_value={old: changed_old, new: current})):
            self.assertEqual(p.retire_legacy(client, GAME, snapshot), 1)
            self.assertEqual(snapshot[old]["aliases"], sorted([old_alias, moved_alias]))

    def test_postflight_checks_retired_hosts_and_rejects_remaining_history(self):
        old = "00000000-0000-4000-8000-000000000001"
        new = "00000000-0000-4000-8000-000000000002"
        snapshot = {old: {"host": "old.staradvs-staging.pages.dev", "aliases": []}}
        current = {"host": "new.staradvs-staging.pages.dev", "aliases": []}
        with (patch.object(p, "active_deployment", return_value=(new, current["host"])),
              patch.object(p, "inventory", return_value={new: current}) as inv,
              patch.object(p, "require_denial") as denial):
            result = p.verify_postflight(object(), GAME, snapshot)
            self.assertFalse(result["can_activate"])
            denial.assert_called_once_with(current["host"], {"old.staradvs-staging.pages.dev"})
            inv.return_value = {**snapshot, new: current}
            with self.assertRaises(p.ReleaseBlocked):
                p.verify_postflight(object(), GAME, snapshot)

    def test_guest_denial_includes_all_routes_and_methods(self):
        calls = []
        def probe(url, method):
            calls.append((url, method))
            return (401 if url.startswith("https://" + p.pages.HOST + "/") else 404, b"")
        p.require_denial("new.staradvs-staging.pages.dev", ["old.staradvs-staging.pages.dev"], probe)
        self.assertEqual(len(calls), 32)
        with self.assertRaises(p.ReleaseBlocked):
            p.require_denial("new.staradvs-staging.pages.dev", [], lambda *_: (200, b""))

    def test_manual_only_release_without_public_publisher_or_secrets_in_game_build(self):
        flow = (ROOT / ".github/workflows/staradvs-protected-publish.yml").read_text()
        for term in (
            "workflow_dispatch:", "inputs.operation == 'publish'",
            "STARADVS_PUBLISH_AND_RETIRE_OLD_DEPLOYMENTS",
            "github.ref == 'refs/heads/main'", "environment: staging",
            "shadowops-staradvs-staging-pages",
            "scripts/staradvs_protected_publish.py preflight",
            "scripts/staradvs_protected_publish.py postflight",
            "scripts/staradvs_protected_bundle.py verify",
            "actions/download-artifact@v4",
            '"$RUNNER_TEMP/staradvs-wrangler/node_modules/.bin/wrangler" pages deploy protected-dist',
            "github-token: DOLLAR{{ github.token }}",
            "github.repository == 'evilsysadmin/shadowops-infra'",
        ):
            self.assertIn(term.replace("DOLLAR", "$"), flow, term)
        for banned in (
            "contents: write", "CLOUDFLARE_ACCESS_WRITE_TOKEN", "CLOUDFLARE_ACCESS_READ_TOKEN",
            "scripts/staradvs_pages.py verify",
            "staradvs_pages.py domain",
            "SHADOWOPS_STARADVS_SERVICE_CREDENTIAL: DOLLAR{{ secrets.",
            "STARADVS_STAGING_PUBLIC_READY", "npm ci", "npm run build",
        ):
            self.assertNotIn(banned.replace("DOLLAR", "$"), flow)
        self.assertIn("pending-identity", flow)
        self.assertEqual(flow.count('scripts/staradvs_infra_revision.py "$GITHUB_SHA"'), 3)
        self.assertLess(flow.index("preflight --inventory-file"), flow.index("pages deploy protected-dist"))
        self.assertLess(flow.index("pages deploy protected-dist"), flow.index("retire --game-sha"))
        self.assertLess(flow.index("retire --game-sha"), flow.index("postflight --game-sha"))
        # A publish request without the exact confirmation must fail the
        # whole workflow at admission, not silently skip the publish job.
        admission = flow.split("\n  admit:\n", 1)[1].split("\n  preflight:\n", 1)[0]
        self.assertIn('REQUESTED_OPERATION: DOLLAR{{ inputs.operation }}'.replace("DOLLAR", "$"), admission)
        self.assertIn('PUBLISH_CONFIRM: DOLLAR{{ inputs.confirm }}'.replace("DOLLAR", "$"), admission)
        self.assertIn('if [[ "$PUBLISH_CONFIRM" != "STARADVS_PUBLISH_AND_RETIRE_OLD_DEPLOYMENTS" ]]', admission)
        self.assertIn('exit 64', admission)
        self.assertIn('if [[ -n "$PUBLISH_CONFIRM" ]]', admission)
        publish = flow.split("\n  publish:\n", 1)[1]
        self.assertIn("needs: [contracts, admit, preflight]", publish)
        self.assertIn("inputs.confirm == 'STARADVS_PUBLISH_AND_RETIRE_OLD_DEPLOYMENTS'", publish)
        install = publish.split(
            "- name: Install exact reviewed Wrangler version WITHOUT Cloudflare or GitHub tokens", 1
        )[1].split("- name: Publish exact Infra-owned advanced-mode Worker", 1)[0]
        self.assertIn('npm install --prefix "$RUNNER_TEMP/staradvs-wrangler"', install)
        self.assertIn("wrangler@4.127.1", install)
        self.assertNotIn("CLOUDFLARE_API_TOKEN", install)
        self.assertNotIn("CLOUDFLARE_ACCOUNT_ID", install)
        self.assertNotIn("GH_TOKEN", install)
        deploy = publish.split("- name: Publish exact Infra-owned advanced-mode Worker", 1)[1]
        deploy_step = deploy.split("- name: Fail closed unless old deployments are retired", 1)[0]
        self.assertNotIn("npx ", deploy_step)
        self.assertNotIn("npm ", deploy_step)
        self.assertLess(publish.index("scripts/staradvs_protected_bundle.py verify"),
                        publish.index('"$RUNNER_TEMP/staradvs-wrangler/node_modules/.bin/wrangler" pages deploy'))
        self.assertLess(publish.index("scripts/staradvs_protected_publish.py preflight"),
                        publish.index('"$RUNNER_TEMP/staradvs-wrangler/node_modules/.bin/wrangler" pages deploy'))
        self.assertGreater(publish.index("scripts/staradvs_protected_publish.py postflight"),
                           publish.index('"$RUNNER_TEMP/staradvs-wrangler/node_modules/.bin/wrangler" pages deploy'))


if __name__ == "__main__":
    unittest.main()
