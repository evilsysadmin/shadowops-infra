"""Contract tests: readable release notes must never act as deploy admission."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import chronicles_staging_changelog as notes

OLD = "a" * 40
NEW = "b" * 40
COMMIT = "c" * 40


def artifact(sha=OLD, *, run_id=11, expired=False, branch="main"):
    return {
        "name": f"chronicles-pages-staging-{sha}",
        "expired": expired,
        "workflow_run": {"id": run_id, "head_branch": branch},
    }


def run(run_id=11, **changes):
    data = {
        "id": run_id, "status": "completed", "conclusion": "success",
        "path": notes.PAGES_WORKFLOW, "head_branch": "main",
        "repository": {"full_name": notes.INFRA}, "event": "workflow_dispatch",
    }
    data.update(changes)
    return data


def sample_pr(number=17, **changes):
    data = {
        "number": number, "title": "Repair inventory | docs",
        "merged_at": "2026-10-31T07:00:00Z",
        "base": {"repo": {"full_name": notes.SOURCE}},
    }
    data.update(changes)
    return data


class ChroniclesReleaseChangelog(unittest.TestCase):
    def test_trust_requires_completed_source_owner_run(self):
        a = artifact()
        self.assertTrue(notes.trusted_receipt(a, run()))
        for bad in (
            run(conclusion="failure"), run(status="queued"),
            run(path="wrong.yml"), run(head_branch="feature"),
            run(repository={"full_name": "other/repo"}),
            run(event="pull_request"), run(id=12),
        ):
            with self.subTest(bad=bad):
                self.assertFalse(notes.trusted_receipt(a, bad))
        for bad in (artifact(expired=True), artifact(branch="topic"),
                    artifact(run_id=0), artifact(run_id=True)):
            self.assertFalse(notes.trusted_receipt(bad, run()))

    def test_last_receipt_filters_noise_and_uses_newest_trusted(self):
        entries = [{"name": "other", "expired": False},
                   artifact("d" * 40, run_id=22), artifact(OLD)]
        paths = []
        def get(path):
            paths.append(path)
            if "artifacts?" in path:
                return {"artifacts": entries}
            return run(22, conclusion="failure") if path.endswith("/22") else run()
        self.assertEqual(notes.last_verified_sha(NEW, get), OLD)
        self.assertEqual(sum("artifacts?" in p for p in paths), 1)
        self.assertEqual(len(paths), 3)

    def test_without_receipt_no_baseline_and_no_made_up_changes(self):
        data = notes.changes_for(NEW, lambda _: {"artifacts": []})
        self.assertEqual(data["status"], "no_baseline")
        self.assertIsNone(data["previous_sha"])
        self.assertFalse(data["pull_requests"])
        self.assertIn("Sin baseline", notes.render_summary(data))

    def test_existing_verified_sha_not_reported_as_new(self):
        def get(path):
            if "artifacts?" in path:
                return {"artifacts": [artifact(NEW)]}
            return run()
        data = notes.changes_for(NEW, get)
        self.assertEqual(data["status"], "already_verified")
        self.assertEqual(data["total_commits"], 0)
        self.assertNotIn("Comparar versiones", notes.render_summary(data))

    def test_compare_links_merged_prs_once_and_preserves_commit_trace(self):
        def get(path):
            if "artifacts?" in path:
                return {"artifacts": [artifact()]}
            if path.endswith("/11"):
                return run()
            if "/compare/" in path:
                return {
                    "status": "ahead", "total_commits": 2,
                    "commits": [
                        {"sha": COMMIT, "commit": {"message": "UI fixes\n\nbody"}},
                        {"sha": "d" * 40, "commit": {"message": "Docs"}},
                    ],
                }
            if "/commits/" in path:
                return {"_items": [
                    sample_pr(), sample_pr(),
                    sample_pr(number=30, merged_at=None),
                    sample_pr(number=31, base={"repo": {"full_name": "other/repo"}}),
                ]}
            raise AssertionError(path)
        data = notes.changes_for(NEW, get)
        self.assertEqual(data["status"], "changes")
        self.assertEqual(data["previous_sha"], OLD)
        self.assertEqual(data["total_commits"], 2)
        self.assertEqual([p["number"] for p in data["pull_requests"]], [17])
        self.assertEqual(data["commits"][0]["message"], "UI fixes")
        summary = notes.render_summary(data)
        self.assertIn("/compare/" + OLD + "..." + NEW, summary)
        self.assertIn("Repair inventory", summary)

    def test_non_linear_compare_does_not_make_up_prs(self):
        def get(path):
            if "artifacts?" in path:
                return {"artifacts": [artifact()]}
            if path.endswith("/11"):
                return run()
            return {"status": "diverged"}
        data = notes.changes_for(NEW, get)
        self.assertEqual(data["status"], "non_linear")
        self.assertEqual(data["pull_requests"], [])

    def test_missing_associations_are_marked_partial(self):
        def get(path):
            if "artifacts?" in path:
                return {"artifacts": [artifact()]}
            if path.endswith("/11"):
                return run()
            if "/compare/" in path:
                return {"status": "ahead", "total_commits": 1,
                        "commits": [{"sha": COMMIT, "commit": {"message": "Commit"}}]}
            raise notes.ChangelogError("API read unavailable")
        data = notes.changes_for(NEW, get)
        self.assertEqual(data["status"], "partial")
        self.assertTrue(data["truncated"])
        self.assertEqual(len(data["commits"]), 1)

    def test_malformed_artifact_listing_is_not_considered_empty(self):
        with self.assertRaises(notes.ChangelogError):
            notes.last_verified_sha(NEW, lambda _: {})
        with self.assertRaises(ValueError):
            notes.changes_for("invalid", lambda _: {})

    def test_cli_writes_nonblocking_unavailable_report_for_final_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            try:
                os.chdir(tmp)
                with patch.object(sys, "argv", ["notes", NEW]), \
                     patch.dict(os.environ, {"GH_TOKEN": "not-secret",
                                             "GITHUB_STEP_SUMMARY": str(Path(tmp) / "summary.md")}), \
                     patch.object(notes, "github_get", side_effect=notes.ChangelogError("offline")):
                    self.assertEqual(notes.main(), 0)
                data = __import__("json").loads(Path("verified-pages/changes.json").read_text())
                self.assertEqual(data["status"], "unavailable")
                self.assertFalse((Path(tmp) / "summary.md").exists())
                self.assertIn("Changelog no disponible",
                              Path("verified-pages/RELEASE_NOTES.md").read_text())
                self.assertTrue(Path("verified-pages/RELEASE_NOTES.md").is_file())
                page = Path("verified-pages/release-notes.html").read_text()
                self.assertIn("<!doctype html>", page)
                self.assertIn("Staging · Release notes", page)
                self.assertIn("Detalle de cambios no disponible", page)
            finally:
                os.chdir(cwd)

    def test_human_report_has_summary_table_and_collapsible_commits(self):
        data = {
            "source_sha": NEW, "previous_sha": OLD, "status": "changes",
            "total_commits": 1, "pull_requests": [{
                "number": 55, "title": "Fix <b>inventory</b> | resize",
                "url": f"https://github.com/{notes.SOURCE}/pull/55",
            }],
            "commits": [{"sha": COMMIT, "message": "Repair inventory"}],
            "compare_url": f"https://github.com/{notes.SOURCE}/compare/{OLD}...{NEW}",
            "truncated": False,
        }
        md = notes.render_summary(data)
        self.assertIn("# 🚀 Chronicles · staging", md)
        self.assertIn("| PR | Cambio |", md)
        self.assertIn("&#124;", md)
        self.assertIn("&lt;b&gt;", md)
        self.assertIn("<details><summary>Ver commits incluidos</summary>", md)
        html = notes.render_html(data)
        self.assertIn("<!doctype html>", html)
        self.assertIn("Fix &lt;b&gt;inventory&lt;/b&gt; | resize", html)
        self.assertNotIn("<b>inventory</b>", html)
        self.assertIn("Comparar versiones", html)
        self.assertIn("<summary>Ver commits (1)</summary>", html)
        self.assertNotIn("<script", html.lower())
        self.assertNotIn("cdn.", html.lower())

    def test_human_html_status_variants_and_escaped_untrusted_copy(self):
        data = {
            "source_sha": NEW, "previous_sha": None, "status": "no_baseline",
            "total_commits": None, "pull_requests": [], "commits": [],
            "compare_url": None, "truncated": False,
        }
        self.assertIn("No hay una versión anterior verificable", notes.render_html(data))
        self.assertIn("Sin baseline verificable", notes.render_summary(data))
        data["status"] = "already_verified"
        self.assertIn("Sin cambios nuevos", notes.render_html(data))
        data["status"] = "non_linear"
        self.assertIn("rollback", notes.render_html(data))
        data["status"] = "partial"
        data["truncated"] = True
        self.assertIn("Listado parcial", notes.render_html(data))

    def test_workflow_keeps_receipt_gate_and_changelog_best_effort(self):
        workflow = (Path(__file__).resolve().parents[1] /
                    ".github/workflows/chronicles-pages-release.yml").read_text()
        self.assertIn("python3 scripts/chronicles_staging_changelog.py", workflow)
        self.assertIn("continue-on-error: true", workflow)
        self.assertIn(
            "if: steps.entry_freshness.outputs.fresh == 'true' && "
            "(steps.source_freshness.outputs.fresh == 'true')", workflow)
        self.assertIn('verified-pages/changes.json', workflow)
        self.assertIn("CHRONICLES_PAGES_RECEIPT_SHA_MISMATCH", workflow)
        self.assertIn("chronicles-staging-release-notes-", workflow)
        self.assertIn("verified-pages/RELEASE_NOTES.md", workflow)
        self.assertIn("verified-pages/release-notes.html", workflow)
        # Only the successful Pages release can create the final run summary.
        notes_job = workflow.split("  staging-release-summary:", 1)[1].split("  production:", 1)[0]
        release_job = workflow.split("  release:", 1)[1].split("  staging-release-summary:", 1)[0]
        self.assertIn("needs: release", notes_job)
        self.assertIn("needs.release.result == 'success'", notes_job)
        self.assertIn("needs.release.outputs.verified == 'true'", notes_job)
        self.assertIn("chronicles-pages-staging-${{ needs.release.outputs.source_sha }}", notes_job)
        self.assertIn("cat verified-pages/RELEASE_NOTES.md >> \"$GITHUB_STEP_SUMMARY\"", notes_job)
        self.assertIn("continue-on-error: true", notes_job)
        self.assertIn("verified: ${{ steps.source_freshness.outputs.fresh }}", release_job)
        self.assertIn("source_sha: ${{ steps.source.outputs.sha }}", release_job)
        # Release retains its pre-existing superseded-run status note, but
        # does not duplicate the human-facing notes rendered by the final job.
        self.assertNotIn('cat verified-pages/RELEASE_NOTES.md >> "$GITHUB_STEP_SUMMARY"', release_job)
        self.assertNotIn("GITHUB_STEP_SUMMARY", (Path(__file__).resolve().parents[1] /
                         "scripts/chronicles_staging_changelog.py").read_text())


if __name__ == "__main__":
    unittest.main()
