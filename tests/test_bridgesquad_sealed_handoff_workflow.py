"""Static guardrails for the non-deploying Bridge Squad source-to-Infra handoff."""
import re
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/bridgesquad-source-admission.yml"


class SealedHandoffWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.job = self.text.split("\n  sealed-candidate:\n", 1)[1]

    def test_handoff_is_bound_to_trusted_main_and_green_contracts(self):
        self.assertIn("needs: contracts", self.job)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", self.job)
        self.assertIn("github.ref == 'refs/heads/main'", self.job)
        self.assertIn("github.event_name == 'push'", self.job)
        self.assertIn("github.event_name == 'workflow_dispatch'", self.job)
        self.assertNotIn("pull_request", self.job)

    def test_green_game_artifact_provenance_and_privately_rebuilt_source(self):
        for required in (
            "source.admit(reader, sha)",
            "steps.source.outputs.source_sha",
            "bridgesquad_source_snapshot.py snapshot",
            "steps.snapshot.outputs.snapshot_digest",
            "bridgesquad_release_package.py prepare",
            "bridgesquad_release_package.py verify",
            "bridgesquad_source_admission.py check \"$SOURCE_SHA\"",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.job)
        order = ["source.admit(reader, sha)", "bridgesquad_source_snapshot.py snapshot",
                 "release_package.py prepare", "release_package.py verify",
                 "source_admission.py check", "actions/upload-artifact@v4"]
        offsets = [self.job.index(item) for item in order]
        self.assertEqual(offsets, sorted(offsets), "upload must follow all checks")
        self.assertNotIn("/actions/artifacts/$ARTIFACT_ID/zip", self.job)
        self.assertNotIn("gh api \"repos/evilsysadmin/matthias-bridge-squad/actions/artifacts", self.job)

    def test_signed_browser_runs_on_exact_sealed_artifact_before_archive(self):
        self.assertIn("node-version: '22'", self.text)
        self.assertIn("tests/test_bridgesquad_sealed_worker_fixture.py", self.text)
        self.assertIn("scripts/bridgesquad_sealed_worker_browser.py", self.job)
        self.assertIn("scripts/bridgesquad_sealed_worker_fixture.mjs", self.text)
        self.assertIn("python3 -m playwright install --with-deps chromium", self.job)
        self.assertIn("timeout-minutes: 12", self.job)
        self.assertIn("if: steps.duplicate.outputs.sealed_exists != 'true'", self.job)
        self.assertLess(self.job.index("bridgesquad_release_package.py verify"),
                        self.job.index("scripts/bridgesquad_sealed_worker_browser.py"))
        self.assertLess(self.job.index("scripts/bridgesquad_sealed_worker_browser.py"),
                        self.job.index("bridgesquad_source_admission.py check"))
        self.assertLess(self.job.index("scripts/bridgesquad_sealed_worker_browser.py"),
                        self.job.index("actions/upload-artifact@v4"))

    def test_browser_fixture_does_not_eval_into_strict_csp_login_shell(self):
        probe = (WORKFLOW.parents[2] / "scripts" /
                 "bridgesquad_sealed_worker_browser.py").read_text(encoding="utf-8")
        self.assertIn('page.locator(\'[data-action="play"]\').wait_for(', probe)
        self.assertNotIn('window.__MBS_TEST__ && __MBS_TEST__.getState()', probe)

    def test_no_cloudflare_dns_secret_binding_or_public_delivery(self):
        for prohibited in (
            "wrangler", "deploy-pages", "cloudflare-api", "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_ACCOUNT_ID", "OCI_PRIVATE_KEY",
            "actions/deploy-pages", "CF_API_TOKEN",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited.lower(), self.job.lower())
        self.assertIn("actions/upload-artifact@v4", self.job)
        self.assertIn("retention-days: 14", self.job)
        self.assertIn("persist-credentials: false", self.job)

    def test_daily_reconciliation_is_read_only_and_uploads_only_once_per_sha_pair(self):
        self.assertIn("  schedule:", self.text)
        self.assertIn("cron: '19 7 * * *'", self.text)
        self.assertIn("cancel-in-progress: false", self.text)
        self.assertIn("github.event_name == 'schedule'", self.job)
        self.assertIn("needs: contracts", self.job)
        self.assertIn("id: duplicate", self.job)
        self.assertIn("scripts/bridgesquad_sealed_candidate_dedupe.py check", self.job)
        self.assertGreater(
            self.job.index("scripts/bridgesquad_sealed_candidate_dedupe.py check"),
            self.job.index("source.admit(reader, sha)"),
        )
        for title in (
            "Rebuild pinned public game commit into a private source ZIP (no cross-repo Actions download)",
            "Seal the exact HTML with Infra-owned fail-closed Identity Worker",
            "Recheck unchanged game main before publishing private artifact",
            "Archive private Infra candidate for later protected delivery",
        ):
            marker = "      - name: " + title + "\n        if: steps.duplicate.outputs.sealed_exists != 'true'"
            with self.subTest(title=title):
                self.assertIn(marker, self.job)
        self.assertIn("scripts/bridgesquad_sealed_candidate_dedupe.py", self.text)
        self.assertIn("tests/test_bridgesquad_sealed_candidate_dedupe.py", self.text)

    def test_no_pr_or_untrusted_fork_can_package_as_main(self):
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", self.job)
        self.assertIn("github.ref == 'refs/heads/main'", self.job)
        self.assertRegex(self.job, r"\[\[ \"\$SOURCE_SHA\" =~ \^\[0-9a-f\]\{40\}\$ \]\]")
        self.assertIn("if-no-files-found: error", self.job)


if __name__ == "__main__":
    unittest.main()
