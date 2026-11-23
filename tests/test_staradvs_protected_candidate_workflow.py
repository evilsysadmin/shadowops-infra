"""The real protected candidate is built only from admitted immutable sources."""
from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import staradvs_protected_bundle as protected

WORKFLOW = ROOT / ".github/workflows/staradvs-protected-candidate.yml"


class ProtectedCandidateWorkflowTests(unittest.TestCase):
    def test_it_remains_a_non_deployable_candidate(self):
        flow = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(protected.policy_status(), "pending-identity")
        self.assertEqual(protected.main(["gate"]), 10)
        for banned in (
            "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCESS_WRITE_TOKEN",
            "SHADOWOPS_STARADVS_SERVICE_CREDENTIAL",
            "wrangler", "pages deploy", "curl -X", "ssh ", "oci==",
            "contents: write", "secrets.", "environment: staging",
        ):
            self.assertNotIn(banned, flow, banned)
        self.assertIn("deployment=not-attempted", flow)
        self.assertIn("NOT DEPLOYED", flow)
        self.assertIn("actions/upload-artifact@v4", flow)

    def test_exact_green_game_sha_required_twice_and_no_untrusted_pr_build(self):
        flow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", flow)
        self.assertIn("pull_request:", flow)
        self.assertIn("branches: [main]", flow)
        self.assertIn("github.repository == 'evilsysadmin/shadowops-infra'", flow)
        self.assertIn("github.ref == 'refs/heads/main'", flow)
        self.assertIn("github.event_name == 'push'", flow)
        self.assertIn("github.event_name == 'workflow_dispatch'", flow)
        self.assertIn("needs: [contracts, admit]", flow)
        self.assertIn("needs: contracts", flow)
        self.assertNotIn("repository: evilsysadmin/star-adventures", flow)
        self.assertIn("GIT_TERMINAL_PROMPT=0", flow)
        self.assertIn("https://github.com/evilsysadmin/star-adventures.git", flow)
        self.assertIn("sha: ${{ steps.source.outputs.sha }}", flow)
        self.assertEqual(flow.count("scripts/staradvs_source_admission.py \"$"), 1)
        self.assertEqual(flow.count("scripts/staradvs_infra_revision.py \"$"), 1)
        self.assertIn("actions/checkout@v4", flow)
        self.assertIn("persist-credentials: false", flow)
        self.assertEqual(flow.count("GH_TOKEN: ${{ github.token }}"), 1)
        untrusted = flow.split("\n  candidate:\n", 1)[1]
        self.assertNotIn("GH_TOKEN:", untrusted)
        self.assertNotIn("github.token", untrusted)
        build_step = flow.split("- name: Build exact game source", 1)[1].split("- name: Recheck game main", 1)[0]
        self.assertNotIn("GH_TOKEN:", build_step)
        self.assertNotIn("secrets.", build_step)
        self.assertNotIn("cache: npm", flow)
        self.assertIn("git -C staradvs-source rev-parse HEAD", flow)

    def test_prepared_worker_integrity_checked_before_any_artifact(self):
        flow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("npm ci --prefix staradvs-source/frontend", flow)
        self.assertIn("npm run build --prefix staradvs-source/frontend", flow)
        self.assertIn("scripts/staradvs_pages.py manifest", flow)
        self.assertIn("scripts/staradvs_protected_bundle.py prepare", flow)
        self.assertEqual(flow.count("scripts/staradvs_protected_bundle.py verify"), 2)
        self.assertIn("node --test tests/staradvs-identity-gate.test.mjs", flow)
        self.assertIn("node --check edge/staradvs-identity-gate.mjs", flow)
        first_verify = flow.index("scripts/staradvs_protected_bundle.py verify")
        upload = flow.index("actions/upload-artifact@v4")
        self.assertLess(first_verify, upload)
        self.assertIn("retention-days: 7", flow)
        self.assertIn("name: staradvs-protected-candidate-${{ needs.admit.outputs.sha }}", flow)
        self.assertIn("path: staradvs-source", flow)
        self.assertIn("if-no-files-found: error", flow)


if __name__ == "__main__":
    unittest.main()
