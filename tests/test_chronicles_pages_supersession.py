"""Protect Pages from superseded SHA races without false-red deploy results.

These guards run after building the source and immediately before Cloudflare
writes. A source-main advance is an expected no-op, not a deployment failure;
broken GitHub checks, malformed SHAs and actual deploy failures remain red.
"""
import os
import pathlib
import subprocess
import tempfile
import unittest


WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows/chronicles-pages-release.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8").split("\n  production:\n", 1)[0]
EXPECTED = "a" * 40
CURRENT = "b" * 40


def step_block(name):
    marker = f"      - name: {name}\n"
    assert TEXT.count(marker) == 1, name
    section = TEXT.split(marker, 1)[1].split("\n      - ", 1)[0]
    return section


def bash_run(name):
    section = step_block(name)
    assert "        shell: bash\n" in section
    return "\n".join(
        line[10:] if line.startswith("          ") else line
        for line in section.split("        run: |\n", 1)[1].splitlines()
    ) + "\n"


def run_guard(name, *, current=CURRENT, fail_gh=False):
    script = bash_run(name)
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp)
        output = root / "outputs"
        summary = root / "summary"
        calls = root / "calls"
        gh_mock = r"""
gh() {
  if [[ "$FAKE_GH_FAIL" == 'true' ]]; then return 23; fi
  printf '%s\n' "$FAKE_CURRENT_SHA"
}
npx() {
  echo 'WRANGLER_CALLED' >> "$FAKE_CALLS"
  return 0
}
"""
        env = {
            **os.environ,
            "ADMITTED_SHA": EXPECTED,
            "CHRONICLES_SOURCE_SHA": EXPECTED,
            "FAKE_CURRENT_SHA": current,
            "FAKE_GH_FAIL": "true" if fail_gh else "false",
            "FAKE_CALLS": str(calls),
            "GITHUB_OUTPUT": str(output),
            "GITHUB_STEP_SUMMARY": str(summary),
            "RUNNER_TEMP": str(root),
        }
        result = subprocess.run(
            ["bash", "-c", gh_mock + "\n" + script],
            env=env, text=True, capture_output=True, timeout=10, check=False,
        )
        return result, output.read_text() if output.exists() else "", (
            summary.read_text() if summary.exists() else ""
        ), calls.read_text() if calls.exists() else ""


class PagesSupersessionTest(unittest.TestCase):
    def test_pre_publish_superseded_is_clean_noop_with_notice(self):
        result, output, summary, calls = run_guard(
            "Reject superseded source before Pages mutations"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CHRONICLES_PAGES_SUPERSEDED_BEFORE_PUBLISH", result.stdout)
        self.assertIn("::notice", result.stdout)
        self.assertIn("fresh=false", output)
        self.assertIn("No Cloudflare mutation or release receipt", summary)
        self.assertFalse(calls)

    def test_pre_publish_current_sha_allows_mutations(self):
        result, output, summary, calls = run_guard(
            "Reject superseded source before Pages mutations", current=EXPECTED
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("fresh=true", output)
        self.assertFalse(summary)
        self.assertFalse(calls)

    def test_at_deploy_superseded_never_invokes_wrangler(self):
        result, output, summary, calls = run_guard(
            "Publish exact source SHA to the isolated Pages project"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CHRONICLES_PAGES_SUPERSEDED_AT_DEPLOY", result.stdout)
        self.assertIn("published=false", output)
        self.assertFalse(calls)
        self.assertIn("No Pages deploy or release receipt", summary)

    def test_at_deploy_current_sha_invokes_wrangler(self):
        result, output, _, calls = run_guard(
            "Publish exact source SHA to the isolated Pages project", current=EXPECTED
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WRANGLER_CALLED", calls)
        self.assertIn("published=true", output)

    def test_github_failure_and_malformed_sha_still_fail_closed(self):
        for name in (
            "Reject superseded source before Pages mutations",
            "Publish exact source SHA to the isolated Pages project",
        ):
            with self.subTest(step=name, failure="api"):
                result, output, _, calls = run_guard(name, fail_gh=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output)
                self.assertFalse(calls)
            with self.subTest(step=name, failure="malformed"):
                result, output, _, calls = run_guard(name, current="not-a-commit")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output)
                self.assertFalse(calls)

    def test_downstream_steps_cannot_publish_verify_or_certify_stale_sha(self):
        gate = step_block("Reject superseded source before Pages mutations")
        self.assertIn("id: prepublish", gate)
        self.assertIn("fresh=false", gate)

        project = step_block("Reconcile independent Chronicles Pages project")
        self.assertIn("steps.prepublish.outputs.fresh == 'true'", project)
        publish = step_block("Publish exact source SHA to the isolated Pages project")
        self.assertIn("id: publish", publish)
        self.assertIn("steps.prepublish.outputs.fresh == 'true'", publish)
        self.assertIn("published=false", publish)

        domain = step_block("Reconcile the exact domain without overwriting other DNS")
        self.assertIn("steps.publish.outputs.published == 'true'", domain)
        conditional = (
            "steps.live.outputs.already_published == 'true'"
            " || steps.publish.outputs.published == 'true'"
        )
        for name in (
            "Prove the public game build at root",
            "Prove the public update manifest serves the exact SHA",
            "Verify lockfile-pinned Playwright browser harness",
            "Cache exact Chromium browser binaries",
            "Real public browser smoke (desktop, mobile, login, update deferral)",
            "Reject superseded source before writing verified receipt",
        ):
            with self.subTest(step=name):
                self.assertIn("if: " + conditional, step_block(name))
        self.assertIn("steps.source_freshness.outputs.fresh == 'true'",
                      step_block("Record the verified Chronicles Pages source generation"))
        self.assertIn("steps.source_freshness.outputs.fresh == 'true'",
                      step_block("Save verified Pages receipt for idempotent hourly sync"))


if __name__ == "__main__":
    unittest.main()
