"""Pages must pass real browser login and safe-update UI before release receipt."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / ".github/workflows/chronicles-pages-release.yml"


class PublicBrowserWorkflow(unittest.TestCase):
    def test_every_infra_main_push_retries_staging_convergence(self):
        workflow = yaml.load(PATH.read_text(), Loader=yaml.BaseLoader)
        events = workflow["on"]
        self.assertEqual(events["push"]["branches"], ["main"])
        self.assertNotIn("paths", events["push"])
        self.assertIn("paths", events["pull_request"])
        candidate = next(s["run"] for s in workflow["jobs"]["staging-candidate"]["steps"]
                         if s.get("id") == "check")
        self.assertIn("chronicles_source_ci.py", candidate)
        self.assertIn("chronicles_pages_verified_receipt.py", candidate)
        self.assertIn("publish=false", candidate)
        self.assertEqual(workflow["jobs"]["release"]["if"],
                         "needs.api-ready.outputs.publish == 'true'")
        self.assertIn("inputs.environment != 'production'",
                      workflow["jobs"]["staging-candidate"]["if"])

    def test_api_ready_skips_obsolete_infra_owner_before_pages_release(self):
        workflow = yaml.load(PATH.read_text(), Loader=yaml.BaseLoader)
        jobs = workflow['jobs']
        gate = next(s for s in jobs['api-ready']['steps'] if s.get('id') == 'gate')
        self.assertIn('chronicles_api_before_pages.py', gate['run'])
        self.assertIn('repos/evilsysadmin/shadowops-infra/commits/main', gate['run'])
        self.assertIn('CHRONICLES_PAGES_INFRA_SUPERSEDED_BEFORE_RELEASE', gate['run'])
        self.assertIn('CHRONICLES_PAGES_INVALID_INFRA_SHA', gate['run'])
        self.assertIn('CHRONICLES_PAGES_SOURCE_SUPERSEDED_AFTER_API', gate['run'])
        self.assertIn('CHRONICLES_PAGES_INVALID_SOURCE_SHA', gate['run'])
        self.assertLess(gate['run'].index('owner_main='), gate['run'].index('source_main='))
        self.assertLess(gate['run'].index('source_main='), gate['run'].index("echo 'publish=true'"))
        self.assertEqual(jobs['release']['if'], "needs.api-ready.outputs.publish == 'true'")
        # The independent owner admission is still required before any Pages mutation.
        self.assertIn('pages_owner_admission.py',
                      next(s['run'] for s in jobs['release']['steps']
                           if s.get('name') == 'Require protected mains and single Pages owner before any mutations'))

    def test_post_api_gate_only_skips_proven_stale_source_or_infra_main(self):
        # Run the *real* workflow Bash with a fake API gate and a GitHub CLI
        # stub. An outage, malformed SHA or failed admission must fail closed.
        flow = yaml.load(PATH.read_text(), Loader=yaml.BaseLoader)
        script = next(s['run'] for s in flow['jobs']['api-ready']['steps']
                      if s.get('id') == 'gate')
        owner_sha, admitted = 'a' * 40, 'c' * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gh = root / 'gh'
            gh.write_text(
                '#!/bin/sh\n'
                'case "$*" in\n'
                '  *shadowops-infra/commits/main*)\n'
                '    if [ "$FAKE_GH_FAIL" = owner ]; then exit 7; fi\n'
                '    printf "%s\\n" "$FAKE_OWNER_MAIN";;\n'
                '  *chronicles-of-matthias/commits/main*)\n'
                '    if [ "$FAKE_GH_FAIL" = source ]; then exit 7; fi\n'
                '    printf "%s\\n" "$FAKE_SOURCE_MAIN";;\n'
                '  *) exit 80;;\n'
                'esac\n'
            )
            gh.chmod(0o755)
            py = root / 'python3'
            py.write_text('#!/bin/sh\nexit 0\n')
            py.chmod(0o755)
            scenarios = (
                # owner, source, failure, expected exit, output, log marker
                (owner_sha, admitted, '', 0, 'publish=true', ''),
                ('b' * 40, admitted, '', 0, 'publish=false',
                 'INFRA_SUPERSEDED_BEFORE_RELEASE'),
                (owner_sha, 'd' * 40, '', 0, 'publish=false',
                 'SOURCE_SUPERSEDED_AFTER_API'),
                ('bad-owner', admitted, '', 64, '', 'INVALID_INFRA_SHA'),
                (owner_sha, 'bad-source', '', 64, '', 'INVALID_SOURCE_SHA'),
                (owner_sha, admitted, 'owner', 7, '', ''),
                (owner_sha, admitted, 'source', 7, '', ''),
            )
            for owner, source, failure, code, publish, marker in scenarios:
                with self.subTest(owner=owner, source=source, failure=failure):
                    output = root / 'output'
                    output.write_text('')
                    env = dict(os.environ,
                               PATH=f"{root}{os.pathsep}{os.environ.get('PATH', '')}",
                               ADMITTED_SHA=admitted, GITHUB_SHA=owner_sha,
                               FAKE_OWNER_MAIN=owner, FAKE_SOURCE_MAIN=source,
                               FAKE_GH_FAIL=failure, GITHUB_OUTPUT=str(output))
                    run = subprocess.run(['bash', '-c', script], cwd=ROOT, env=env,
                                         capture_output=True, text=True, check=False)
                    self.assertEqual(run.returncode, code, run.stderr)
                    self.assertEqual(output.read_text().strip(), publish)
                    if marker:
                        self.assertIn(marker, run.stdout + run.stderr)

    def test_browsers_are_live_public_and_after_http_smokes(self):
        workflow = yaml.load(PATH.read_text(), Loader=yaml.BaseLoader)
        jobs = workflow["jobs"]
        steps = jobs["release"]["steps"]
        names = [s.get("name", "") for s in steps]
        browser = "Real public browser smoke (desktop, mobile, login, update deferral)"
        self.assertLess(names.index("Prove the public update manifest serves the exact SHA"),
                        names.index(browser))
        self.assertLess(names.index(browser),
                        names.index("Record the verified Chronicles Pages source generation"))
        action = next(s for s in steps if s.get("name") == browser)
        self.assertIn("smoke/public-staging.mjs", action["run"])
        self.assertIn("smoke/public-staging-journey.mjs", action["run"])
        self.assertLess(action["run"].index("smoke/public-staging.mjs"),
                        action["run"].index("smoke/public-staging-journey.mjs"))
        self.assertIn("chronicles-journey-*.png", PATH.read_text())
        self.assertIn("bash smoke/ensure-chromium.sh", action["run"])
        self.assertNotIn("playwright install --with-deps", action["run"])
        self.assertEqual(action["env"]["CHRONICLES_SOURCE_SHA"],
                         "${{ steps.source.outputs.sha }}")
        self.assertEqual(action["env"]["CHRONICLES_STAGING_INVITE_CODE"],
                         "${{ secrets.CHRONICLES_STAGING_INVITE_CODE }}")
        self.assertEqual(jobs["release"]["environment"]["name"], "staging")
        self.assertIn("if: always()", PATH.read_text())
        self.assertNotIn("environment=production", action["run"])


    def test_same_sha_can_retry_public_smokes_without_redeployment(self):
        workflow = yaml.load(PATH.read_text(), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["release"]["steps"]
        named = {step.get("name", ""): step for step in steps}
        live = named["Check whether exact SHA is already publicly deployed"]
        self.assertIn("--live-only", live["run"])
        self.assertIn("FORCE_PUBLISH", live["env"])
        self.assertIn("workflow_dispatch", live["env"]["FORCE_PUBLISH"])
        self.assertIn("only_if_new", live["env"]["FORCE_PUBLISH"])
        self.assertLess(steps.index(live),
                        steps.index(named["Build the game against its own API"]))
        build = named["Build the game against its own API"]
        # A smoke-only retry does not re-publish, but it MUST build the
        # expected index.html used to catch stale public JS/CSS.
        self.assertNotIn("if", build)
        self.assertIn("dist/index.html", build["run"])
        self.assertLess(steps.index(build), steps.index(named[
            "Real public browser smoke (desktop, mobile, login, update deferral)"]))
        for name in (
            "Assemble static root",
            "Reject foreign hostname ownership before any mutations",
            "Reject superseded source before Pages mutations",
            "Reconcile independent Chronicles Pages project",
            "Publish exact source SHA to the isolated Pages project",
            "Reconcile the exact domain without overwriting other DNS",
        ):
            self.assertEqual(named[name]["if"],
                             "steps.live.outputs.already_published != 'true'")
        # Both the HTTPS and real-browser checks remain compulsory in both paths.
        for name in (
            "Prove the public game build at root",
            "Prove the public update manifest serves the exact SHA",
            "Real public browser smoke (desktop, mobile, login, update deferral)",
            "Reject superseded source before writing verified receipt",
            "Record the verified Chronicles Pages source generation",
        ):
            self.assertNotIn("if", named[name])
        self.assertIn("ALREADY_PUBLISHED",
                      named["Record the verified Chronicles Pages source generation"]["env"])


    def test_playwright_version_step_runs_in_real_bash_and_exports_version(self):
        # Exercise the real shell with pinned and mismatched dependencies.
        flow = yaml.load(PATH.read_text(), Loader=yaml.BaseLoader)
        harness = next(step for step in flow["jobs"]["release"]["steps"]
                       if step.get("name") == "Verify lockfile-pinned Playwright browser harness")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fake = root / "node"
            fake.write_text("#!/bin/sh\ncase \"$*\" in\n  *devDependencies.playwright*) echo \"${DECLARED_VERSION}\" ;;\n  *) echo 1.64.1 ;;\nesac\n")
            fake.chmod(0o755)
            output_file = root / "github_output"
            base_env = {**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                        "GITHUB_OUTPUT": str(output_file)}
            for declared, valid in (("1.64.1", True), ("1.64.0", False)):
                with self.subTest(declared=declared):
                    output_file.write_text("")
                    result = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", harness["run"]],
                        cwd=root, env={**base_env, "DECLARED_VERSION": declared},
                        capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode == 0, valid, result.stderr)
                    self.assertEqual(output_file.read_text().splitlines(),
                                     ["version=1.64.1"] if valid else [])

    def test_staging_uses_lockfile_keyed_npm_cache_without_skipping_ci(self):
        workflow = yaml.load(PATH.read_text(), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["release"]["steps"]
        setup = next(step for step in steps
                     if step.get("name") == "Prepare pinned Node.js for the Chronicles frontend")
        self.assertEqual(setup["with"]["cache"], "npm")
        self.assertEqual(setup["with"]["cache-dependency-path"],
                         "chronicles-source/frontend/package-lock.json")
        build = next(step for step in steps
                     if step.get("name") == "Build the game against its own API")
        self.assertIn("npm ci --ignore-scripts", build["run"])
        self.assertNotIn("if", build)
        browser = next(step for step in steps
                       if step.get("name") == "Real public browser smoke (desktop, mobile, login, update deferral)")
        harness = next(step for step in steps
                       if step.get("name") == "Verify lockfile-pinned Playwright browser harness")
        cache = next(step for step in steps
                     if step.get("name") == "Cache exact Chromium browser binaries")
        self.assertLess(steps.index(harness), steps.index(cache))
        self.assertLess(steps.index(cache), steps.index(browser))
        self.assertEqual(harness["id"], "playwright")
        self.assertNotIn("npm install", harness["run"])
        self.assertIn("devDependencies.playwright", harness["run"])
        self.assertIn("node_modules/playwright/package.json", harness["run"])
        self.assertEqual(cache["uses"], "actions/cache@v4")
        self.assertEqual(cache["with"]["path"], "~/.cache/ms-playwright")
        self.assertIn("steps.playwright.outputs.version", cache["with"]["key"])
        self.assertIn("runner.os", cache["with"]["key"])
        self.assertIn("runner.arch", cache["with"]["key"])
        self.assertNotIn("npm install --no-save", browser["run"])
        self.assertIn("bash smoke/ensure-chromium.sh", browser["run"])
        self.assertNotIn("install --with-deps", browser["run"])
        production = workflow["jobs"]["production"]["steps"]
        prod_setup = next(step for step in production
                          if step.get("name") == "Prepare pinned Node.js for the Chronicles frontend")
        self.assertNotIn("cache", prod_setup["with"])


if __name__ == "__main__":
    unittest.main()
