"""Pages must pass real browser login and safe-update UI before release receipt."""
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / ".github/workflows/chronicles-pages-release.yml"


class PublicBrowserWorkflow(unittest.TestCase):
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
        self.assertIn("playwright install --with-deps chromium", action["run"])
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
        for name in (
            "Build the game against its own API",
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
        self.assertEqual(build["if"], "steps.live.outputs.already_published != 'true'")
        browser = next(step for step in steps
                       if step.get("name") == "Real public browser smoke (desktop, mobile, login, update deferral)")
        harness = next(step for step in steps
                       if step.get("name") == "Prepare Playwright browser harness")
        cache = next(step for step in steps
                     if step.get("name") == "Cache exact Chromium browser binaries")
        self.assertLess(steps.index(harness), steps.index(cache))
        self.assertLess(steps.index(cache), steps.index(browser))
        self.assertEqual(harness["id"], "playwright")
        self.assertIn("npm install --no-save --no-audit --no-fund playwright@1", harness["run"])
        self.assertIn("node_modules/playwright/package.json", harness["run"])
        self.assertEqual(cache["uses"], "actions/cache@v4")
        self.assertEqual(cache["with"]["path"], "~/.cache/ms-playwright")
        self.assertIn("steps.playwright.outputs.version", cache["with"]["key"])
        self.assertIn("runner.os", cache["with"]["key"])
        self.assertNotIn("npm install --no-save", browser["run"])
        self.assertIn("playwright install --with-deps chromium", browser["run"])
        production = workflow["jobs"]["production"]["steps"]
        prod_setup = next(step for step in production
                          if step.get("name") == "Prepare pinned Node.js for the Chronicles frontend")
        self.assertNotIn("cache", prod_setup["with"])


if __name__ == "__main__":
    unittest.main()
