"""Offline regression for shared Chronicles staging/production bundle checks."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/chronicles_frontend_artifacts.sh"
WORKFLOW = ROOT / ".github/workflows/chronicles-pages-release.yml"
SHA = "a" * 40
STAGING = "chronicles-api-staging.shadowops.dpdns.org"
PRODUCTION = "chronicles-api.shadowops.dpdns.org/api"


class FrontendArtifactsContract(unittest.TestCase):
    def make_build(self, folder, *, api=STAGING, build=SHA):
        dist = folder / "dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "audio/orchestra").mkdir(parents=True)
        (dist / "models").mkdir(parents=True)
        (dist / "release.json").write_text(json.dumps({"build": build}))
        (dist / "index.html").write_text(
            '<html><head><title>Chronicles of Matthias</title>'
            '<script src="/assets/main.js"></script></head></html>')
        (dist / "assets/ChroniclesOfMatthias-main.js").write_text(
            "// /chronicles/runs\nconst api = " + repr(api) + ";\n")
        (dist / "assets/ChroniclesOfMatthiasTactics-main.js").write_text("/* tactics */")
        (dist / "assets/chroniclesOfMatthiasThree-main.js").write_text("/* renderer */")
        (dist / "audio/orchestra/violin-fs3.mp3").write_bytes(b"test-audio")
        (dist / "models/matthias-home-canonical.glb").write_bytes(b"test-model")
        return dist

    def run_gate(self, folder, target, *, build=SHA):
        return subprocess.run(
            ["bash", str(SCRIPT), target], cwd=folder,
            env={**os.environ, "VITE_BUILD_SHA": build},
            capture_output=True, text=True, timeout=10,
        )

    def test_both_expected_api_modes_pass_a_full_build(self):
        for mode, api in (("staging", STAGING), ("production", PRODUCTION)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.make_build(root, api=api)
                result = self.run_gate(root, mode)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_production_rejects_staging_api_even_if_production_api_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dist = self.make_build(root, api=PRODUCTION)
            js = dist / "assets/ChroniclesOfMatthias-main.js"
            js.write_text(js.read_text() + "\n// " + STAGING)
            result = self.run_gate(root, "production")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("staging API in production build", result.stderr)

    def test_staging_rejects_production_only_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_build(root, api=PRODUCTION)
            self.assertNotEqual(self.run_gate(root, "staging").returncode, 0)

    def test_manifest_must_match_exact_source_sha(self):
        for mode, api in (("staging", STAGING), ("production", PRODUCTION)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.make_build(root, api=api, build="b" * 40)
                self.assertNotEqual(self.run_gate(root, mode).returncode, 0)

    def test_missing_assets_never_pass(self):
        missing = (
            "dist/release.json", "dist/index.html",
            "dist/assets/ChroniclesOfMatthias-main.js",
            "dist/assets/ChroniclesOfMatthiasTactics-main.js",
            "dist/assets/chroniclesOfMatthiasThree-main.js",
            "dist/audio/orchestra/violin-fs3.mp3",
            "dist/models/matthias-home-canonical.glb",
        )
        for path in missing:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                self.make_build(root)
                (root / path).unlink()
                self.assertNotEqual(self.run_gate(root, "staging").returncode, 0)

    def test_runtime_api_usage_must_be_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dist = self.make_build(root)
            (dist / "assets/ChroniclesOfMatthias-main.js").write_text("// " + STAGING)
            self.assertNotEqual(self.run_gate(root, "staging").returncode, 0)

    def test_invalid_mode_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_gate(Path(tmp), "prod")
            self.assertEqual(result.returncode, 64)
            self.assertIn("CHRONICLES_ARTIFACTS_INVALID_TARGET", result.stderr)

    def test_both_workflows_build_before_verifying_and_publishing(self):
        doc = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        for job, mode in (("release", "staging"), ("production", "production")):
            with self.subTest(job=job):
                steps = doc["jobs"][job]["steps"]
                build = next(s for s in steps if s.get("name") ==
                             "Build the game against its own API")
                cmd = "bash ../../scripts/chronicles_frontend_artifacts.sh " + mode
                self.assertIn("npm ci --ignore-scripts --no-audit --no-fund", build["run"])
                self.assertIn("npm run build", build["run"])
                self.assertIn(cmd, build["run"])
                self.assertLess(build["run"].index("npm run build"), build["run"].index(cmd))
                self.assertEqual(build["working-directory"], "chronicles-source/frontend")
                self.assertEqual(build["env"]["VITE_BUILD_SHA"], "${{ steps.source.outputs.sha }}")
                assemble = next(s for s in steps if s.get("name") == "Assemble static root")
                self.assertLess(steps.index(build), steps.index(assemble))
                self.assertLess(steps.index(assemble), next(
                    i for i, s in enumerate(steps)
                    if s.get("name") == "Publish exact source SHA to the isolated Pages project"))
        stage = next(s for s in doc["jobs"]["release"]["steps"]
                     if s.get("name") == "Build the game against its own API")
        prod = next(s for s in doc["jobs"]["production"]["steps"]
                    if s.get("name") == "Build the game against its own API")
        self.assertEqual(stage["env"]["VITE_API_URL"], "https://" + STAGING + "/api")
        self.assertEqual(prod["env"]["VITE_API_URL"], "https://" + PRODUCTION)
        self.assertIn("steps.entry_freshness.outputs.fresh == 'true'", stage["if"])
        content = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("scripts/chronicles_frontend_artifacts.sh",
                      content.split("  pull_request:", 1)[1].split("  push:", 1)[0])


if __name__ == "__main__":
    unittest.main()
