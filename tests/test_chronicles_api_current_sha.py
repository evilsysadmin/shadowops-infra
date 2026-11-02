"""Two independent OCI staging gates share a strict, read-only source SHA lookup."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/chronicles_api_current_sha.sh"
WORKFLOW = ROOT / ".github/workflows/chronicles-api-staging.yml"
SHA = "a" * 40


class OCIStagingSourceSHA(unittest.TestCase):
    def probe(self, *, admitted=SHA, current=SHA, gh_fail=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            gh = root / "gh"
            gh.write_text(
                '#!/bin/sh\n'
                'if [ "$FAKE_GH_FAIL" = true ]; then exit 7; fi\n'
                'case "$*" in\n'
                '  *chronicles-of-matthias/commits/main*) printf "%s\\n" "$FAKE_MAIN_SHA";;\n'
                '  *) exit 9;;\n'
                'esac\n', encoding="utf-8")
            gh.chmod(0o755)
            env = {**os.environ,
                   "PATH": str(root) + os.pathsep + os.environ.get("PATH", ""),
                   "GH_TOKEN": "synthetic-readonly", "FAKE_MAIN_SHA": current,
                   "FAKE_GH_FAIL": str(gh_fail).lower()}
            return subprocess.run(["bash", str(SCRIPT), admitted], env=env,
                                  cwd=ROOT, capture_output=True, text=True,
                                  timeout=5, check=False)

    def test_valid_main_sha_is_only_stdout(self):
        result = self.probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, SHA + "\n")
        self.assertEqual(result.stderr, "")

    def test_newer_valid_main_is_reported_for_each_gate_to_decide(self):
        newer = "b" * 40
        result = self.probe(current=newer)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), newer)

    def test_invalid_admitted_sha_fails_with_original_code(self):
        for value in ("", "main", "A" * 40, "a" * 39, "a" * 41):
            with self.subTest(value=value):
                result = self.probe(admitted=value)
                self.assertEqual(result.returncode, 64)
                self.assertEqual(result.stdout, "")
                self.assertIn("CHRONICLES_OCI_INVALID_SOURCE", result.stderr)

    def test_malformed_live_main_fails_with_original_code(self):
        for current in ("", "main", "A" * 40, "b" * 39):
            with self.subTest(current=current):
                result = self.probe(current=current)
                self.assertEqual(result.returncode, 65)
                self.assertEqual(result.stdout, "")
                self.assertIn("CHRONICLES_OCI_INVALID_MAIN_SHA", result.stderr)

    def test_github_failure_is_not_mistaken_for_supersession(self):
        result = self.probe(gh_fail=True)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "")

    def test_oci_staging_checks_remain_independent_and_ordered(self):
        data = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        deploy = data["jobs"]["deploy"]
        steps = deploy["steps"]
        pre = next(s for s in steps if s.get("id") == "staging_preflight")
        late = next(s for s in steps if s.get("id") == "staging_freshness")
        command = 'current="$(bash scripts/chronicles_api_current_sha.sh "$ADMITTED_SHA")"'
        for gate in (pre, late):
            self.assertIn("set -euo pipefail", gate["run"])
            self.assertEqual(gate["run"].count(command), 1)
            self.assertIn("GRANT_ADMIN", gate["env"])
            self.assertIn("CHRONICLES_ADMIN_GRANT_DEPLOY_BLOCKED", gate["run"])
            self.assertIn("fresh=false", gate["run"])
            self.assertIn("fresh=true", gate["run"])
        self.assertLess(steps.index(pre), steps.index(late))
        self.assertLess(steps.index(pre), next(i for i, s in enumerate(steps)
                        if s.get("uses") == "actions/setup-python@v5"))
        self.assertLess(steps.index(late), next(i for i, s in enumerate(steps)
                        if s.get("name") == "Execute only the restricted Chronicles API deployer"))
        self.assertIn("--receipt-only", pre["run"])
        self.assertIn("CHRONICLES_OCI_LATE_RECEIPT_CHECK_INCONCLUSIVE", pre["run"])
        self.assertNotIn("--receipt-only", late["run"])
        self.assertIn("CHRONICLES_OCI_STALE_SOURCE_PRECHECK_SKIPPED", pre["run"])
        self.assertIn("CHRONICLES_OCI_STALE_SOURCE_SKIPPED", late["run"])
        self.assertEqual(pre["if"], "inputs.environment != 'production'")
        self.assertIn("steps.staging_preflight.outputs.fresh == 'true'", late["if"])
        self.assertIn("steps.staging_freshness.outputs.fresh == 'true'",
                      next(s for s in steps if s.get("name") ==
                           "Execute only the restricted Chronicles API deployer")["if"])
        self.assertIn("chronicles_production_admission.py",
                      next(s for s in steps if s.get("name") ==
                           "Require verified staging API and Pages before production mutation")["run"])
        text = WORKFLOW.read_text()
        self.assertIn("scripts/chronicles_api_current_sha.sh",
                      text.split("  pull_request:", 1)[1].split("  push:", 1)[0])
        self.assertIn("bash -n scripts/chronicles_api_current_sha.sh", text)
        self.assertIn("test_chronicles_api_current_sha.py", text)


if __name__ == "__main__":
    unittest.main()
