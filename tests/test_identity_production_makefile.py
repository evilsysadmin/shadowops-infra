"""Contract for Makefile entrypoints: wrappers, not an unreviewed prod deploy."""
from pathlib import Path
import os
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")

EXPECTED = {
    "identity-prod-mongo-inspect": "scripts/identity_production_mongo_operator.py inspect",
    "identity-prod-mongo-apply": "scripts/identity_production_mongo_operator.py apply",
    "identity-prod-origin-inspect": "host/identity-production-origin.py inspect",
    "identity-prod-origin-start": "host/identity-production-origin.py start-origin",
    "identity-prod-origin-stop": "host/identity-production-origin.py stop-origin",
    "identity-prod-tunnel-inspect": "host/identity-production-tunnel.py inspect",
    "identity-prod-tunnel-start": "host/identity-production-tunnel.py start-tunnel",
    "identity-prod-tunnel-stop": "host/identity-production-tunnel.py stop-tunnel",
    "identity-prod-account-inspect": "host/identity-production-native-account.py inspect",
    "identity-prod-account-create": "host/identity-production-native-account.py create",
    "bridgesquad-prod-identity-status": "scripts/bridgesquad_prod_identity_probe.py inspect",
    "bridgesquad-prod-identity-ready": "scripts/bridgesquad_prod_identity_probe.py require-public-surface",
    "bridgesquad-prod-pages-audit": "scripts/bridgesquad_alias_watchdog.py audit",
    "bridgesquad-prod-proof-inspect": "scripts/bridgesquad_production_proof_bind.py inspect",
    "bridgesquad-prod-proof-bind": "scripts/bridgesquad_production_proof_bind.py bind",
    "bridgesquad-prod-release-plan": "scripts/bridgesquad_production_release.py plan",
}


def dry_run(target):
    p = subprocess.run(
        ["make", "--no-print-directory", "--dry-run", target],
        cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    if p.returncode:
        raise AssertionError(f"make -n {target}: {p.stderr}")
    return p.stdout


class MakeEntrypointsTests(unittest.TestCase):
    def test_existing_cka_and_staging_entrypoints_unchanged(self):
        for snippet in (
            "bash host/cka-retire-over-ssh.sh retire",
            "bash host/cka-retire-over-ssh.sh inspect",
            "bash host/bootstrap-identity-staging-over-ssh.sh",
        ):
            self.assertIn(snippet, MAKEFILE)
        self.assertIn(".DEFAULT_GOAL := help", MAKEFILE)

    def test_all_operator_targets_call_only_the_correct_operator(self):
        all_scripts = tuple(EXPECTED.values())
        for target, script in EXPECTED.items():
            with self.subTest(target=target):
                command = dry_run(target)
                self.assertIn(script, command)
                for other in all_scripts:
                    if other != script:
                        self.assertNotIn(other, command)
                self.assertNotIn("sudo ", command)
                self.assertNotIn("docker ", command)
                self.assertNotIn("wrangler ", command)
                self.assertNotIn("gh workflow run", command)
                self.assertNotIn("ssh ", command)

    def test_plan_and_inspect_do_not_start_or_bind_anything(self):
        for target in ("identity-prod-plan", "identity-prod-doctor", "identity-prod-inspect",
                       "identity-prod-mongo-inspect", "identity-prod-origin-inspect",
                       "identity-prod-tunnel-inspect",
                       "identity-prod-account-inspect",
                       "bridgesquad-prod-identity-status",
                       "bridgesquad-prod-identity-ready",
                       "bridgesquad-prod-pages-audit",
                       "bridgesquad-prod-proof-inspect",
                       "bridgesquad-prod-release-plan"):
            with self.subTest(target=target):
                cmd = dry_run(target)
                self.assertNotRegex(cmd, r"(?m)^python3 .* (start-origin|start-tunnel|create|apply|bind|stop-origin|stop-tunnel)\b")
        doctor = dry_run("identity-prod-doctor")
        self.assertIn("scripts/identity_production_doctor.py", doctor)
        self.assertLess(
            dry_run("identity-prod-inspect").index("scripts/identity_production_doctor.py"),
            dry_run("identity-prod-inspect").index("identity_production_mongo_operator.py inspect"),
        )
        plan = dry_run("identity-prod-plan")
        for required in (
            "identity_production_mongo_operator.py plan",
            "identity-production-origin.py plan",
            "identity-production-tunnel.py plan",
            "identity-production-native-account.py plan",
            "bridgesquad_production_proof_bind.py plan",
            "bridgesquad_production_release.py plan",
        ):
            self.assertIn(required, plan)
        for forbidden in (" start-origin", " start-tunnel", " apply", " bind", " create"):
            self.assertNotIn(forbidden, plan)

    def test_account_and_proof_targets_require_explicit_nonsecret_identifiers(self):
        for target in ("identity-prod-account-inspect", "identity-prod-account-create"):
            self.assertIn('$IDENTITY_PRODUCTION_ACCOUNT', dry_run(target))
        for target in ("bridgesquad-prod-proof-inspect", "bridgesquad-prod-proof-bind"):
            self.assertIn('$BRIDGESQUAD_PAGES_SHA', dry_run(target))

        # Actual make invocation must be refused *before* the operator is called.
        env = dict(os.environ)
        env.pop("IDENTITY_PRODUCTION_ACCOUNT", None)
        env.pop("BRIDGESQUAD_PAGES_SHA", None)
        for target in ("identity-prod-account-create", "bridgesquad-prod-proof-bind"):
            p = subprocess.run(["make", "--no-print-directory", target], cwd=ROOT,
                               capture_output=True, text=True, timeout=10, env=env)
            with self.subTest(target=target):
                self.assertNotEqual(p.returncode, 0)
                self.assertIn("Set ", p.stderr)

    def test_makefile_never_defines_an_unattended_production_chain(self):
        self.assertNotIn("workflow_dispatch", MAKEFILE)
        self.assertNotIn("RELEASE_BRIDGESQUAD_PRODUCTION", MAKEFILE)
        self.assertNotIn("START_LOOPBACK_PRODUCTION_IDENTITY_ONLY", MAKEFILE)
        self.assertNotIn("ENABLE_ONLY_IDENTITY_NAMED_TUNNEL", MAKEFILE)
        self.assertNotIn("PROVISION_EXACT_PRODUCTION_IDENTITY_DB", MAKEFILE)
        self.assertNotIn("BIND_BRIDGESQUAD_PRODUCTION_PROOF_ONLY", MAKEFILE)
        # Only executable recipe lines matter: comments explicitly document
        # the forbidden operations, and are not themselves shell commands.
        recipes = "\n".join(line for line in MAKEFILE.splitlines()
                            if line.startswith("\t"))
        self.assertNotIn("sudo ", recipes)
        self.assertNotIn("docker compose", recipes)
        self.assertNotIn("gh workflow run", recipes)
        self.assertNotIn("curl ", recipes)
        self.assertNotIn("ssh ", recipes)
        self.assertRegex(MAKEFILE, r"(?m)^identity-prod-origin-start:")
        self.assertRegex(MAKEFILE, r"(?m)^identity-prod-tunnel-start:")


if __name__ == "__main__":
    unittest.main()
