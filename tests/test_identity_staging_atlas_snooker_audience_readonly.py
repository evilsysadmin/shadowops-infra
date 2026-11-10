"""Offline Snooker audience custody probes; no live host, secrets, Vault or Docker."""
import contextlib
from importlib.util import module_from_spec, spec_from_file_location
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts/identity_staging_atlas_snooker_audience_readonly.py"
spec = spec_from_file_location("atlas_snooker_audience_readonly", MODULE)
audit = module_from_spec(spec)
spec.loader.exec_module(audit)

SN = "soc1_" + "a" * 43
CH = "soc1_" + "b" * 43


class AuditFixture(unittest.TestCase):
    def fixture(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        state = root / "state"
        state.mkdir(mode=0o700)
        self.root, self.state = root, state
        self.uid = os.getuid()
        self.source, self.atlas = root / "service.json", root / "atlas-service.json"
        self.write(self.source, {"chronicles": CH})
        self.write(self.atlas, {"chronicles": CH})

    def write(self, path, consumers):
        # CI runs as an unprivileged user; restore fixture write permission
        # before replacing the bytes, then enforce real 0400 reader mode.
        if path.exists():
            path.chmod(0o600)
        path.write_text(json.dumps({"environment": "staging", "consumers": consumers,
                                    "signing_seed": "PRIVATE_MUST_NEVER_APPEAR"}))
        path.chmod(0o400)

    def evaluate(self):
        with patch.object(audit, "trusted_directory"):
            return audit.evaluate(root=self.root, state=self.state, service_uid=self.uid)

    def test_both_absent_identifies_stale_provisioning_not_image(self):
        self.fixture()
        self.assertEqual(self.evaluate(),
                         "IDENTITY_ATLAS_SNOOKER_AUDIENCE_DIAG source=absent atlas=absent "
                         "consumer_parity=matching checkpoint=absent writes=false")

    def test_source_present_but_atlas_old_identifies_config_drift(self):
        self.fixture()
        self.write(self.source, {"chronicles": CH, "snooker": SN})
        self.assertEqual(self.evaluate(),
                         "IDENTITY_ATLAS_SNOOKER_AUDIENCE_DIAG source=present atlas=absent "
                         "consumer_parity=different checkpoint=absent writes=false")

    def test_both_present_proves_only_configuration_not_runtime_behavior(self):
        self.fixture()
        self.write(self.source, {"chronicles": CH, "snooker": SN})
        self.write(self.atlas, {"chronicles": CH, "snooker": SN})
        result = self.evaluate()
        self.assertIn("source=present atlas=present consumer_parity=matching", result)
        self.assertIn("writes=false", result)
        self.assertNotIn("ready", result)
        self.assertNotIn(SN, result)
        self.assertNotIn(CH, result)
        self.assertNotIn("PRIVATE_", result)

    def test_consumer_proofs_same_audience_different_secret_is_not_matching(self):
        self.fixture()
        self.write(self.source, {"chronicles": CH, "snooker": SN})
        self.write(self.atlas, {"chronicles": CH, "snooker": "soc1_" + "c" * 43})
        self.assertIn("consumer_parity=different", self.evaluate())

    def test_duplicate_keys_bad_proof_symlink_or_unsafe_mode_are_blocked(self):
        self.fixture()
        self.source.chmod(0o600)
        self.source.write_text('{"environment":"staging","consumers":{"snooker":"' + SN +
                               '","snooker":"' + CH + '"}}')
        self.source.chmod(0o400)
        with self.assertRaises(audit.AudienceAuditBlocked):
            self.evaluate()
        self.write(self.source, {"snooker": "PRIVATE_MUST_NOT_BE_A_PROOF"})
        with self.assertRaises(audit.AudienceAuditBlocked):
            self.evaluate()
        self.write(self.source, {"snooker": SN})
        self.source.chmod(0o644)
        with self.assertRaises(audit.AudienceAuditBlocked):
            self.evaluate()
        self.source.unlink()
        self.source.symlink_to(self.atlas)
        with self.assertRaises(audit.AudienceAuditBlocked):
            self.evaluate()

    def test_pending_checkpoint_requires_review_even_if_configs_match(self):
        self.fixture()
        (self.state / "atlas-deploy-pending.json").write_text("PRIVATE_NOT_READ")
        with self.assertRaises(audit.AudienceAuditBlocked) as result:
            self.evaluate()
        self.assertEqual(result.exception.stage, "checkpoint")

    def test_untrusted_directory_is_rejected_and_never_followed(self):
        self.fixture()
        with self.assertRaises(audit.AudienceAuditBlocked):
            audit.trusted_directory(self.root, uid=self.uid)
        # /tmp is world writable; the real host only accepts root-owned parents.

    def test_root_operator_denies_unknown_args_and_suppresses_private_errors(self):
        self.fixture()
        out = io.StringIO()
        with patch.object(audit.os, "geteuid", return_value=1000), contextlib.redirect_stdout(out):
            self.assertEqual(audit.main(), 1)
        self.assertIn("stage=authority", out.getvalue())

        out = io.StringIO()
        with patch.object(audit.os, "geteuid", return_value=0), patch.object(audit.sys, "argv", ["probe"]), patch.object(audit, "evaluate", side_effect=RuntimeError("PRIVATE_CONTENT")), contextlib.redirect_stdout(out):
            self.assertEqual(audit.main(), 1)
        self.assertEqual(out.getvalue().strip(),
                         "IDENTITY_ATLAS_SNOOKER_AUDIENCE_BLOCKED stage=unverified")

    def test_operator_ssh_wrapper_uses_fixed_read_only_entrypoint_and_exact_result(self):
        source = (ROOT / "host/inspect-identity-atlas-snooker-audience-over-ssh.sh").read_text()
        subprocess.run(["bash", "-n", str(ROOT / "host/inspect-identity-atlas-snooker-audience-over-ssh.sh")],
                       check=True, timeout=10)
        for required in ("git ls-remote --exit-code", "stale-main", "dirty-checkout",
                         "python -I -B -", "identity_staging_atlas_snooker_audience_readonly.py",
                         "consumer_parity=(matching|different)", "checkpoint=absent writes=false"):
            self.assertIn(required, source)
        for forbidden in ("sudo docker", "docker compose", "chmod", "password=", "echo \"$report\""):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
