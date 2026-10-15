"""Private, atomic staging-receipt persistence tests (no OCI calls)."""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from oci_staging_deploy import DeployError, _write_verified_receipt, run_staging
from staging_read_smoke import SmokeError

from test_oci_staging_deploy import (
    COMPOSE, DIGEST, ENV, SHA, Runner, fake_host_preflight,
)

RUN_ID = 38812775390


class ReceiptContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "chronicles-state"
        self.state.mkdir(mode=0o700)

    def test_receipt_compatible_with_shadowops_staging_ledger(self):
        when = datetime(2026, 10, 16, 12, 30, 45, tzinfo=timezone.utc)
        destination = _write_verified_receipt(
            self.state, SHA, DIGEST, RUN_ID, now=lambda: when
        )
        self.assertEqual(destination.name, "last-verified-staging-receipt.json")
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(
            json.loads(destination.read_text()),
            {
                "repository": "evilsysadmin/chronicles-of-matthias",
                "service": "chronicles-api",
                "environment": "staging",
                "sha": SHA,
                "digest": DIGEST,
                "workflowRunId": RUN_ID,
                "healthPassed": True,
                "smokePassed": True,
                "deployedAt": "2026-10-16T12:30:45Z",
            },
        )
        self.assertEqual(
            list(self.state.glob(".receipt-*.json")), [],
            "temporary receipt files must not remain after successful replace",
        )

    def test_check_only_never_generates_receipt(self):
        result = run_staging(
            sha=SHA, run_id=RUN_ID, env=ENV,
            deploy=False, runner=Runner(), architecture="aarch64",
            host_preflight=fake_host_preflight, lock_dir=self.state,
        )
        self.assertEqual(result, "CHRONICLES_OCI_STAGING_PREFLIGHT_OK")
        self.assertFalse(
            (self.state / "last-verified-staging-receipt.json").exists()
        )

    def test_failed_smoke_preserves_prior_verified_receipt(self):
        prior = _write_verified_receipt(
            self.state, "c" * 40, "sha256:" + "d" * 64, 1,
            now=lambda: datetime(2026, 10, 15, tzinfo=timezone.utc),
        )
        original = prior.read_bytes()

        def fail_smoke(*_args):
            raise SmokeError("synthetic smoke failed")

        with self.assertRaisesRegex(DeployError, "synthetic staging HTTP smoke failed"):
            run_staging(
                sha=SHA, run_id=RUN_ID, env=ENV, deploy=True,
                runner=Runner(), architecture="aarch64",
                host_preflight=fake_host_preflight, lock_dir=self.state,
                token_reader=lambda p: "alice-token" if "owner" in p else "bob-token",
                smoke=fail_smoke,
            )
        self.assertEqual(prior.read_bytes(), original)

    def test_refuse_to_replace_symlink_receipt(self):
        other = self.state / "other.json"
        other.write_text("never overwrite")
        target = self.state / "last-verified-staging-receipt.json"
        target.symlink_to(other)
        with self.assertRaisesRegex(DeployError, "unsafe staging receipt"):
            _write_verified_receipt(self.state, SHA, DIGEST, RUN_ID)
        self.assertEqual(other.read_text(), "never overwrite")

    def test_receipt_requires_aware_utc_timestamp(self):
        with self.assertRaisesRegex(DeployError, "timezone"):
            _write_verified_receipt(
                self.state, SHA, DIGEST, RUN_ID,
                now=lambda: datetime(2026, 10, 16, 12, 30),
            )


if __name__ == "__main__":
    unittest.main()
