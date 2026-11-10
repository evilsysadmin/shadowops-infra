import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_identity_public_probe as probe
import snooker_staging_operator as operator
import snooker_staging_publish as publish

SHA = "a" * 40


class PublicReadinessTests(unittest.TestCase):
    def test_ready_login_and_public_release_are_reported_without_secrets(self):
        self.assertEqual(
            probe.inspect(login_probe=lambda: None, release_probe=lambda: SHA),
            "SNOOKER_IDENTITY_PUBLIC_CHECK login=snooker-target-present release_sha=" + SHA,
        )

    def test_missing_login_target_and_unreachable_release_are_finite(self):
        def missing():
            raise publish.ProvisionError("PRIVATE identity credential")

        def unreachable():
            raise operator.ActivationBlocked("PRIVATE host error")

        self.assertEqual(
            probe.inspect(login_probe=missing, release_probe=unreachable),
            "SNOOKER_IDENTITY_PUBLIC_CHECK login=unavailable-or-unrecognized "
            "release_sha=unavailable",
        )

    def test_release_receipt_does_not_make_login_target_ready(self):
        def missing():
            raise publish.ProvisionError("Does not recognize Snooker")
        self.assertEqual(
            probe.inspect(login_probe=missing, release_probe=lambda: SHA),
            "SNOOKER_IDENTITY_PUBLIC_CHECK login=unavailable-or-unrecognized release_sha=" + SHA,
        )

    def test_login_target_does_not_prove_public_release(self):
        self.assertEqual(
            probe.inspect(login_probe=lambda: None, release_probe=lambda: "non-sha PRIVATE"),
            "SNOOKER_IDENTITY_PUBLIC_CHECK login=snooker-target-present release_sha=unavailable",
        )

    def test_cli_rejects_arguments_and_does_not_print_private_exceptions(self):
        out = io.StringIO()
        err = io.StringIO()
        with patch.object(sys, "argv", ["probe", "anything"]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(probe.main(), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue().strip(),
                         "SNOOKER_IDENTITY_PUBLIC_PROBE_BLOCKED reason=arguments")

        with patch.object(sys, "argv", ["probe"]), patch.object(
            probe, "inspect", side_effect=RuntimeError("PRIVATE token")
        ), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(probe.main(), 1)
        self.assertNotIn("PRIVATE", err.getvalue())
        self.assertIn("reason=unexpected", err.getvalue())


if __name__ == "__main__":
    unittest.main()
