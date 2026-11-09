import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, call

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import snooker_staging_operator as op

OLD_SHA = "1" * 40
NEW_SHA = "2" * 40
ACTOR = "operator-name"


def run(run_id, actor=ACTOR, sha=NEW_SHA):
    return {"id": run_id, "actor": {"login": actor},
            "event": "workflow_dispatch", "head_sha": sha}


class OperatorTests(unittest.TestCase):
    def test_default_is_read_only_plan_and_never_calls_gh(self):
        with patch.object(sys, "argv", ["snooker_staging_operator.py"]), \
             patch.object(op, "gh") as transport, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(op.main(), 0)
        transport.assert_not_called()
        self.assertIn("writes=false", output.getvalue())

    def test_select_run_requires_unique_new_actor_and_exact_head(self):
        rows = [run(2), run(1), run(4, actor="foreign"), run(5, sha=OLD_SHA)]
        self.assertEqual(op.select_new_run(rows, {1}, ACTOR, NEW_SHA)["id"], 2)
        self.assertIsNone(op.select_new_run(rows, {1, 2}, ACTOR, NEW_SHA))
        with self.assertRaises(op.ActivationBlocked):
            op.select_new_run(rows + [run(3)], {1}, ACTOR, NEW_SHA)

    def test_protected_job_cannot_be_skipped_or_confused_with_green_contracts(self):
        with patch.object(op, "api", return_value={"jobs": [
            {"name": "contracts", "conclusion": "success"},
            {"name": "publish", "conclusion": "skipped"},
        ]}):
            with self.assertRaises(op.ActivationBlocked):
                op.require_job_success(10, "publish")
        with patch.object(op, "api", return_value={"jobs": [
            {"name": "publish", "conclusion": "success"},
        ]}):
            op.require_job_success(10, "publish")
        with patch.object(op, "api", return_value={"jobs": [
            {"name": "publish", "conclusion": "success"},
            {"name": "publish", "conclusion": "success"},
        ]}):
            with self.assertRaises(op.ActivationBlocked):
                op.require_job_success(10, "publish")

    def test_identity_candidate_rejects_downgrade_or_missing_snooker_contract(self):
        with patch.object(op, "api", side_effect=[
            {"status": "ahead"}, {"status": "identical"},
        ]) as reader:
            op.no_downgrade(NEW_SHA, NEW_SHA)
            self.assertEqual(reader.call_count, 2)
        with patch.object(op, "api", return_value={"status": "behind"}):
            with self.assertRaises(op.ActivationBlocked):
                op.no_downgrade(OLD_SHA, NEW_SHA)
        with self.assertRaises(op.ActivationBlocked):
            op.no_downgrade("not-a-sha", NEW_SHA)

    def test_missing_identity_sha_stops_after_provision_not_before(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA]), \
             patch.object(op, "identity_ready", return_value=False), \
             patch.object(op, "run_protected") as dispatch:
            with self.assertRaisesRegex(op.ActivationBlocked, "Supply --identity-sha"):
                op.activate(None)
            self.assertEqual(dispatch.call_count, 1)
            self.assertEqual(dispatch.call_args.args[:2], (op.IDENTITY_WORKFLOW, "provision"))

    def test_already_active_identity_does_not_redeploy(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA, OLD_SHA]), \
             patch.object(op, "identity_ready", return_value=True), \
             patch.object(op, "run_protected") as dispatch, \
             contextlib.redirect_stdout(io.StringIO()):
            op.activate(None)
            self.assertEqual([c.args[1] for c in dispatch.call_args_list],
                             ["provision", "publish"])

    def test_full_sequence_deploys_before_publish_and_rechecks_issuer(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA, OLD_SHA]), \
             patch.object(op, "deployed_identity_sha", return_value=OLD_SHA), \
             patch.object(op, "no_downgrade") as guard, \
             patch.object(op, "identity_ready", side_effect=[False, True]), \
             patch.object(op, "run_protected") as dispatch, \
             contextlib.redirect_stdout(io.StringIO()):
            op.activate(NEW_SHA)
            guard.assert_called_once_with(OLD_SHA, NEW_SHA)
            self.assertEqual([c.args[1] for c in dispatch.call_args_list],
                             ["provision", "deploy", "publish"])
            self.assertEqual(dispatch.call_args_list[1].args[-1]["source_sha"], NEW_SHA)

    def test_stale_game_main_refuses_publication(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA, NEW_SHA]), \
             patch.object(op, "identity_ready", return_value=True), \
             patch.object(op, "run_protected") as dispatch:
            with self.assertRaisesRegex(op.ActivationBlocked, "Game main advanced"):
                op.activate(None)
            self.assertEqual(dispatch.call_count, 1)

    def test_invalid_identity_sha_rejected_before_any_dispatch(self):
        with patch.object(op, "run_protected") as dispatch:
            with self.assertRaises(op.ActivationBlocked):
                op.activate("main")
            dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
