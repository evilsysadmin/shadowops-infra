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

    def test_no_published_identity_image_blocks_before_any_provision(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA]), \
             patch.object(op, "source_admitted", return_value={"run_id": 123}), \
             patch.object(op, "identity_ready", return_value=False), \
             patch.object(op, "latest_identity_image_sha",
                          side_effect=op.ActivationBlocked("No published Identity image")), \
             patch.object(op, "run_protected") as dispatch:
            with self.assertRaisesRegex(op.ActivationBlocked, "No published Identity image"):
                op.activate(None)
            dispatch.assert_not_called()

    def test_already_active_identity_does_not_redeploy(self):
        with patch.object(op, "preflight", return_value=(ACTOR, NEW_SHA, OLD_SHA, None)), \
             patch.object(op, "main_sha", return_value=OLD_SHA), \
             patch.object(op, "identity_ready", return_value=True), \
             patch.object(op, "run_protected") as dispatch, \
             contextlib.redirect_stdout(io.StringIO()):
            op.activate(None)
            self.assertEqual([c.args[1] for c in dispatch.call_args_list],
                             ["provision", "publish"])

    def test_full_sequence_deploys_before_publish_and_rechecks_issuer(self):
        with patch.object(op, "preflight", return_value=(ACTOR, NEW_SHA, OLD_SHA, NEW_SHA)), \
             patch.object(op, "main_sha", return_value=OLD_SHA), \
             patch.object(op, "identity_ready", side_effect=[False, True]), \
             patch.object(op, "run_protected") as dispatch, \
             contextlib.redirect_stdout(io.StringIO()):
            op.activate(NEW_SHA)
            self.assertEqual([c.args[1] for c in dispatch.call_args_list],
                             ["provision", "deploy", "publish"])
            self.assertEqual(dispatch.call_args_list[1].args[-1]["source_sha"], NEW_SHA)

    def test_stale_game_main_refuses_publication(self):
        with patch.object(op, "preflight", return_value=(ACTOR, NEW_SHA, OLD_SHA, None)), \
             patch.object(op, "main_sha", return_value=NEW_SHA), \
             patch.object(op, "identity_ready", return_value=True), \
             patch.object(op, "run_protected") as dispatch:
            with self.assertRaisesRegex(op.ActivationBlocked, "Game main advanced"):
                op.activate(None)
            self.assertEqual(dispatch.call_count, 1)


    def test_preflight_proves_exact_game_artifact_and_main_heads_without_mutation(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA, NEW_SHA, OLD_SHA]), \
             patch.object(op, "source_admitted", return_value={"run_id": 42600868589}) as admission, \
             patch.object(op, "identity_ready", return_value=True), \
             patch.object(op, "run_protected") as dispatch, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(op.preflight(None), (ACTOR, NEW_SHA, OLD_SHA, None))
            admission.assert_called_once_with(OLD_SHA)
            dispatch.assert_not_called()
            self.assertIn("writes=false", output.getvalue())
            self.assertIn("ci_run=42600868589", output.getvalue())

    def test_stale_main_or_invalid_ci_artifact_stops_before_provision(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA]), \
             patch.object(op, "source_admitted", side_effect=op.ActivationBlocked("unverified artifact")), \
             patch.object(op, "run_protected") as dispatch:
            with self.assertRaisesRegex(op.ActivationBlocked, "unverified artifact"):
                op.activate(None)
            dispatch.assert_not_called()
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA, NEW_SHA, NEW_SHA]), \
             patch.object(op, "source_admitted", return_value={"run_id": 123}), \
             patch.object(op, "identity_ready", return_value=True), \
             patch.object(op, "run_protected") as dispatch:
            with self.assertRaisesRegex(op.ActivationBlocked, "advanced during"):
                op.activate(None)
            dispatch.assert_not_called()

    def test_downgrade_rejected_at_read_only_preflight(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA]), \
             patch.object(op, "source_admitted", return_value={"run_id": 123}), \
             patch.object(op, "identity_ready", return_value=False), \
             patch.object(op, "deployed_identity_sha", return_value=OLD_SHA), \
             patch.object(op, "no_downgrade", side_effect=op.ActivationBlocked("downgrade")), \
             patch.object(op, "run_protected") as dispatch:
            with self.assertRaisesRegex(op.ActivationBlocked, "downgrade"):
                op.activate(NEW_SHA)
            dispatch.assert_not_called()

    def test_check_cli_is_read_only_even_with_a_candidate_sha(self):
        with patch.object(sys, "argv", [
            "snooker_staging_operator.py", "--check", "--identity-sha", NEW_SHA,
        ]), patch.object(op, "preflight", return_value=(ACTOR, NEW_SHA, OLD_SHA, NEW_SHA)) as check, \
             patch.object(op, "run_protected") as dispatch:
            self.assertEqual(op.main(), 0)
            check.assert_called_once_with(NEW_SHA)
            dispatch.assert_not_called()

    def test_source_admission_reuses_exact_release_gate(self):
        import snooker_source_admission as admission
        with patch.object(op, "api", return_value={"sha": OLD_SHA}) as reader, \
             patch.object(admission, "admit", return_value={"run_id": 33}) as gate:
            self.assertEqual(op.source_admitted(OLD_SHA), {"run_id": 33})
            gate.call_args.args[0].get("/repos/evilsysadmin/snooker-of-matthias/commits/main")
            reader.assert_called_once_with("repos/evilsysadmin/snooker-of-matthias/commits/main")
            self.assertEqual(gate.call_args.args[1], OLD_SHA)
        with patch.object(admission, "admit", side_effect=admission.AdmissionError("bad")):
            with self.assertRaisesRegex(op.ActivationBlocked, "not admissible"):
                op.source_admitted(OLD_SHA)


    def test_image_discovery_requires_real_publish_and_attestation_steps(self):
        def image_run(identifier, sha, **changes):
            return {"id": identifier, "head_sha": sha, "head_branch": "main",
                    "event": "push", "status": "completed", "conclusion": "success", **changes}
        def publication(steps, conclusion="success"):
            return {"jobs": [{"name": "Publish SHA-pinned Identity staging image",
                              "conclusion": conclusion, "steps": [
                                  {"name": name, "status": "completed", "conclusion": "success"}
                                  for name in steps]}]}
        # Latest workflow is green but only unit tests completed; ignore it.
        responses = [
            {"workflow_runs": [
                image_run(6, NEW_SHA),
                image_run(5, "3"*40, event="pull_request"),
                image_run(4, "4"*40),
                image_run(3, OLD_SHA),
            ]},
            publication([]),  # publisher did not upload/attest
            publication({"Run docker/build-push-action@v7"}),  # no attestation
            publication(op.IMAGE_PUBLICATION_STEPS),
        ]
        with patch.object(op, "api", side_effect=responses) as reader:
            self.assertEqual(op.latest_identity_image_sha(), OLD_SHA)
            self.assertEqual(reader.call_count, 4)
            self.assertIn("identity-service.yml", reader.call_args_list[0].args[0])

    def test_image_discovery_fail_closed_if_no_proven_published_image(self):
        row = {"id": 7, "head_sha": NEW_SHA, "head_branch": "main",
               "event": "push", "status": "completed", "conclusion": "success"}
        with patch.object(op, "api", side_effect=[
            {"workflow_runs": [row]},
            {"jobs": [{"name": "Publish SHA-pinned Identity staging image",
                       "conclusion": "skipped", "steps": []}]},
        ]):
            with self.assertRaisesRegex(op.ActivationBlocked, "No published Identity image"):
                op.latest_identity_image_sha()
        with patch.object(op, "api", return_value={"workflow_runs": None}):
            with self.assertRaisesRegex(op.ActivationBlocked, "inventory unavailable"):
                op.latest_identity_image_sha()

    def test_preflight_auto_selects_image_before_provision_and_checks_downgrade(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA, NEW_SHA, OLD_SHA]), \
             patch.object(op, "source_admitted", return_value={"run_id": 123}), \
             patch.object(op, "identity_ready", return_value=False), \
             patch.object(op, "latest_identity_image_sha", return_value=NEW_SHA) as discover, \
             patch.object(op, "deployed_identity_sha", return_value=OLD_SHA), \
             patch.object(op, "no_downgrade") as gate, \
             patch.object(op, "run_protected") as dispatch, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(op.preflight(None), (ACTOR, NEW_SHA, OLD_SHA, NEW_SHA))
            discover.assert_called_once_with()
            gate.assert_called_once_with(OLD_SHA, NEW_SHA)
            dispatch.assert_not_called()
            self.assertIn("identity_image_sha=" + NEW_SHA, output.getvalue())

    def test_explicit_image_override_never_selects_an_unrelated_image(self):
        with patch.object(op, "api", return_value={"login": ACTOR}), \
             patch.object(op, "main_sha", side_effect=[NEW_SHA, OLD_SHA, NEW_SHA, OLD_SHA]), \
             patch.object(op, "source_admitted", return_value={"run_id": 123}), \
             patch.object(op, "identity_ready", return_value=False), \
             patch.object(op, "latest_identity_image_sha") as discover, \
             patch.object(op, "deployed_identity_sha", return_value=OLD_SHA), \
             patch.object(op, "no_downgrade") as gate, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(op.preflight(NEW_SHA), (ACTOR, NEW_SHA, OLD_SHA, NEW_SHA))
            discover.assert_not_called()
            gate.assert_called_once_with(OLD_SHA, NEW_SHA)


    def test_actions_mode_requires_exact_protected_manual_workflow_and_main(self):
        valid = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": op.INFRA,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": NEW_SHA,
            "GITHUB_WORKFLOW_REF": (
                op.INFRA + "/.github/workflows/snooker-staging-activate.yml@refs/heads/main"
            ),
            "GITHUB_RUN_ID": "12345",
            "GH_TOKEN": "testing-placeholder-not-real",
        }
        with patch.dict(op.os.environ, valid, clear=True):
            self.assertEqual(op.actions_dispatch_actor(NEW_SHA), "github-actions[bot]")
        for key, wrong in [
            ("GITHUB_ACTIONS", "false"),
            ("GITHUB_EVENT_NAME", "pull_request"),
            ("GITHUB_REPOSITORY", "evilsysadmin/foreign"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_SHA", OLD_SHA),
            ("GITHUB_WORKFLOW_REF", "foreign/workflow@refs/heads/main"),
            ("GITHUB_RUN_ID", "not-a-run"),
            ("GH_TOKEN", ""),
        ]:
            with self.subTest(key=key), patch.dict(
                op.os.environ, {**valid, key: wrong}, clear=True,
            ), self.assertRaises(op.ActivationBlocked):
                op.actions_dispatch_actor(NEW_SHA)

    def test_actions_mode_avoids_user_api_and_still_revalidates_everything(self):
        valid = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": op.INFRA,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": NEW_SHA,
            "GITHUB_WORKFLOW_REF": (
                op.INFRA + "/.github/workflows/snooker-staging-activate.yml@refs/heads/main"
            ),
            "GITHUB_RUN_ID": "456",
            "GH_TOKEN": "testing-placeholder-not-real",
        }
        with patch.dict(op.os.environ, valid, clear=True), \
             patch.object(op, "main_sha",
                          side_effect=[NEW_SHA, OLD_SHA, NEW_SHA, OLD_SHA]), \
             patch.object(op, "api") as http, \
             patch.object(op, "source_admitted", return_value={"run_id": 123}), \
             patch.object(op, "identity_ready", return_value=True), \
             patch.object(op, "run_protected") as dispatch, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(
                op.preflight(None, github_actions=True),
                ("github-actions[bot]", NEW_SHA, OLD_SHA, None),
            )
            http.assert_not_called()
            dispatch.assert_not_called()

    def test_actions_cli_flag_is_rejected_outside_manual_staging_context(self):
        with patch.dict(op.os.environ, {}, clear=True), \
             patch.object(sys, "argv", [
                 "snooker_staging_operator.py", "--apply", "--github-actions",
             ]), patch.object(op, "main_sha", return_value=NEW_SHA), \
             patch.object(op, "run_protected") as dispatch, \
             contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(op.main(), 1)
            dispatch.assert_not_called()
            self.assertIn("Untrusted Actions dispatch context", output.getvalue())

    def test_actions_cli_check_is_read_only(self):
        with patch.object(sys, "argv", [
            "snooker_staging_operator.py", "--check", "--github-actions",
        ]), patch.object(op, "preflight", return_value=(
            "github-actions[bot]", NEW_SHA, OLD_SHA, None,
        )) as verify, patch.object(op, "run_protected") as dispatch:
            self.assertEqual(op.main(), 0)
            verify.assert_called_once_with(None, github_actions=True)
            dispatch.assert_not_called()

    def test_invalid_identity_sha_rejected_before_any_dispatch(self):
        with patch.object(op, "run_protected") as dispatch:
            with self.assertRaises(op.ActivationBlocked):
                op.activate("main")
            dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
