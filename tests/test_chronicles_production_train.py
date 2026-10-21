"""Daily release train: exact staging accreditation, ordered fail-closed deployment."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import chronicles_production_train as train

SHA = "a" * 40
OTHER = "b" * 40
TOKEN = "mock-read-write-actions-token"


class ReleaseTrainTests(unittest.TestCase):
    def test_schedule_is_eight_am_madrid_with_dst_and_no_push_trigger(self):
        path = ROOT / ".github/workflows/chronicles-production-train.yml"
        data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(data["on"]["schedule"],
                         [{"cron": "0 8 * * *", "timezone": "Europe/Madrid"}])
        self.assertNotIn("push", data["on"])
        self.assertIn("workflow_dispatch", data["on"])
        self.assertEqual(data["permissions"], {"contents": "read"})
        self.assertEqual(data["jobs"]["train"]["permissions"],
                         {"contents": "read", "actions": "write"})
        self.assertEqual(data["jobs"]["train"]["needs"], "contracts")
        self.assertIn("pull_request", data["on"])
        self.assertIn("test_chronicles_production_train.py",
                      str(data["jobs"]["contracts"]["steps"]))
        steps = data["jobs"]["train"]["steps"]
        self.assertIn("chronicles_production_train.py", str(steps))
        self.assertIn("environment", data["jobs"]["train"])
        self.assertEqual(data["jobs"]["train"]["environment"]["name"], "production")

    def test_readonly_preflight_cannot_enter_mutating_train_job(self):
        path = ROOT / ".github/workflows/chronicles-production-train.yml"
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        jobs = workflow["jobs"]
        inputs = workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["dry_run"]["type"], "boolean")
        self.assertEqual(inputs["dry_run"]["default"], "false")
        self.assertEqual(jobs["preflight"]["permissions"],
                         {"contents": "read", "actions": "read"})
        self.assertIn("inputs.dry_run == true", jobs["preflight"]["if"])
        self.assertIn("inputs.dry_run != true", jobs["train"]["if"])
        self.assertEqual(jobs["preflight"]["needs"], "contracts")
        self.assertNotIn("environment", jobs["preflight"])
        self.assertEqual(jobs["preflight"]["env"]["CHRONICLES_TRAIN_DRY_RUN"], "true")
        self.assertIn("chronicles_production_train.py", str(jobs["preflight"]["steps"]))

    def test_preflight_is_read_only_and_never_dispatches(self):
        observed = []
        def select(token, sha):
            observed.append(("admit", token, sha))
            return SHA
        def current(sha, token):
            observed.append(("inspect", sha, token))
            return False
        with patch.object(train, "dispatch", side_effect=AssertionError("no dispatch")):
            result = train.preflight(TOKEN, select=select, current=current,
                                     verify=lambda _: self.fail("not live in prod"),
                                     surface=lambda: observed.append(("public",)) or True)
        self.assertEqual(result["result"], "would-promote")
        self.assertEqual(result["source_sha"], SHA)
        self.assertIsNone(result["api_run"])
        self.assertEqual(observed, [("admit", TOKEN, ""), ("inspect", SHA, TOKEN),
                                    ("public",)])
        result = train.preflight(TOKEN, select=select,
                                 current=lambda *_: True, verify=lambda _: SHA)
        self.assertEqual(result["result"], "unchanged")
        with self.assertRaisesRegex(train.TrainError, "public game audit"):
            train.preflight(TOKEN, select=select,
                            current=lambda *_: True, verify=lambda _: OTHER)
        with self.assertRaisesRegex(train.TrainError, "production degraded"):
            train.preflight(TOKEN, select=select,
                            current=lambda *_: (_ for _ in ()).throw(
                                train.TrainError("production degraded")))

    def test_preflight_verifies_existing_production_when_candidate_differs(self):
        calls = []
        def verify_assets(**kwargs):
            self.assertEqual(kwargs, {"path": "/", "assets": b"/assets/",
                                      "manifest_path": None})
            calls.append("assets")
            return "ok"
        def api(name):
            calls.append(name)
            return True
        self.assertTrue(train.production_surface_ready(
            page=lambda: calls.append("page") or "ok",
            assets=verify_assets, api=api,
            sso=lambda: calls.append("sso") or True))
        self.assertEqual(calls, ["page", "assets", "health", "ready", "cors", "sso"])
        for condition in ("page", "assets", "api", "sso"):
            with self.subTest(condition=condition):
                self.assertFalse(train.production_surface_ready(
                    page=lambda: "tls_error" if condition == "page" else "ok",
                    assets=lambda **_: "broken" if condition == "assets" else "ok",
                    api=lambda _: condition != "api",
                    sso=lambda: condition != "sso"))
        progress = {}
        with patch.object(train, "dispatch", side_effect=AssertionError("no dispatch")):
            with self.assertRaisesRegex(train.TrainError, "current production surface unhealthy"):
                train.preflight(TOKEN, select=lambda *_: SHA,
                                current=lambda *_: False, surface=lambda: False,
                                progress=progress)
        self.assertEqual(progress["stage"], "existing-production-readiness")
        self.assertEqual(progress["source_sha"], SHA)
        with patch.object(train, "dispatch", side_effect=AssertionError("no dispatch")):
            result = train.preflight(
                TOKEN, select=lambda *_: SHA, current=lambda *_: True,
                verify=lambda _: SHA, surface=lambda: self.fail("no extra surface read"))
        self.assertEqual(result["result"], "unchanged")

    def test_staging_selection_uses_live_manifest_not_current_main(self):
        called = []
        def admit(sha, token):
            called.append((sha, token))
        self.assertEqual(
            train.select_sha(TOKEN, live=lambda: SHA,
                             gate=admit, api_build=lambda: SHA), SHA)
        self.assertEqual(called, [(SHA, TOKEN)])
        self.assertEqual(
            train.select_sha(TOKEN, pinned=OTHER, live=lambda: self.fail("live must not be read"),
                             gate=admit, api_build=lambda: self.fail("pinned source is historical")), OTHER)
        self.assertEqual(called[-1], (OTHER, TOKEN))
        for pinned in ("deadbeef", "x" * 40, "A" * 40):
            with self.subTest(pinned=pinned), self.assertRaises(train.TrainError):
                train.select_sha(TOKEN, pinned=pinned, live=lambda: SHA, gate=admit)
        with self.assertRaises(train.TrainError):
            train.select_sha("")

    def test_live_staging_api_drift_blocks_scheduled_candidate_before_admission(self):
        called = []
        for build in (None, OTHER):
            with self.subTest(public_api_build=build):
                with self.assertRaisesRegex(train.TrainError, "staging API live source"):
                    train.select_sha(
                        TOKEN, live=lambda: SHA, api_build=lambda: build,
                        gate=lambda *args: called.append(args),
                    )
        self.assertEqual(called, [])
        # A candidate that is not even a full SHA remains inadmissible.
        with self.assertRaisesRegex(train.TrainError, "live staging SHA invalid"):
            train.select_sha(TOKEN, live=lambda: "not-a-sha",
                             api_build=lambda: self.fail("invalid manifest"))
        # An explicit historical manual SHA uses the same trusted source CI
        # and staging receipts, but must not depend on the current live API.
        self.assertEqual(
            train.select_sha(TOKEN, pinned=OTHER,
                             api_build=lambda: self.fail("historical manual override"),
                             gate=lambda sha, token: called.append((sha, token))), OTHER)
        self.assertEqual(called, [(OTHER, TOKEN)])

    def test_unchanged_prod_only_skipped_if_receipts_and_api_are_healthy(self):
        self.assertFalse(train.deployed_sha(
            SHA, TOKEN, manifest=lambda: {"build": OTHER},
            probe=lambda _: self.fail("probe unnecessary"),
            receipt=lambda *args: self.fail("receipt unnecessary")))
        called = []
        self.assertTrue(train.deployed_sha(
            SHA, TOKEN, manifest=lambda: {"build": SHA},
            probe=lambda path: called.append(path) or True,
            receipt=lambda sha, kind, token: called.append(kind) or True))
        self.assertEqual(called, ["health", "ready", "cors", "production-api", "production-pages"])
        with self.assertRaisesRegex(train.TrainError, "not healthy"):
            train.deployed_sha(SHA, TOKEN, manifest=lambda: {"build": SHA},
                               probe=lambda p: p != "ready")
        with self.assertRaisesRegex(train.TrainError, "trusted receipts"):
            train.deployed_sha(SHA, TOKEN, manifest=lambda: {"build": SHA},
                               probe=lambda _: True, receipt=lambda *_: False)

    def test_dispatch_is_exact_sha_and_returns_correlated_run_id(self):
        calls = []
        def call(method, path, token, payload):
            calls.append((method, path, token, payload))
            return {"workflow_run_id": len(calls) + 10}
        self.assertEqual(train.dispatch("api", SHA, TOKEN, call=call), 11)
        self.assertEqual(train.dispatch("pages", SHA, TOKEN, call=call), 12)
        self.assertEqual([c[0] for c in calls], ["POST", "POST"])
        self.assertEqual(calls[0][3]["inputs"], {
            "action": "deploy", "environment": "production",
            "source_sha": SHA, "only_if_new": "false"})
        self.assertEqual(calls[1][3]["inputs"], {
            "environment": "production", "source_sha": SHA, "only_if_new": "false"})
        self.assertTrue(all(c[3]["ref"] == "main" and
                            c[3]["return_run_details"] is True for c in calls))
        with self.assertRaisesRegex(train.TrainError, "attributable"):
            train.dispatch("api", SHA, TOKEN, call=lambda *a: {})
        with self.assertRaises(train.TrainError):
            train.dispatch("foreign", SHA, TOKEN, call=call)

    def test_run_wait_rejects_wrong_job_or_failure(self):
        payload = {"id": 42, "path": ".github/workflows/" + train.API_WORKFLOW,
                   "event": "workflow_dispatch", "head_branch": "main",
                   "repository": {"full_name": train.INFRA},
                   "status": "completed", "conclusion": "success"}
        train.wait_run("api", 42, TOKEN, call=lambda *a: dict(payload), attempts=1)
        for changes in (
            {"conclusion": "failure"},
            {"path": ".github/workflows/other.yml"},
            {"event": "pull_request"},
            {"head_branch": "feature"},
            {"id": 41},
        ):
            with self.subTest(changes=changes), self.assertRaises(train.TrainError):
                train.wait_run("api", 42, TOKEN,
                               call=lambda *a: {**payload, **changes}, attempts=1)
        with self.assertRaisesRegex(train.TrainError, "timed out"):
            train.wait_run("api", 42, TOKEN,
                           call=lambda *a: {**payload, "status": "in_progress"},
                           sleep=lambda _: None, attempts=1)

    def test_same_sha_is_idempotent_no_dispatch(self):
        data = train.run(TOKEN, select=lambda *_: SHA, current=lambda *_: True,
                         start=lambda *a: self.fail("no rerun on unchanged prod"),
                         verify=lambda _: SHA)
        self.assertEqual(data["result"], "unchanged")
        self.assertIsNone(data["api_run"])
        with self.assertRaisesRegex(train.TrainError, "public game audit"):
            train.run(TOKEN, select=lambda *_: SHA, current=lambda *_: True,
                      start=lambda *a: self.fail("no rerun on unhealthy same SHA"),
                      verify=lambda _: OTHER)

    def test_scheduled_release_blocks_degraded_existing_production_before_api(self):
        for condition in (False, None):
            with self.subTest(condition=condition):
                progress = {}
                dispatched = []
                with self.assertRaisesRegex(train.TrainError, "before scheduled promotion"):
                    train.run(
                        TOKEN, select=lambda *_: SHA,
                        current=lambda *_: False,
                        scheduled=True, surface=lambda: condition,
                        start=lambda *args: dispatched.append(args),
                        progress=progress,
                    )
                self.assertEqual(dispatched, [])
                self.assertEqual(progress["source_sha"], SHA)
                self.assertEqual(progress["stage"], "existing-production-readiness")
                self.assertNotIn("api_run", progress)

    def test_scheduled_release_checks_current_production_before_dispatch(self):
        order = []
        def start(kind, sha, token):
            order.append("start-" + kind)
            return 51 if kind == "api" else 52
        result = train.run(
            TOKEN, select=lambda *_: SHA,
            current=lambda *_: False,
            scheduled=True,
            surface=lambda: order.append("production-health") or True,
            start=start,
            wait=lambda *args: None,
            receipt=lambda *args: None,
            probe=lambda *_: True,
            api_build=lambda: SHA,
            verify=lambda _: SHA,
        )
        self.assertEqual(result["result"], "promoted")
        self.assertEqual(order, ["production-health", "start-api", "start-pages"])

    def test_manual_hotfix_may_repair_degraded_production_explicitly(self):
        launches = []
        train.run(
            TOKEN, pinned=SHA, select=lambda *_: SHA,
            current=lambda *_: False,
            scheduled=False,
            surface=lambda: self.fail("manual hotfix must not be gated on old health"),
            start=lambda kind, *_: launches.append(kind) or len(launches),
            wait=lambda *_: None,
            receipt=lambda *_: None,
            probe=lambda *_: True,
            api_build=lambda: SHA,
            verify=lambda _: SHA,
        )
        self.assertEqual(launches, ["api", "pages"])

    def test_unchanged_scheduled_sha_uses_existing_complete_audit(self):
        actions = []
        state = {}
        result = train.run(
            TOKEN, select=lambda *_: SHA, current=lambda *_: True,
            scheduled=True,
            surface=lambda: self.fail("no secondary health check on unchanged SHA"),
            start=lambda *_: self.fail("no deployment"),
            verify=lambda *_: actions.append("full-audit") or SHA,
            progress=state,
        )
        self.assertEqual(result["result"], "unchanged")
        self.assertEqual(actions, ["full-audit"])
        self.assertEqual(state["stage"], "completed")

    def test_new_sha_orders_api_then_pages_and_public_audit(self):
        steps = []
        def start(kind, sha, token):
            steps.append("dispatch-" + kind)
            self.assertEqual((sha, token), (SHA, TOKEN))
            return 11 if kind == "api" else 12
        def wait(kind, run_id, token):
            steps.append("wait-" + kind)
        def receipt(sha, kind, token, run_id):
            self.assertEqual(run_id, 11 if kind == "api" else 12)
            steps.append("receipt-" + kind)
        def probe(path):
            steps.append("api-" + path)
            return True
        def verify(token):
            steps.append("final-audit")
            return SHA
        data = train.run(TOKEN, select=lambda *_: SHA, current=lambda *_: False,
                         start=start, wait=wait, receipt=receipt,
                         probe=probe, verify=verify,
                         api_build=lambda: steps.append("api-build") or SHA)
        self.assertEqual(data["result"], "promoted")
        self.assertEqual((data["api_run"], data["pages_run"]), (11, 12))
        self.assertEqual(steps, ["dispatch-api", "wait-api", "receipt-api",
                                 "api-health", "api-ready", "api-cors",
                                 "api-build", "dispatch-pages", "wait-pages", "receipt-pages",
                                 "final-audit"])

    def test_api_drift_blocks_pages_even_after_green_api_and_receipt(self):
        for live in (None, OTHER):
            actions = []
            state = {}
            def start(kind, sha, token):
                actions.append(kind)
                self.assertEqual(sha, SHA)
                return 42
            with self.subTest(live=live):
                with self.assertRaisesRegex(train.TrainError, "source SHA"):
                    train.run(TOKEN, select=lambda *_: SHA,
                              current=lambda *_: False,
                              start=start, wait=lambda *_: None,
                              receipt=lambda *_: None,
                              probe=lambda _: True, api_build=lambda: live,
                              verify=lambda _: SHA, progress=state)
                self.assertEqual(actions, ["api"])
                self.assertEqual(state["stage"], "api-public-ready")
                self.assertEqual(state["api_run"], 42)
                self.assertNotIn("pages_run", state)

    def test_new_child_receipt_requires_same_workflow_run(self):
        calls = []
        def receipt(sha, kind, token, *, expected_run_id=None):
            calls.append((sha, kind, token, expected_run_id))
            return expected_run_id == 123
        train.receipt_after(SHA, "api", TOKEN, 123,
                            receipt=receipt, sleep=lambda _: None)
        self.assertEqual(calls, [(SHA, "production-api", TOKEN, 123)])
        with self.assertRaisesRegex(train.TrainError, "no trusted"):
            train.receipt_after(SHA, "api", TOKEN, 124,
                                receipt=receipt, sleep=lambda _: None)
        self.assertEqual(len(calls), 7)
        for invalid in (None, -1, 0, True, "123"):
            with self.subTest(invalid=invalid), self.assertRaises(train.TrainError):
                train.receipt_after(SHA, "api", TOKEN, invalid,
                                    receipt=receipt, sleep=lambda _: None)

    def test_partial_api_success_is_journaled_before_pages_failure(self):
        stages = {"result": "blocked", "stage": "starting",
                  "source_sha": None, "api_run": None, "pages_run": None}
        actions = []
        def start(kind, sha, token):
            actions.append(kind)
            return 101 if kind == "api" else 102
        def wait(kind, run_id, token):
            if kind == "pages":
                raise train.TrainError("pages workflow failed")
        with self.assertRaisesRegex(train.TrainError, "pages workflow failed"):
            train.run(TOKEN, select=lambda *_: SHA, current=lambda *_: False,
                      start=start, wait=wait, receipt=lambda *_: None,
                      probe=lambda _: True, verify=lambda _: SHA,
                      api_build=lambda: SHA, progress=stages)
        self.assertEqual(actions, ["api", "pages"])
        self.assertEqual(stages["source_sha"], SHA)
        self.assertEqual(stages["api_run"], 101)
        self.assertEqual(stages["pages_run"], 102)
        self.assertEqual(stages["stage"], "pages-running")
        self.assertEqual(stages["result"], "blocked")

    def test_api_failure_records_api_id_without_dispatching_pages(self):
        stages = {}
        def failed_wait(kind, run_id, token):
            raise train.TrainError("API failed")
        with self.assertRaises(train.TrainError):
            train.run(TOKEN, select=lambda *_: SHA, current=lambda *_: False,
                      start=lambda kind, *_: 15, wait=failed_wait,
                      progress=stages)
        self.assertEqual(stages["stage"], "api-running")
        self.assertEqual(stages["api_run"], 15)
        self.assertNotIn("pages_run", stages)

    def test_main_persists_failed_journal_without_any_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            environ = {
                "GITHUB_REPOSITORY": train.INFRA,
                "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GH_TOKEN": "extremely-secret-token",
                "RUNNER_TEMP": tmp,
            }
            def fail(token, pinned, *, progress):
                self.assertEqual(token, environ["GH_TOKEN"])
                train.progress_stage(progress, "pages-running",
                                     source_sha=SHA, api_run=99, pages_run=100)
                raise train.TrainError("pages check failed")
            with patch.dict(os.environ, environ), patch.object(train, "run", side_effect=fail):
                self.assertEqual(train.main(), 1)
            artifact = json.loads((Path(tmp) / "chronicles-production-train.json").read_text())
            self.assertEqual(artifact, {
                "schema": 1, "result": "blocked", "stage": "pages-running",
                "source_sha": SHA, "api_run": 99, "pages_run": 100,
            })
            self.assertNotIn(environ["GH_TOKEN"], json.dumps(artifact))

    def test_preflight_failure_records_stage_and_uploads_artifact_always(self):
        path = ROOT / ".github/workflows/chronicles-production-train.yml"
        spec = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        for job_name in ("train", "preflight"):
            names = [step for step in spec["jobs"][job_name]["steps"]
                     if step.get("uses") == "actions/upload-artifact@v4"]
            self.assertEqual(len(names), 1)
            self.assertEqual(names[0]["if"], "always()")
            self.assertEqual(names[0]["with"]["if-no-files-found"], "error")
        state = {}
        with self.assertRaisesRegex(train.TrainError, "admission failed"):
            train.preflight(TOKEN, select=lambda *_: (_ for _ in ()).throw(
                train.TrainError("admission failed")), progress=state)
        self.assertEqual(state["stage"], "candidate-admission")

    def test_failure_never_dispatches_pages(self):
        called = []
        def start(kind, *rest):
            called.append(kind)
            return 11
        for fail_at in ("wait", "receipt", "api"):
            called.clear()
            def wait(kind, *args):
                if fail_at == "wait":
                    raise train.TrainError("API failed")
            def receipt(*args):
                if fail_at == "receipt":
                    raise train.TrainError("no API receipt")
            def probe(*args):
                return fail_at != "api"
            with self.subTest(fail_at=fail_at), self.assertRaises(train.TrainError):
                train.run(TOKEN, select=lambda *_: SHA, current=lambda *_: False,
                          start=start, wait=wait, receipt=receipt,
                          probe=probe, verify=lambda _: SHA)
            self.assertEqual(called, ["api"])


if __name__ == "__main__":
    unittest.main()
