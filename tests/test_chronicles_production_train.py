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
                                     verify=lambda _: self.fail("not live in prod"))
        self.assertEqual(result["result"], "would-promote")
        self.assertEqual(result["source_sha"], SHA)
        self.assertIsNone(result["api_run"])
        self.assertEqual(observed, [("admit", TOKEN, ""), ("inspect", SHA, TOKEN)])
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

    def test_staging_selection_uses_live_manifest_not_current_main(self):
        called = []
        def admit(sha, token):
            called.append((sha, token))
        self.assertEqual(
            train.select_sha(TOKEN, live=lambda: SHA, gate=admit), SHA)
        self.assertEqual(called, [(SHA, TOKEN)])
        self.assertEqual(
            train.select_sha(TOKEN, pinned=OTHER, live=lambda: self.fail("live must not be read"),
                             gate=admit), OTHER)
        self.assertEqual(called[-1], (OTHER, TOKEN))
        for pinned in ("deadbeef", "x" * 40, "A" * 40):
            with self.subTest(pinned=pinned), self.assertRaises(train.TrainError):
                train.select_sha(TOKEN, pinned=pinned, live=lambda: SHA, gate=admit)
        with self.assertRaises(train.TrainError):
            train.select_sha("")

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

    def test_new_sha_orders_api_then_pages_and_public_audit(self):
        steps = []
        def start(kind, sha, token):
            steps.append("dispatch-" + kind)
            self.assertEqual((sha, token), (SHA, TOKEN))
            return 11 if kind == "api" else 12
        def wait(kind, run_id, token):
            steps.append("wait-" + kind)
        def receipt(sha, kind, token):
            steps.append("receipt-" + kind)
        def probe(path):
            steps.append("api-" + path)
            return True
        def verify(token):
            steps.append("final-audit")
            return SHA
        data = train.run(TOKEN, select=lambda *_: SHA, current=lambda *_: False,
                         start=start, wait=wait, receipt=receipt,
                         probe=probe, verify=verify)
        self.assertEqual(data["result"], "promoted")
        self.assertEqual((data["api_run"], data["pages_run"]), (11, 12))
        self.assertEqual(steps, ["dispatch-api", "wait-api", "receipt-api",
                                 "api-health", "api-ready", "api-cors",
                                 "dispatch-pages", "wait-pages", "receipt-pages",
                                 "final-audit"])

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
                      progress=stages)
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
