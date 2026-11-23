"""Offline, deterministic tests for private GitHub Actions Prometheus exporter."""
import importlib.util
from pathlib import Path
import sys
import unittest
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "observability/chronicles-deploys/exporter.py"
spec = importlib.util.spec_from_file_location("chronicles_deploy_exporter", PATH)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def run(run_id, title, event, created, conclusion="success",
        status="completed", duration=60):
    return {
        "id": run_id, "display_title": title, "event": event,
        "created_at": f"2026-11-23T08:{created:02d}:00Z",
        "run_started_at": f"2026-11-23T08:{created:02d}:00Z",
        "updated_at": f"2026-11-23T08:{created + duration // 60:02d}:00Z",
        "status": status, "conclusion": conclusion,
    }


class ExporterTests(unittest.TestCase):
    def test_no_false_production_classification_for_pages_manual_dispatch(self):
        self.assertEqual(mod.environment("pages", run(1, "ShadowOps Pages",
                                                     "workflow_dispatch", 1)),
                         "unspecified")
        self.assertEqual(mod.environment("pages", run(1, "ShadowOps Pages",
                                                     "push", 1)), "staging")
        self.assertIsNone(mod.environment("pages", run(1, "CI",
                                                      "pull_request", 1)))
        self.assertEqual(mod.environment("train", run(1, "train", "schedule", 1)),
                         "production")
        self.assertEqual(mod.environment("api", run(1, "Chronicles API · PRODUCTION",
                                                   "workflow_dispatch", 1)),
                         "production")
        self.assertIsNone(mod.environment("api", run(1, "undetermined",
                                                    "workflow_dispatch", 1)))

    def test_last_completed_success_running_and_duration(self):
        data = {
            "train": {"workflow_runs": [
                run(5, "train", "schedule", 12, status="in_progress",
                    conclusion=None),
                run(4, "train", "schedule", 10, conclusion="failure"),
                run(3, "train", "schedule", 6, conclusion="success"),
            ]},
            "api": {"workflow_runs": [
                run(7, "Chronicles API · PRODUCTION", "workflow_dispatch", 11),
                run(8, "Chronicles API · STAGING", "push", 9),
            ]},
            "pages": {"workflow_runs": [
                run(9, "Pages", "workflow_dispatch", 8),
            ]},
        }
        result = mod.render_runs(data)
        self.assertIn('shadowops_deploy_running{component="train",environment="production"} 1', result)
        self.assertIn('shadowops_deploy_last_run_id{component="train",environment="production"} 5', result)
        self.assertIn('shadowops_deploy_last_completed_success{component="train",environment="production"} 0', result)
        self.assertIn('shadowops_deploy_last_result{component="train",environment="production",result="failure"} 1', result)
        self.assertIn('shadowops_deploy_last_completed_duration_seconds{component="train",environment="production"} 60', result)
        self.assertIn('shadowops_deploy_last_success_timestamp_seconds{component="train",environment="production"} ', result)
        self.assertNotIn('shadowops_deploy_last_result{component="train",environment="production",result="success"}', result)
        self.assertIn('shadowops_deploy_last_run_id{component="pages",environment="unspecified"} 9', result)

    def test_no_duplicate_time_series_on_newer_failed_run(self):
        data = {name: {"workflow_runs": []} for name in mod.WORKFLOWS}
        data["train"]["workflow_runs"] = [
            run(9, "train", "schedule", 11, conclusion="failure"),
            run(8, "train", "schedule", 10, conclusion="success"),
        ]
        result = mod.render_runs(data)
        self.assertEqual(result.count("shadowops_deploy_last_completed_success{"), 1)
        self.assertEqual(result.count("shadowops_deploy_last_success_timestamp_seconds{"), 1)

    def test_unavailable_api_exposes_failure_and_preserves_previous_metrics(self):
        state = mod.State()
        payloads = {kind: {"workflow_runs": []} for kind in mod.WORKFLOWS}
        payloads["train"]["workflow_runs"] = [run(5, "train", "schedule", 2)]
        self.assertTrue(state.poll(fetch=lambda k, token: payloads[k], now=lambda: 100))
        self.assertIn("shadowops_exporter_up 1", state.metrics())
        def broken(*_):
            raise urllib.error.HTTPError("https://api.github.com/", 403,
                                         "forbidden", None, None)
        self.assertFalse(state.poll(fetch=broken, now=lambda: 200))
        self.assertIn("shadowops_exporter_up 0", state.metrics())
        self.assertIn("shadowops_exporter_last_success_timestamp_seconds 100", state.metrics())
        self.assertIn('shadowops_deploy_last_run_id{component="train",environment="production"} 5',
                      state.metrics())

    def test_malformed_data_is_fail_closed(self):
        state = mod.State()
        self.assertFalse(state.poll(fetch=lambda *_: {"workflow_runs": None},
                                    now=lambda: 10))
        self.assertIn("shadowops_exporter_up 0", state.metrics())
        self.assertIsNone(mod.timestamp("invalid date"))
        self.assertIsNone(mod.timestamp(None))
        self.assertIsNone(mod.environment("other", {"event": "push"}))

    def test_query_paths_are_fixed_and_credentials_not_exported(self):
        self.assertEqual(len(mod.WORKFLOWS), 3)
        self.assertTrue(all(".." not in path for path in mod.WORKFLOWS.values()))
        self.assertNotIn("Bearer", mod.State().metrics())
        self.assertNotIn("Authorization", mod.State().metrics())


if __name__ == "__main__":
    unittest.main()
