#!/usr/bin/env python3
"""Read-only GitHub Actions exporter for private/LAN Prometheus scraping.

Never dispatches workflows, stores credentials, or exposes GitHub response bodies.
Only bounded, exact workflow paths in evilsysadmin/shadowops-infra are queried.
"""
from __future__ import annotations

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import time
import urllib.error
import urllib.request

REPO = "evilsysadmin/shadowops-infra"
WORKFLOWS = {
    "train": "chronicles-production-train.yml",
    "api": "chronicles-api-staging.yml",
    "pages": "chronicles-pages-release.yml",
}
GITHUB = f"https://api.github.com/repos/{REPO}/actions/workflows/"
HEADERS = {"Accept": "application/vnd.github+json",
           "User-Agent": "ShadowOps-LAN-Deploy-Metrics/1",
           "X-GitHub-Api-Version": "2022-11-28"}


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return date.timestamp() if date.tzinfo else None
    except ValueError:
        return None


def environment(component, run):
    if not isinstance(run, dict) or run.get("event") == "pull_request":
        return None
    event = run.get("event")
    if component == "train":
        return "production" if event in ("schedule", "workflow_dispatch") else None
    if component == "api":
        title = str(run.get("display_title") or "").upper()
        if "PRODUCTION" in title:
            return "production"
        if "STAGING" in title:
            return "staging"
        return None
    if component == "pages":
        # Pages has no environment in its current run-name. Never assume a
        # manual dispatch targets production: classify it explicitly unknown.
        if event in ("push", "schedule"):
            return "staging"
        if event == "workflow_dispatch":
            return "unspecified"
    return None


def sample(name, labels, value):
    labels_text = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return f"shadowops_deploy_{name}{{{labels_text}}} {value}"


def render_runs(workflows):
    """Render strictly bounded-cardinality gauges. No token, URLs or run bodies."""
    groups = {}
    for component in WORKFLOWS:
        payload = workflows.get(component)
        runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
        if not isinstance(runs, list):
            raise ValueError(f"invalid {component} workflow result")
        for run in runs:
            env = environment(component, run)
            if env is None or not isinstance(run.get("id"), int):
                continue
            created = timestamp(run.get("created_at"))
            if created is None:
                continue
            groups.setdefault((component, env), []).append((created, run))
    output = [
        "# HELP shadowops_deploy_last_completed_success Last completed run success (1 yes, 0 no).",
        "# TYPE shadowops_deploy_last_completed_success gauge",
        "# HELP shadowops_deploy_last_completed_timestamp_seconds Last completed run creation time.",
        "# TYPE shadowops_deploy_last_completed_timestamp_seconds gauge",
        "# HELP shadowops_deploy_last_success_timestamp_seconds Last successfully completed run creation time.",
        "# TYPE shadowops_deploy_last_success_timestamp_seconds gauge",
        "# HELP shadowops_deploy_last_completed_duration_seconds Duration of last completed run.",
        "# TYPE shadowops_deploy_last_completed_duration_seconds gauge",
        "# HELP shadowops_deploy_last_run_id GitHub Actions numeric run ID for latest run.",
        "# TYPE shadowops_deploy_last_run_id gauge",
        "# HELP shadowops_deploy_running Runs in progress or queued in the returned history.",
        "# TYPE shadowops_deploy_running gauge",
        "# HELP shadowops_deploy_last_result Result of last completed run (single bounded result label).",
        "# TYPE shadowops_deploy_last_result gauge",
    ]
    for (component, env), records in sorted(groups.items()):
        records.sort(key=lambda item: (item[0], item[1]["id"]), reverse=True)
        latest = records[0][1]
        labels = {"component": component, "environment": env}
        output.append(sample("last_run_id", labels, latest["id"]))
        output.append(sample("running", labels, sum(
            run.get("status") != "completed" for _, run in records)))
        completed = [(created, run) for created, run in records
                     if run.get("status") == "completed"]
        if not completed:
            continue
        created, last = completed[0]
        conclusion = str(last.get("conclusion") or "unknown")
        # Constrain label values even when GitHub adds a new conclusion.
        if conclusion not in {"success", "failure", "cancelled", "timed_out",
                              "neutral", "skipped", "action_required", "unknown"}:
            conclusion = "unknown"
        output.append(sample("last_completed_success", labels,
                             int(conclusion == "success")))
        output.append(sample("last_completed_timestamp_seconds", labels,
                             int(created)))
        output.append(sample("last_result", {**labels, "result": conclusion}, 1))
        end = timestamp(last.get("updated_at"))
        start = timestamp(last.get("run_started_at")) or created
        if end is not None and end >= start:
            output.append(sample("last_completed_duration_seconds", labels,
                                 round(end - start, 3)))
        successes = [(when, run) for when, run in completed
                     if run.get("conclusion") == "success"]
        if successes:
            output.append(sample("last_success_timestamp_seconds", labels,
                                 int(successes[0][0])))
    return "\n".join(output) + "\n"


def fetch_workflow(component, token="", *, opener=urllib.request.urlopen):
    if component not in WORKFLOWS:
        raise ValueError("unknown component")
    url = GITHUB + WORKFLOWS[component] + "/runs?per_page=100"
    headers = dict(HEADERS)
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with opener(request, timeout=15) as response:
        if response.status != 200:
            raise RuntimeError("GitHub API returned non-200")
        body = response.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError("GitHub response too large")
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get("workflow_runs"), list):
        raise ValueError("invalid GitHub workflow response")
    return data


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.samples = ""
        self.ok = 0
        self.last_attempt = 0
        self.last_success = 0

    def poll(self, token="", *, fetch=fetch_workflow, now=time.time):
        attempted = int(now())
        try:
            payloads = {kind: fetch(kind, token) for kind in WORKFLOWS}
            samples = render_runs(payloads)
        except (ValueError, RuntimeError, TypeError, OSError, urllib.error.URLError) as exc:
            # Never print API response bodies or HTTP header/token values.
            suffix = f" http={exc.code}" if isinstance(exc, urllib.error.HTTPError) else ""
            print(f"chronicles metrics: poll failed ({type(exc).__name__}{suffix})",
                  flush=True)
            with self.lock:
                self.last_attempt = attempted
                self.ok = 0
            return False
        with self.lock:
            self.samples = samples
            self.last_attempt = attempted
            self.last_success = attempted
            self.ok = 1
        return True

    def metrics(self):
        with self.lock:
            return (
                "# HELP shadowops_exporter_up Whether latest GitHub API poll succeeded.\n"
                "# TYPE shadowops_exporter_up gauge\n"
                f"shadowops_exporter_up {self.ok}\n"
                "# TYPE shadowops_exporter_last_poll_timestamp_seconds gauge\n"
                f"shadowops_exporter_last_poll_timestamp_seconds {self.last_attempt}\n"
                "# TYPE shadowops_exporter_last_success_timestamp_seconds gauge\n"
                f"shadowops_exporter_last_success_timestamp_seconds {self.last_success}\n"
                + self.samples
            )


def serve(state, interval, token):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in ("/metrics", "/healthz"):
                self.send_error(404)
                return
            output = (state.metrics().encode("utf-8") if self.path == "/metrics"
                      else b"ok\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(output)))
            self.end_headers()
            self.wfile.write(output)

        def log_message(self, fmt, *args):
            pass

    def worker():
        while True:
            state.poll(token)
            time.sleep(interval)

    thread = threading.Thread(target=worker, name="github-actions-poll", daemon=True)
    thread.start()
    server = ThreadingHTTPServer(("0.0.0.0", 9108), Handler)
    server.serve_forever()


if __name__ == "__main__":
    frequency = int(os.environ.get("POLL_INTERVAL_SECONDS", "300"))
    if frequency < 300 or frequency > 3600:
        raise SystemExit("poll interval must be 300..3600 seconds")
    print("Chronicles deploy exporter listening on internal port 9108", flush=True)
    serve(State(), frequency, os.environ.get("GITHUB_TOKEN", ""))
