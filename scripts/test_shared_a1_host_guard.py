"""Shared A1 collision inventory + staging admission, no live Docker calls."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from shared_a1_host_guard import (
    SharedHostError, inspect_container_rows, verify_shared_a1_containers,
)
from oci_staging_deploy import DeployError, run_staging
from test_oci_staging_deploy import COMPOSE, DIGEST, ENV, Runner, SHA, fake_host_preflight


def container(name, project="", service="", ports="", *, state="running"):
    labels = ",".join([f"com.docker.compose.project={project}", f"com.docker.compose.service={service}"]) if project else ""
    return json.dumps({"Names": name, "Labels": labels, "Ports": ports, "State": state})


def rows(*items):
    return "\n".join(items) + "\n"


class DockerCensus:
    def __init__(self, output, exit_code=0):
        self.output, self.exit_code = output, exit_code
        self.args = []

    def __call__(self, args, **kwargs):
        self.args.append(tuple(args))
        return subprocess.CompletedProcess(args, self.exit_code, self.output, "private credentials")


class SharedA1GuardTests(unittest.TestCase):
    def test_accepts_chess_studio_and_isolated_chronicles_services(self):
        inspect_container_rows(rows(
            container("chess-studio-backend", "chess-studio-staging", "backend", "127.0.0.1:4000->4000/tcp"),
            container("chess-studio-production", "chess-studio-production", "backend", "127.0.0.1:4100->4000/tcp"),
            container("chronicles-api", "shadowops-chronicles-staging", "chronicles-api", "127.0.0.1:18081->8080/tcp"),
            container("chronicles-web", "shadowops-chronicles-web-staging", "chronicles-web", "127.0.0.1:18082->8080/tcp"),
        ))
        inspect_container_rows(rows(container("chess-studio", "chess-studio", "backend", "")))

    def test_fails_closed_on_competing_baseline_or_port_owner(self):
        cases = [
            container("legacy", "shadowops-chronicles", "chronicles-api", "", state="exited"),
            container("foreign", "foreign-project", "other", "127.0.0.1:18081->8080/tcp"),
            container("foreign-web", "foreign", "other", "127.0.0.1:18082->8080/tcp"),
            container("unknown", "", "", "127.0.0.1:18081->123/tcp"),
            container("wildcard", "shadowops-chronicles-staging", "chronicles-api", "0.0.0.0:18081->8080/tcp"),
            container("ipv6", "shadowops-chronicles-web-staging", "chronicles-web", "[::]:18082->8080/tcp"),
            container("extra", "shadowops-chronicles-staging", "other", ""),
            container("web-extra", "shadowops-chronicles-web-staging", "other", ""),
            rows(container("one", "shadowops-chronicles-staging", "chronicles-api"),
                 container("two", "shadowops-chronicles-staging", "chronicles-api")),
            '{"Names": "broken"}',
            "not-json",
            container("weird", "", "", "not-a-port->8080/tcp"),
            "x" * 512001,
        ]
        for value in cases:
            with self.subTest(value=value[:85]), self.assertRaises(SharedHostError):
                inspect_container_rows(value)

    def test_census_is_read_only_and_failed_inventory_hides_output(self):
        census = DockerCensus(rows(container("chess", "chess-studio", "backend")))
        verify_shared_a1_containers(census)
        self.assertEqual(census.args, [("docker", "ps", "--all", "--format", "{{json .}}")])
        with self.assertRaises(SharedHostError) as error:
            verify_shared_a1_containers(DockerCensus("secret", 1))
        self.assertNotIn("secret", str(error.exception))

    def test_deploy_hard_stops_before_candidate_checks_if_shared_a1_conflicts(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = Runner()
            def conflict(_runner):
                raise SharedHostError("Port 18081 belongs to another service")
            with self.assertRaisesRegex(DeployError, "shared A1"):
                run_staging(
                    sha=SHA, run_id=38812775390, env=ENV, deploy=True,
                    architecture="aarch64", host_preflight=fake_host_preflight,
                    runner=runner, lock_dir=Path(folder)/"lock",
                    host_collision_guard=conflict,
                )
            self.assertFalse(runner.calls)

    def test_second_census_blocks_pull_when_collisions_appear_during_admission(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = Runner()
            calls = []
            def changed(_runner):
                calls.append(1)
                if len(calls) == 2:
                    raise SharedHostError("Port 18081 belongs to another service")
            with self.assertRaisesRegex(DeployError, "shared A1"):
                run_staging(
                    sha=SHA, run_id=38812775390, env=ENV, deploy=True,
                    architecture="aarch64", host_preflight=fake_host_preflight,
                    runner=runner, lock_dir=Path(folder)/"lock",
                    host_collision_guard=changed,
                    token_reader=lambda path: "owner" if "owner" in path else "other",
                )
            self.assertEqual(len(calls), 2)
            self.assertEqual(len(runner.calls), 2)
            self.assertFalse(any("up" in call or "pull" in call for call in runner.calls))


if __name__ == "__main__":
    unittest.main()
