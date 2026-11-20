"""Offline tests for a single pinned Mongo production replica initialization."""
from __future__ import annotations

from contextlib import nullcontext
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_production_mongo_replica",
    ROOT / "host/identity-production-mongo-replica.py",
)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
CID = "a" * 64


class ReplicaTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": ""})
        self.env.start()
        self.addCleanup(self.env.stop)

    def operator_gate(self, password=op.ACK):
        return (
            mock.patch.object(op.os, "geteuid", return_value=0),
            mock.patch.object(op.sys.stdin, "isatty", return_value=True),
            mock.patch("builtins.input", return_value=password),
            mock.patch.object(op.operator, "single_operator", return_value=nullcontext()),
        )

    def test_plan_no_secret_no_mongo_no_docker(self):
        p = subprocess.run(["python3", str(ROOT / "host/identity-production-mongo-replica.py"),
                            "plan"], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("first_admin=separate-step", p.stdout)
        self.assertIn("user_creation=no", p.stdout)
        self.assertNotIn("password", p.stdout)
        self.assertEqual(op.main([]), 2)
        self.assertEqual(op.main(["apply"]), 2)

    def test_static_mongosh_only_with_tls_and_exact_container_cid(self):
        with mock.patch.object(op.operator, "docker", return_value="UNINITIALIZED") as docker:
            self.assertEqual(op.run_mongosh(CID, op.PROBE_JS), "UNINITIALIZED")
            args = docker.call_args.args
            self.assertEqual(args[:3], ("exec", "-i", CID))
            self.assertIn("--tlsCAFile", args)
            self.assertIn("mongodb://127.0.0.1:27017/?directConnection=true", args)
            self.assertEqual(args[-2:], ("--eval", op.PROBE_JS))
            self.assertNotIn("password", " ".join(args).lower())
            self.assertNotIn("staging", " ".join(args).lower())
        with mock.patch.object(op.operator, "docker") as docker, \
             self.assertRaises(op.Refused):
            op.run_mongosh(CID, "db.dropDatabase()")
            docker.assert_not_called()
        self.assertIn('host:"identity-mongo-production:27017"', op.INIT_JS)
        self.assertIn('_id:"identity-production-rs"', op.INIT_JS)
        self.assertNotIn("localhost:27017", op.INIT_JS)
        self.assertNotIn("drop", op.INIT_JS)

    def test_read_only_probe_classification(self):
        for returned in ("PRIMARY", "NONPRIMARY", "UNINITIALIZED"):
            with self.subTest(status=returned), \
                 mock.patch.object(op, "verified_container", return_value=CID), \
                 mock.patch.object(op, "run_mongosh", return_value=returned):
                self.assertEqual(op.inspect(), returned)
        with mock.patch.object(op, "verified_container", return_value=CID), \
             mock.patch.object(op, "run_mongosh", return_value="UNEXPECTED"), \
             self.assertRaises(op.Refused):
            op.inspect()

    def test_runtime_validation_refuses_ci_without_docker(self):
        with mock.patch.dict(os.environ, {"CI": "true"}), \
             mock.patch.object(op.operator, "docker") as docker, \
             self.assertRaises(op.Refused):
            op.verified_container()
            docker.assert_not_called()

    def test_explicit_root_tty_and_ack_required_before_communication(self):
        with mock.patch.dict(os.environ, {"CI": "true"}), \
             mock.patch.object(op, "verified_container") as verify, \
             self.assertRaises(op.Refused):
            op.initiate()
            verify.assert_not_called()
        with mock.patch.object(op.os, "geteuid", return_value=1001), \
             mock.patch.object(op, "verified_container") as verify, \
             self.assertRaises(op.Refused):
            op.initiate()
            verify.assert_not_called()
        patches = self.operator_gate(password="WRONG")
        with patches[0], patches[1], patches[2], patches[3], \
             mock.patch.object(op, "verified_container") as verify, \
             self.assertRaises(op.Refused):
            op.initiate()
            verify.assert_not_called()

    def test_primary_election_success(self):
        responses = ["UNINITIALIZED", "INIT_ACCEPTED", "NONPRIMARY", "PRIMARY"]
        patches = self.operator_gate()
        with patches[0], patches[1], patches[2], patches[3], \
             mock.patch.object(op, "verified_container", return_value=CID), \
             mock.patch.object(op, "run_mongosh", side_effect=responses) as mongo:
            op.initiate(sleep=lambda _: None)
        self.assertEqual(mongo.call_count, 4)
        self.assertEqual(mongo.call_args_list[0].args[1], op.PROBE_JS)
        self.assertEqual(mongo.call_args_list[1].args[1], op.INIT_JS)
        self.assertEqual(mongo.call_args_list[2].args[1], op.PROBE_JS)

    def test_double_initialization_is_denied_without_writes(self):
        patches = self.operator_gate()
        with patches[0], patches[1], patches[2], patches[3], \
             mock.patch.object(op, "verified_container", return_value=CID), \
             mock.patch.object(op, "run_mongosh", return_value="PRIMARY") as mongo, \
             self.assertRaises(op.Refused):
            op.initiate()
        self.assertEqual(mongo.call_count, 1)
        self.assertEqual(mongo.call_args.args[1], op.PROBE_JS)

    def test_election_timeout_has_no_unsafe_retry_or_rollback(self):
        patches = self.operator_gate()
        with patches[0], patches[1], patches[2], patches[3], \
             mock.patch.object(op, "verified_container", return_value=CID), \
             mock.patch.object(op, "run_mongosh", side_effect=[
                 "UNINITIALIZED", "INIT_ACCEPTED", *(["NONPRIMARY"]*20)
             ]) as mongo, \
             mock.patch.object(op.operator, "compose") as compose, \
             self.assertRaises(op.Refused):
            op.initiate(sleep=lambda _: None)
        self.assertEqual(sum(x.args[1] == op.INIT_JS for x in mongo.call_args_list), 1)
        compose.assert_not_called()

    def test_make_targets_plan_inspect_and_manual_init(self):
        for target, action in (
            ("identity-prod-mongo-replica-plan", "plan"),
            ("identity-prod-mongo-replica-inspect", "inspect"),
            ("identity-prod-mongo-replica-init", "init"),
        ):
            p = subprocess.run(["make", "-n", "--no-print-directory", target],
                               cwd=ROOT, capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("host/identity-production-mongo-replica.py " + action, p.stdout)
            self.assertNotIn("sudo ", p.stdout)
            self.assertNotIn("docker exec", p.stdout)


if __name__ == "__main__":
    unittest.main()
