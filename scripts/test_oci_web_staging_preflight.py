"""Offline contracts for signed, isolated Chronicles web preflight on shared A1."""
from __future__ import annotations
import json
import pathlib
import subprocess
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from oci_web_staging_preflight import (
    WebPreflightError, check, verify_compose, verify_manifest,
    verified_provenance, verify_source,
)
from shared_a1_host_guard import SharedHostError

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
RUN_ID = 38800000001
ENV = {"GH_TOKEN": "fake-token", "CHRONICLES_WEB_IMAGE_DIGEST": DIGEST}


def read(path, token):
    assert token == "fake-token"
    if path.endswith("/actions/runs/" + str(RUN_ID)):
        return {"head_sha": SHA, "event": "push", "head_branch": "main",
                "path": ".github/workflows/web-publish.yml",
                "status": "completed", "conclusion": "success",
                "repository": {"full_name": "evilsysadmin/chronicles-of-matthias"}}
    if path.endswith("/branches/main"):
        return {"protected": True}
    if "/compare/" in path:
        return {"status": "ahead", "behind_by": 0}
    if path.endswith("/jobs?per_page=100"):
        return {"total_count": 2, "jobs": [
            {"name": "web-image-policy", "status": "completed", "conclusion": "success"},
            {"name": "publish-staging-web", "status": "completed", "conclusion": "success"},
        ]}
    raise AssertionError("Unexpected GitHub API request")


def compose():
    return {"name": "shadowops-chronicles-web-staging", "services": {
        "chronicles-web": {
            "image": "ghcr.io/evilsysadmin/chronicles-web@" + DIGEST,
            "platform": "linux/arm64", "read_only": True, "init": True,
            "cap_drop": ["ALL"], "user": "101:101",
            "security_opt": ["no-new-privileges:true"],
            "ports": [{"host_ip": "127.0.0.1", "published": "18082", "target": 8080}],
        }
    }}


def signed():
    return [{"verificationResult": {"statement": {
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"digest": {"sha256": DIGEST[7:]}}],
    }}}]


def manifest():
    return {"manifests": [
        {"platform": {"os": "linux", "architecture": "arm64"}},
        {"platform": {"os": "linux", "architecture": "amd64"}},
    ]}


class Runner:
    def __init__(self):
        self.commands = []
        self.override = {}

    def __call__(self, args, **kwargs):
        self.commands.append(args)
        assert kwargs["capture_output"] is True
        if args[:2] == ["gh", "attestation"]:
            output = self.override.get("gh", signed())
        elif args[:3] == ["docker", "buildx", "imagetools"]:
            output = self.override.get("manifest", manifest())
        elif args[:2] == ["docker", "compose"]:
            output = self.override.get("compose", compose())
        else:
            raise AssertionError("Unexpected or mutating command " + repr(args))
        return subprocess.CompletedProcess(args, 0, json.dumps(output), "")


class WebStagingPreflightTests(unittest.TestCase):
    def test_complete_read_only_admission(self):
        runner = Runner()
        guards = []
        def guard(r):
            guards.append(r)
        result = check(sha=SHA, digest=DIGEST, run_id=RUN_ID, env=ENV, runner=runner,
                       read=read, guard=guard, architecture="aarch64")
        self.assertEqual(result, "CHRONICLES_WEB_A1_VERIFIED_PREFLIGHT_OK")
        self.assertEqual(guards, [runner])
        self.assertEqual(len(runner.commands), 3)
        self.assertEqual(runner.commands[0][:3], ["gh", "attestation", "verify"])
        for option in ("--signer-workflow", "--source-digest", "--source-ref", "--predicate-type"):
            self.assertIn(option, runner.commands[0])
        self.assertEqual(runner.commands[2][-3:], ["config", "--format", "json"])
        self.assertFalse(any(cmd[0:2] in (["docker", "pull"], ["docker", "run"]) or
                             "up" in cmd or "down" in cmd for cmd in runner.commands))

    def test_rejects_source_run_mismatch_or_missing_green_job(self):
        def broken(path, token):
            data = read(path, token)
            if path.endswith("/jobs?per_page=100"):
                data["jobs"][1]["conclusion"] = "failure"
            return data
        with self.assertRaisesRegex(WebPreflightError, "job"):
            verify_source(SHA, RUN_ID, ENV["GH_TOKEN"], broken)
        def unprotected(path, token):
            data = read(path, token)
            if path.endswith("/branches/main"):
                data["protected"] = False
            return data
        with self.assertRaisesRegex(WebPreflightError, "protected"):
            verify_source(SHA, RUN_ID, ENV["GH_TOKEN"], unprotected)
        def stale(path, token):
            data = read(path, token)
            if "/compare/" in path:
                data["behind_by"] = 1
            return data
        with self.assertRaisesRegex(WebPreflightError, "main"):
            verify_source(SHA, RUN_ID, ENV["GH_TOKEN"], stale)

    def test_rejects_unverified_digest_and_missing_arm_variant(self):
        with self.assertRaisesRegex(WebPreflightError, "digest"):
            verified_provenance(json.dumps([{"verificationResult": {"statement": {
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"digest": {"sha256": "c" * 64}}],
            }}}]), DIGEST)
        with self.assertRaisesRegex(WebPreflightError, "arm64"):
            verify_manifest(json.dumps({"manifests": [
                {"platform": {"os": "linux", "architecture": "amd64"}}
            ]}))

    def test_rejects_extra_service_and_public_or_privileged_binding(self):
        invalid = compose()
        invalid["services"]["other"] = {}
        with self.assertRaises(WebPreflightError):
            verify_compose(json.dumps(invalid), DIGEST)
        for patch in ({"privileged": True},
                      {"ports": [{"host_ip": "0.0.0.0", "published": "18082", "target": 8080}]},
                      {"volumes": ["/:/host"]},
                      {"image": "ghcr.io/evilsysadmin/chronicles-web:latest"}):
            invalid = compose()
            invalid["services"]["chronicles-web"].update(patch)
            with self.subTest(patch=patch), self.assertRaises(WebPreflightError):
                verify_compose(json.dumps(invalid), DIGEST)

    def test_bad_input_and_collision_fail_before_any_release_checks(self):
        for sha, digest, run_id, env, architecture in (
            ("main", DIGEST, RUN_ID, ENV, "aarch64"),
            (SHA, "sha256:invalid", RUN_ID, ENV, "aarch64"),
            (SHA, DIGEST, 0, ENV, "aarch64"),
            (SHA, DIGEST, RUN_ID, {}, "aarch64"),
            (SHA, DIGEST, RUN_ID, ENV, "x86_64"),
        ):
            runner = Runner()
            with self.subTest(sha=sha,digest=digest,run_id=run_id,architecture=architecture):
                with self.assertRaises(WebPreflightError):
                    check(sha=sha,digest=digest,run_id=run_id,env=env,
                          runner=runner,read=read,guard=lambda _: None,architecture=architecture)
                self.assertFalse(runner.commands)
        runner = Runner()
        def conflict(_):
            raise SharedHostError("private details must stay hidden")
        with self.assertRaisesRegex(WebPreflightError, "collision guard"):
            check(sha=SHA,digest=DIGEST,run_id=RUN_ID,env=ENV,runner=runner,
                  read=read,guard=conflict,architecture="aarch64")
        self.assertFalse(runner.commands)


if __name__ == "__main__":
    unittest.main()
