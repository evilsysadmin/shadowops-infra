"""No OCI calls on PRs; fake a single fixed host read-only command."""
import hashlib
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace as NS

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "scripts"))
sys.path.insert(0, str(root / "tests"))
import oci_control_plane as cp
import oci_host_probe as hp
from test_oci_control_plane import FakeSDK, ENV


class Capture:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class HostSDK(FakeSDK):
    def __init__(self, *, lifecycle="SUCCEEDED", code=0, output=hp.HOST_READY+"\n", **kwargs):
        super().__init__(**kwargs)
        self.invocations = []
        self.lifecycle, self.code, self.output = lifecycle, code, output
        self.compute_instance_agent.models = NS(
            InstanceAgentCommandContent=Capture,
            InstanceAgentCommandSourceViaTextDetails=Capture,
            InstanceAgentCommandOutputViaTextDetails=Capture,
            CreateInstanceAgentCommandDetails=Capture,
            InstanceAgentCommandTarget=Capture,
        )
        self.compute_instance_agent.ComputeInstanceAgentClient = lambda config: self

    def create_instance_agent_command(self, **kwargs):
        self.invocations.append(("create", kwargs))
        return NS(data=NS(id="test-command"))

    def get_instance_agent_command_execution(self, **kwargs):
        self.invocations.append(("poll", kwargs))
        return NS(data=NS(lifecycle_state=self.lifecycle,
                          content=NS(exit_code=self.code, text=self.output)))


class TestFixedHostProbe(unittest.TestCase):
    def test_success_only_for_fixed_read_only_command(self):
        sdk = HostSDK()
        hp.execute(sdk, cp.config_from_env(sdk, ENV), pause=lambda _:None)
        self.assertEqual(len([x for x in sdk.invocations if x[0] == "create"]), 1)
        obj = sdk.invocations[0][1]["create_instance_agent_command_details"]
        self.assertEqual(obj.kwargs["target"].kwargs["instance_id"], "instance-test")
        source = obj.kwargs["content"].kwargs["source"].kwargs["text"]
        self.assertEqual(source, hp.HOST_COMMAND)
        self.assertNotIn("sudo", source)
        self.assertNotIn("docker compose up", source)

    def test_refuse_failed_or_missing_result(self):
        for change in ({"lifecycle": "FAILED"}, {"code": 1},
                       {"output": "untrusted output\\n"},
                       {"plugin": "STOPPED"}, {"shape": "VM.Standard.E4.Flex"}):
            with self.subTest(change=change):
                sdk = HostSDK(**change)
                with self.assertRaises(cp.InventoryError):
                    hp.execute(sdk, cp.config_from_env(sdk, ENV), pause=lambda _:None)
                if change.get("plugin") or change.get("shape"):
                    self.assertFalse(sdk.invocations)


    def test_wrapper_command_is_fixed_read_only_and_hashes_only_our_wrapper(self):
        hp.assert_command_safe(hp.WRAPPER_COMMAND)
        self.assertIn("helper=/usr/local/sbin/shadowops-chronicles-api", hp.WRAPPER_COMMAND)
        self.assertIn("sha256sum --", hp.WRAPPER_COMMAND)
        for forbidden in ("sudo", "docker ", "chmod ", "chown ", "install ",
                          "git ", "curl ", "rm ", "ssh ", "OCI_PRIVATE_KEY"):
            self.assertNotIn(forbidden, hp.WRAPPER_COMMAND)
        for unsafe in (hp.WRAPPER_COMMAND + "\necho extra",
                       hp.WRAPPER_COMMAND.replace("chronicles-api", "chess-studio"),
                       hp.WRAPPER_COMMAND.replace("sha256sum", "cat")):
            with self.assertRaises(cp.InventoryError):
                hp.assert_command_safe(unsafe)

    def test_wrapper_fixed_command_reports_safe_hash_missing_and_unsafe(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root)
            wrapper = path / "wrapper"
            wrapper.write_text("synthetic trusted content")
            wrapper.chmod(0o755)
            command = hp.WRAPPER_COMMAND.replace(
                "helper=/usr/local/sbin/shadowops-chronicles-api",
                "helper=" + str(wrapper))
            stat = path / "stat"
            stat.write_text('#!/bin/sh\n'
                            'if [ "$2" = "%u" ]; then echo 0; else /usr/bin/stat "$@"; fi\n')
            stat.chmod(0o755)
            env = dict(os.environ, PATH=str(path) + os.pathsep + os.environ["PATH"])
            def observe():
                return subprocess.run(["sh", "-c", command], capture_output=True,
                                      text=True, env=env, check=False)
            good = observe()
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(good.stdout.strip(),
                             "CHRONICLES_API_WRAPPER_SHA256 " +
                             hashlib.sha256(wrapper.read_bytes()).hexdigest())
            wrapper.chmod(0o777)
            self.assertEqual(observe().stdout.strip(), "CHRONICLES_API_WRAPPER_UNSAFE")
            wrapper.unlink()
            self.assertEqual(observe().stdout.strip(), "CHRONICLES_API_WRAPPER_MISSING")
            wrapper.symlink_to(path / "absent")
            self.assertEqual(observe().stdout.strip(), "CHRONICLES_API_WRAPPER_UNSAFE")

    def test_wrapper_result_is_strict_and_does_not_echo_host_output(self):
        digest = "a" * 64
        self.assertEqual(hp.wrapper_verdict("CHRONICLES_API_WRAPPER_SHA256 " + digest + "\n",
                                            digest), "CHRONICLES_API_WRAPPER_CURRENT")
        self.assertEqual(hp.wrapper_verdict("CHRONICLES_API_WRAPPER_SHA256 " + "b" * 64 + "\n",
                                            digest), "CHRONICLES_API_WRAPPER_OUTDATED")
        for status in ("MISSING", "UNSAFE"):
            self.assertEqual(hp.wrapper_verdict("CHRONICLES_API_WRAPPER_" + status + "\n",
                                                digest), "CHRONICLES_API_WRAPPER_" + status)
        for bad in ("", "HOST_READY", "secret\nCHRONICLES_API_WRAPPER_SHA256 " + digest,
                    "CHRONICLES_API_WRAPPER_SHA256 " + digest + "\nextra",
                    "CHRONICLES_API_WRAPPER_SHA256 " + digest + " secret",
                    "CHRONICLES_API_WRAPPER_SHA256 " + "f" * 65):
            with self.subTest(text=bad[:50]), self.assertRaises(cp.InventoryError):
                hp.wrapper_verdict(bad, digest)
        for invalid in ("", "B" * 64, "0" * 63, "0" * 64 + "x"):
            with self.assertRaises(cp.InventoryError):
                hp.wrapper_verdict("CHRONICLES_API_WRAPPER_MISSING", invalid)

    def test_wrapper_uses_one_trusted_host_gate_and_no_raw_stdout(self):
        digest = "a" * 64
        sdk = HostSDK(output="CHRONICLES_API_WRAPPER_SHA256 " + digest + "\n")
        output = io.StringIO()
        with redirect_stdout(output):
            hp.execute(sdk, cp.config_from_env(sdk, ENV),
                       probe="wrapper", expected_digest=digest)
        self.assertEqual(output.getvalue().strip(), "CHRONICLES_API_WRAPPER_CURRENT")
        self.assertEqual([name for name, _ in sdk.observed],
                         ["validate", "list", "list", "plugin"])
        self.assertEqual(len(sdk.invocations), 2)
        command = sdk.invocations[0][1]["create_instance_agent_command_details"].kwargs
        self.assertEqual(command["content"].kwargs["source"].kwargs["text"], hp.WRAPPER_COMMAND)
        self.assertEqual(command["target"].kwargs["instance_id"], "instance-test")
        for change in ({"output": "CHRONICLES_API_WRAPPER_SHA256 " + "b" * 64},
                       {"output": "CHRONICLES_API_WRAPPER_MISSING"},
                       {"output": "CHRONICLES_API_WRAPPER_UNSAFE"},
                       {"output": "SECRET\nCHRONICLES_API_WRAPPER_SHA256 " + digest},
                       {"lifecycle": "FAILED"}, {"plugin": "STOPPED"}):
            with self.subTest(change=change):
                bad = HostSDK(**change)
                captured = io.StringIO()
                with redirect_stdout(captured), self.assertRaises(cp.InventoryError):
                    hp.execute(bad, cp.config_from_env(bad, ENV),
                               probe="wrapper", expected_digest=digest)
                self.assertNotIn("SECRET", captured.getvalue())
                if change.get("plugin"):
                    self.assertEqual(bad.invocations, [])

    def test_invalid_wrapper_arguments_are_rejected_before_oci_calls(self):
        for probe, digest in (("wrapper", ""), ("wrapper", "Z" * 64),
                              ("host", "a" * 64), ("random", "")):
            sdk = HostSDK()
            with self.subTest(probe=probe), self.assertRaises(cp.InventoryError):
                hp.execute(sdk, cp.config_from_env(sdk, ENV),
                           probe=probe, expected_digest=digest)
            self.assertEqual(sdk.invocations, [])

    def test_reject_arbitrary_remote_command(self):
        for value in ("sudo docker ps", hp.HOST_COMMAND + "\\nsudo id",
                      "docker compose up --detach", "", "echo token"):
            with self.subTest(value=value):
                with self.assertRaises(cp.InventoryError):
                    hp.assert_command_safe(value)


if __name__ == "__main__":
    unittest.main()
