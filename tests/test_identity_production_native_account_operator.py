"""Production native account creation is only through pinned running origin.

All Docker, certificate, secret, and principal operations are synthetic.
"""
from contextlib import nullcontext
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[1] / "host/identity-production-native-account.py"
spec = importlib.util.spec_from_file_location("production_native_operator", PATH)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)

CID = "a" * 64
SHA = "b" * 40
IMAGE = op.origin_operator.IMAGE + "sha256:" + "c" * 64
CERT = Path("/synthetic/production-ca.pem")
RECEIPT = {
    "tls": "verified", "ready": "yes", "jwks": "ed25519-public",
    "registration": "disabled", "foreign_host": "denied",
}


class DockerDouble:
    def __init__(self):
        self.calls = []
        self.events = []
        self.returncode = 0
        self.container = CID
        self.payload = None
        self.state = "running"
        self.image = IMAGE

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[:2] == ["docker", "exec"]:
            self.payload = kwargs.get("input")
            self.events.append("provision")
            return SimpleNamespace(returncode=self.returncode, stdout=b"", stderr=b"private")
        if argv[:2] == ["docker", "inspect"]:
            self.events.append("inspect")
            return SimpleNamespace(returncode=0, stdout=(
                self.image + "|65532:65532|true|" + op.origin_operator.PROJECT
                + "|" + op.origin_operator.SERVICE + "|true"),
                stderr="")
        if argv[:2] == ["docker", "compose"]:
            self.events.append("ps")
            return SimpleNamespace(returncode=0, stdout=self.container, stderr="")
        raise AssertionError("unexpected docker operation: " + str(argv))


def patch_origin(runner):
    stack = mock.patch.multiple(
        op.origin_operator,
        origin_admission=mock.DEFAULT,
        project_container_status=mock.DEFAULT,
        require_manual=mock.DEFAULT,
        exclusive=mock.DEFAULT,
    )
    mapping = stack.start()
    mapping["origin_admission"].return_value = (SHA, IMAGE)
    mapping["project_container_status"].return_value = [
        {"Service": op.origin_operator.SERVICE, "State": runner.state},
    ]
    mapping["exclusive"].return_value = nullcontext()
    return stack, mapping


class AccountOperatorTests(unittest.TestCase):
    def test_no_secret_or_docker_access_on_plan(self):
        self.assertEqual(op.main(["plan"]), 0)
        self.assertEqual(op.main([]), 2)
        self.assertEqual(op.main(["create", "bad Alias"]), 2)

    def test_running_exact_image_id_and_tls_receipt_required(self):
        runner = DockerDouble()
        patch, mocks = patch_origin(runner)
        try:
            with mock.patch.object(op.origin, "ca_file", return_value=CERT):
                got = op.admission(runner=runner, probe=lambda ca: RECEIPT)
            self.assertEqual(got, {"sha": SHA, "image": IMAGE, "container": CID})
            self.assertEqual(runner.events, ["ps", "inspect"])
            mocks["origin_admission"].assert_called_once_with(runner=runner)
            self.assertIn("production", IMAGE)
        finally:
            patch.stop()

    def test_realistic_password_via_pipe_only_without_docker_tty_or_env(self):
        runner = DockerDouble()
        patch, _ = patch_origin(runner)
        try:
            with mock.patch.object(op.origin, "ca_file", return_value=CERT):
                op.provision("bridgeadmin", reader=lambda prompt: "safe secret 1234567890",
                             runner=runner, probe=lambda ca: RECEIPT)
            self.assertEqual(runner.events, ["ps", "inspect", "ps", "inspect", "provision"])
            self.assertEqual(runner.payload, b"safe secret 1234567890\n")
            call, kwargs = runner.calls[-1]
            self.assertEqual(call, [
                "docker", "exec", "-i", "--user", "65532:65532",
                CID, "/app/identity-production", "provision-native-account", "bridgeadmin",
            ])
            self.assertNotIn("-t", call)
            self.assertNotIn("environment", kwargs)
            self.assertTrue(kwargs["capture_output"])
            self.assertNotIn("safe secret", " ".join(call))
        finally:
            patch.stop()

    def test_bad_image_or_other_container_refused_before_secret_prompt(self):
        for poisoned in ("wrong-image", "wrong-cid", "offline", "no-jwks", "registration"):
            runner = DockerDouble()
            patch, mocks = patch_origin(runner)
            reader = mock.Mock(side_effect=AssertionError("secret asked too early"))
            try:
                if poisoned == "wrong-image":
                    runner.image = "ghcr.io/evil/foreign@sha256:" + "a" * 64
                if poisoned == "wrong-cid":
                    runner.container = "not-an-id"
                if poisoned == "offline":
                    mocks["project_container_status"].return_value = [
                        {"Service": op.origin_operator.SERVICE, "State": "exited"},
                    ]
                receipt = dict(RECEIPT)
                if poisoned == "no-jwks":
                    receipt["jwks"] = "untrusted"
                if poisoned == "registration":
                    receipt["registration"] = "enabled"
                with mock.patch.object(op.origin, "ca_file", return_value=CERT), \
                     self.assertRaises((op.Refused, op.origin_operator.Refused)):
                    op.provision("bridgeadmin", reader=reader, runner=runner,
                                 probe=lambda ca: receipt)
                reader.assert_not_called()
                self.assertNotIn("provision", runner.events)
            finally:
                patch.stop()

    def test_discard_password_after_success_and_failure(self):
        for exitcode in (0, 1):
            runner = DockerDouble()
            runner.returncode = exitcode
            secret = bytearray(b"testverylongpassword")
            if exitcode == 1:
                with self.assertRaises(op.Refused):
                    op.run_provision(CID, "bridgeadmin", secret, runner=runner)
            else:
                op.run_provision(CID, "bridgeadmin", secret, runner=runner)
            self.assertTrue(all(item == 0 for item in secret))
            self.assertEqual(runner.payload, b"testverylongpassword\n")
            self.assertNotIn("secret", str(runner.calls[-1][0]))

    def test_password_confirmation_alias_and_unicode_length(self):
        for a, b in (("short", "short"), ("Long enough secret", "different secret"),
                     ("embedded\nvalue 123456", "embedded\nvalue 123456"),
                     ("\x00" + "x" * 20, "\x00" + "x" * 20),
                     ("a" * 4097, "a" * 4097)):
            it = iter((a, b))
            with self.subTest(a=repr(a)[:20]), self.assertRaises(op.Refused):
                op.password_bytes(read=lambda prompt: next(it))
        for alias in ("ABCD", "a", "_admin", "admin-with-dash", "admin;whoami"):
            with self.subTest(alias=alias), self.assertRaises(op.Refused):
                op.run_provision(CID, alias, bytearray(b"a" * 20),
                                 runner=DockerDouble())

    def test_refuse_when_container_restarts_during_password_input(self):
        runner = DockerDouble()
        patch, _ = patch_origin(runner)
        calls = [CID, "f" * 64]
        def changing_id(argv, **kwargs):
            if argv[:2] == ["docker", "compose"]:
                runner.container = calls.pop(0)
            return runner(argv, **kwargs)
        try:
            with mock.patch.object(op.origin, "ca_file", return_value=CERT):
                with self.assertRaises(op.Refused):
                    op.provision("bridgeadmin", reader=lambda prompt: "safe secret 1234567890",
                                 runner=changing_id, probe=lambda ca: RECEIPT)
            self.assertNotIn("provision", runner.events)
        finally:
            patch.stop()


if __name__ == "__main__":
    unittest.main()
