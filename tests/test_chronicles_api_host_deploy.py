"""Offline contracts for the Chronicles API host deployer and its provisioning."""
from __future__ import annotations

import base64
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("chronicles_api_host_deploy",
                                              ROOT / "host" / "chronicles-api-deploy.py")
api = importlib.util.module_from_spec(spec)
spec.loader.exec_module(api)
import chronicles_api_provision as provision  # noqa: E402
import oci_chronicles_api_release as release  # noqa: E402

DIGEST = "sha256:" + "b" * 64
VAULT = "ocid1.vault.oc1.eu-frankfurt-1.abcdefghijkl"
SECRETS = {"MONGO_URL": "mongodb+srv://chronicles_staging:pw@cluster.example.mongodb.net/",
           "JWT_SECRET": "j" * 64, "INVITE_CODE": "MATTHIAS", "TUNNEL_TOKEN": "t" * 80}


def bundle_b64(values=SECRETS):
    text = "".join(f"{k}={v}\n" for k, v in values.items())
    return base64.b64encode(text.encode()).decode()


def hardened(image, **extra):
    return {"image": image, "platform": "linux/arm64", "user": "65532:65532", "read_only": True,
            "init": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], **extra}


def policy(digest=DIGEST):
    return {"name": "shadowops-chronicles-staging", "services": {
        "chronicles-api": hardened(
            "ghcr.io/evilsysadmin/chronicles-api@" + digest,
            env_file=[{"path": str(api.API_ENV), "required": True}],
            ports=[{"host_ip": "127.0.0.1", "published": "18081", "target": 8080, "protocol": "tcp"}]),
        "chronicles-tunnel": hardened(api.TUNNEL_IMAGE,
                                      env_file=[{"path": str(api.TUNNEL_ENV), "required": True}]),
    }}


class Runner:
    def __init__(self, config=None, vault_out=None, fail_at=None):
        self.config = config or policy()
        self.vault_out = bundle_b64() if vault_out is None else vault_out
        self.fail_at, self.commands = fail_at, []

    def __call__(self, args, **kwargs):
        self.commands.append(args)
        if self.fail_at and self.fail_at in args:
            return subprocess.CompletedProcess(args, 1, "private", "private")
        if args[0] == str(api.OCI_PYTHON):
            return subprocess.CompletedProcess(args, 0, self.vault_out, "")
        if "config" in args:
            return subprocess.CompletedProcess(args, 0, json.dumps(self.config), "")
        return subprocess.CompletedProcess(args, 0, "", "")


def run_deploy(runner, tmp):
    state, runtime = pathlib.Path(tmp, "state"), pathlib.Path(tmp, "runtime")
    return api.deploy(DIGEST, VAULT, runner=runner, guard=lambda _r: None, smoke=lambda: None,
                      state=state, runtime=runtime, require_root=False), state, runtime


class ChroniclesApiHostDeployTests(unittest.TestCase):
    def test_invocation_requires_digest_and_vault(self):
        self.assertEqual(api.validate_request("deploy", DIGEST, VAULT), (DIGEST, VAULT))
        for args in (("deploy", DIGEST, ""), ("deploy", "sha256:BAD", VAULT), ("rm", DIGEST, VAULT),
                     ("deploy", DIGEST, "ocid1.vault.x; rm -rf /")):
            with self.subTest(args=args), self.assertRaises(api.ReleaseError):
                api.validate_request(*args)

    def test_deploy_writes_private_env_files_and_brings_up_both_services(self):
        runner = Runner()
        with tempfile.TemporaryDirectory() as tmp:
            marker, state, runtime = run_deploy(runner, tmp)
            self.assertEqual(marker, "CHRONICLES_API_OCI_STAGING_SMOKE_OK digest=" + DIGEST)
            api_env = (runtime / "api.env").read_text()
            tunnel_env = (runtime / "tunnel.env").read_text()
            self.assertEqual((runtime / "api.env").stat().st_mode & 0o777, 0o600)
            self.assertEqual((runtime / "tunnel.env").stat().st_mode & 0o777, 0o600)
            self.assertIn("MONGO_URL='" + SECRETS["MONGO_URL"] + "'", api_env)
            self.assertIn("MONGO_DB_NAME='chronicles_staging'", api_env)
            self.assertIn("CORS_ORIGINS='https://staging.chronicles.shadowops.dpdns.org'", api_env)
            self.assertNotIn("TUNNEL_TOKEN", api_env)
            self.assertEqual(tunnel_env, "TUNNEL_TOKEN='" + SECRETS["TUNNEL_TOKEN"] + "'\n")
            self.assertTrue((state / "last-verified-api.json").exists())
        up = [c for c in runner.commands if "up" in c][0]
        self.assertEqual(up[-2:], ["chronicles-api", "chronicles-tunnel"])
        # Vault is read by the fixed OCI venv, never through a shell.
        vault_call = runner.commands[0]
        self.assertEqual(vault_call[:3], [str(api.OCI_PYTHON), "-I", "-c"])

    def test_bundle_contract_is_strict(self):
        bad = [dict(SECRETS, EXTRA="x"), {k: v for k, v in SECRETS.items() if k != "INVITE_CODE"},
               dict(SECRETS, JWT_SECRET="has'quote"), dict(SECRETS, INVITE_CODE="")]
        for values in bad:
            with self.subTest(values=sorted(values)), tempfile.TemporaryDirectory() as tmp, \
                    self.assertRaises(api.ReleaseError):
                run_deploy(Runner(vault_out=bundle_b64(values)), tmp)
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(api.ReleaseError):
            run_deploy(Runner(vault_out="not base64!"), tmp)

    def test_compose_policy_rejects_unsafe_or_unadmitted_config(self):
        mutations = [
            lambda c: c["services"]["chronicles-api"].update(image="ghcr.io/evilsysadmin/chronicles-api:latest"),
            lambda c: c["services"]["chronicles-api"].update(ports=[{"host_ip": "0.0.0.0", "published": "18081", "target": 8080}]),
            lambda c: c["services"]["chronicles-api"].update(privileged=True),
            lambda c: c["services"]["chronicles-api"].update(volumes=[{"source": "/", "target": "/host"}]),
            lambda c: c["services"]["chronicles-tunnel"].update(image="cloudflare/cloudflared:latest"),
            lambda c: c["services"]["chronicles-tunnel"].update(ports=[{"host_ip": "127.0.0.1", "published": "9999", "target": 1}]),
            lambda c: c["services"]["chronicles-tunnel"].update(network_mode="host"),
            lambda c: c["services"].update(extra=hardened("busybox")),
            lambda c: c.update(name="chess-studio-staging"),
            lambda c: c["services"]["chronicles-api"].update(env_file=[{"path": "/tmp/evil.env"}]),
        ]
        for mutate in mutations:
            config = policy()
            mutate(config)
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as tmp, \
                    self.assertRaises(api.ReleaseError):
                run_deploy(Runner(config=config), tmp)

    def test_inlined_environment_form_is_accepted_only_with_expected_keys(self):
        config = policy()
        for name, keys in (("chronicles-api", api.API_ENV_KEYS), ("chronicles-tunnel", api.TUNNEL_ENV_KEYS)):
            service = config["services"][name]
            service.pop("env_file")
            service["environment"] = {key: "x" for key in keys}
        with tempfile.TemporaryDirectory() as tmp:
            run_deploy(Runner(config=config), tmp)
        config["services"]["chronicles-tunnel"]["environment"]["MONGO_URL"] = "leak"
        with tempfile.TemporaryDirectory() as tmp, self.assertRaises(api.ReleaseError):
            run_deploy(Runner(config=config), tmp)

    def test_failed_docker_step_does_not_record_a_verified_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(api.ReleaseError):
                run_deploy(Runner(fail_at="up"), tmp)
            self.assertFalse(pathlib.Path(tmp, "state", "last-verified-api.json").exists())


class ProvisionAndReleaseContracts(unittest.TestCase):
    def test_inputs_are_validated_without_echoing_values(self):
        env = {"CHRONICLES_STAGING_MONGO_URL": "mongodb+srv://u:p@h/",
               "CHRONICLES_STAGING_JWT_SECRET": "s" * 64, "CHRONICLES_STAGING_INVITE_CODE": "INV"}
        self.assertEqual(set(provision.read_inputs(env)), {"MONGO_URL", "JWT_SECRET", "INVITE_CODE"})
        for key, value in (("CHRONICLES_STAGING_MONGO_URL", "postgres://x"),
                           ("CHRONICLES_STAGING_JWT_SECRET", "short"),
                           ("CHRONICLES_STAGING_INVITE_CODE", "")):
            with self.subTest(key=key), self.assertRaises(provision.ProvisionError) as caught:
                provision.read_inputs(dict(env, **{key: value}))
            self.assertNotIn("p@h", str(caught.exception))

    def test_tunnel_is_never_chess_studio_and_dns_is_never_overwritten(self):
        self.assertNotIn(provision.TUNNEL_NAME, provision.FORBIDDEN_TUNNELS)

        class FakeCF:
            account = "acc"

            def __init__(self, records):
                self.records, self.posts = records, []

            def call(self, method, path, payload=None):
                if path.startswith("/zones?"):
                    return [{"id": "zone"}]
                if "/dns_records?" in path:
                    return self.records
                self.posts.append((method, path, payload))
                return {}

        tunnel = "12345678-1234-1234-1234-123456789abc"
        foreign = FakeCF([{"type": "CNAME", "content": "other.cfargotunnel.com", "proxied": True}])
        with self.assertRaises(provision.ProvisionError):
            provision.ensure_dns(foreign, tunnel)
        self.assertEqual(foreign.posts, [])
        same = FakeCF([{"type": "CNAME", "content": tunnel + ".cfargotunnel.com", "proxied": True}])
        self.assertEqual(provision.ensure_dns(same, tunnel), "unchanged")
        fresh = FakeCF([])
        self.assertEqual(provision.ensure_dns(fresh, tunnel), "created")
        self.assertEqual(fresh.posts[-1][2]["content"], tunnel + ".cfargotunnel.com")
        self.assertEqual(provision.HOSTNAME.count("."), 3)  # one level: Universal SSL

    def test_legacy_record_is_retired_only_when_it_is_ours(self):
        tunnel = "12345678-1234-1234-1234-123456789abc"

        class FakeCF:
            account = "acc"

            def __init__(self, legacy):
                self.legacy, self.calls = legacy, []

            def call(self, method, path, payload=None):
                self.calls.append((method, path))
                if "/dns_records?" in path:
                    return self.legacy if "api-staging.chronicles" in path else []
                return {}

        ours = FakeCF([{"id": "r1", "type": "CNAME", "content": tunnel + ".cfargotunnel.com"}])
        provision.retire_legacy(ours, "zone", tunnel + ".cfargotunnel.com")
        self.assertIn(("DELETE", "/zones/zone/dns_records/r1"), ours.calls)
        foreign = FakeCF([{"id": "r2", "type": "CNAME", "content": "other.cfargotunnel.com"}])
        provision.retire_legacy(foreign, "zone", tunnel + ".cfargotunnel.com")
        self.assertFalse(any(m == "DELETE" for m, _ in foreign.calls))

    def test_release_command_carries_no_secret(self):
        command = release.command_for(DIGEST, VAULT)
        self.assertIn("/usr/local/sbin/shadowops-chronicles-api deploy " + DIGEST + " " + VAULT, command)
        for word in ("MONGO", "JWT", "TOKEN", "docker"):
            self.assertNotIn(word, command)
        with self.assertRaises(Exception):
            release.command_for(DIGEST, "ocid1.vault.x && curl evil")


if __name__ == "__main__":
    unittest.main()
