"""Origin operator test: no real Docker command, OCI, DNS or secret file is used."""
from __future__ import annotations

from contextlib import nullcontext
import copy
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

FILE = Path(__file__).resolve().parents[1] / "host/identity-production-origin.py"
spec = importlib.util.spec_from_file_location("production_origin_operator", FILE)
op = importlib.util.module_from_spec(spec)
spec.loader.exec_module(op)
SHA = "c" * 40
DIGEST = "sha256:" + "a" * 64
TUNNEL_DIGEST = "sha256:" + "b" * 64
IMAGE = op.IMAGE + DIGEST


def render():
    return {
        "name": op.PROJECT,
        "services": {
            op.SERVICE: {
                "image": IMAGE, "command": ["serve-ready"],
                "user": "65532:65532", "read_only": True, "privileged": False,
                "restart": "no", "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "ports": [{"mode": "ingress", "target": 9443, "published": "19443",
                           "host_ip": "127.0.0.1", "protocol": "tcp"}],
                "networks": {"identity-origin": {}, "identity-mongo-egress": {}},
                "environment": {
                    "IDENTITY_PRODUCTION_CONFIG_FILE": "/run/secrets/identity-production.json",
                    "IDENTITY_INTERNAL_PORT": "9443",
                },
                "volumes": [{
                    "target": "/run/secrets/identity-production.json",
                    "read_only": True, "bind": {"create_host_path": False},
                }],
            },
            op.TUNNEL: {
                "image": "cloudflare/cloudflared@" + TUNNEL_DIGEST,
                "restart": "no", "ports": [],
                "networks": {"identity-origin": {}, "identity-tunnel-egress": {}},
            },
        },
        "networks": {"identity-origin": {"internal": True},
                     "identity-mongo-egress": {"name": op.MONGO_NETWORK, "external": True}},
    }

def render_origin():
    obj = copy.deepcopy(render())
    obj["services"].pop(op.TUNNEL)
    obj["networks"] = {
        "identity-origin": {
            "internal": True,
            "name": "shadowops-identity-production-origin",
        },
        "identity-mongo-egress": {
            "name": op.MONGO_NETWORK, "external": True,
        },
    }
    return obj



class DockerDouble:
    def __init__(self):
        self.config = render()
        self.origin_config = render_origin()
        self.events = []
        self.containers = []
        self.fail_up = False
        self.extra_service = False
        self.image_sha = SHA
        self.mongo_network = {
            "Name": op.MONGO_NETWORK, "Driver": "bridge", "Internal": True,
            "Labels": {
                "com.docker.compose.project": op.MONGO_OWNER,
                "com.docker.compose.network": "identity-mongo-egress",
                "com.docker.compose.version": "synthetic",
            },
            "Containers": {"a"*64: {"Name": op.MONGO_CONTAINER}},
        }

    def __call__(self, args, **kwargs):
        self.events.append(tuple(args))
        if args[:3] == ["docker", "network", "inspect"]:
            result = json.dumps(self.mongo_network)
        elif args[:2] == ["docker", "ps"]:
            result = "\n".join(x["Service"] + "|" + x["State"] for x in self.containers)
        elif args[:3] == ["docker", "image", "inspect"]:
            result = self.image_sha
        elif args[:2] == ["docker", "compose"]:
            if "config" in args:
                result = json.dumps(
                    self.origin_config if str(op.ORIGIN_OVERLAY) in args
                    else self.config
                )
            elif "ps" in args:
                result = "\n".join(json.dumps(x) for x in self.containers)
            elif "up" in args:
                if self.fail_up:
                    self.containers = [{"Service": op.SERVICE, "State": "exited", "Project": op.PROJECT}]
                    return SimpleNamespace(returncode=1, stdout="", stderr="secret mount details")
                self.containers = [{"Service": op.SERVICE, "State": "running", "Project": op.PROJECT}]
                if self.extra_service:
                    self.containers.append({"Service": op.TUNNEL, "State": "running", "Project": op.PROJECT})
                result = ""
            elif "stop" in args:
                for row in self.containers:
                    if row["Service"] == op.SERVICE:
                        row["State"] = "exited"
                result = ""
            else:
                raise AssertionError("unadmitted Docker command")
        else:
            raise AssertionError("foreign command")
        return SimpleNamespace(returncode=0, stdout=result, stderr="")


def gates():
    return mock.patch.multiple(op, env_contract=mock.DEFAULT,
                               exclusive=mock.DEFAULT, require_manual=mock.DEFAULT)


class OriginOperatorTests(unittest.TestCase):
    def test_plan_alone_requires_no_operator_secrets_or_docker(self):
        with mock.patch.object(op, "env_contract", side_effect=AssertionError("do not inspect")):
            self.assertEqual(op.main(["plan"]), 0)
        self.assertEqual(op.main([]), 2)
        self.assertEqual(op.main(["deploy"]), 2)

    def test_rendered_config_exact_security_and_negative_drift(self):
        op.check_compose_config(json.dumps(render()), IMAGE, TUNNEL_DIGEST)
        for poison in ("port", "image", "network", "tunnel-start", "volume",
                       "root", "privileged", "extra-service", "allow-restart"):
            with self.subTest(poison=poison):
                bad = copy.deepcopy(render())
                s = bad["services"][op.SERVICE]
                t = bad["services"][op.TUNNEL]
                if poison == "port":
                    s["ports"][0]["host_ip"] = "0.0.0.0"
                elif poison == "image":
                    s["image"] = "ghcr.io/evilsysadmin/staging@sha256:" + "a"*64
                elif poison == "network":
                    s["networks"]["identity-tunnel-egress"] = {}
                elif poison == "tunnel-start":
                    t["networks"]["identity-mongo-egress"] = {}
                elif poison == "volume":
                    s["volumes"][0]["read_only"] = False
                elif poison == "root":
                    s["user"] = "0:0"
                elif poison == "privileged":
                    s["privileged"] = True
                elif poison == "extra-service":
                    bad["services"]["unexpected"] = {}
                elif poison == "allow-restart":
                    s["restart"] = "unless-stopped"
                with self.assertRaises(op.Refused):
                    op.check_compose_config(json.dumps(bad), IMAGE, TUNNEL_DIGEST)

    def test_origin_only_compose_does_not_require_tunnel_configuration(self):
        op.check_origin_compose_config(json.dumps(render_origin()), IMAGE)
        for bad in ("port", "tunnel", "network", "root", "volume", "restart",
                    "network-name", "private-network", "mongo-not-external", "image"):
            with self.subTest(bad=bad):
                cfg = render_origin()
                o = cfg["services"][op.SERVICE]
                if bad == "port":
                    o["ports"][0]["host_ip"] = "0.0.0.0"
                elif bad == "tunnel":
                    cfg["services"][op.TUNNEL] = render()["services"][op.TUNNEL]
                elif bad == "network":
                    o["networks"]["identity-tunnel-egress"] = {}
                elif bad == "root":
                    o["user"] = "0:0"
                elif bad == "volume":
                    o["volumes"][0]["read_only"] = False
                elif bad == "restart":
                    o["restart"] = "always"
                elif bad == "network-name":
                    cfg["networks"]["identity-origin"]["name"] = "foreign-network"
                elif bad == "private-network":
                    cfg["networks"]["identity-origin"]["internal"] = False
                elif bad == "mongo-not-external":
                    cfg["networks"]["identity-mongo-egress"].pop("external")
                elif bad == "image":
                    o["image"] = "unreviewed/image:latest"
                with self.assertRaises(op.Refused):
                    op.check_origin_compose_config(json.dumps(cfg), IMAGE)

    def test_production_mongo_network_ownership_and_exact_participants(self):
        docker = DockerDouble()
        op.mongo_network_admission(runner=docker)
        self.assertTrue(any(x[:3] == ("docker", "network", "inspect") for x in docker.events))
        for label, mutate in (
            ("staging-owner", lambda n: n["Labels"].update(
                {"com.docker.compose.project": "shadowops-identity-staging"})),
            ("public-network", lambda n: n.update(Internal=False)),
            ("other-network", lambda n: n.update(Name="foreign-network")),
            ("other-service", lambda n: n["Containers"].update(
                {"b"*64: {"Name": "shadowops-identity-staging-identity-mongo-1"}})),
            ("missing-mongo", lambda n: n.update(Containers={})),
            ("untrusted-driver", lambda n: n.update(Driver="host")),
        ):
            with self.subTest(label=label):
                docker = DockerDouble()
                mutate(docker.mongo_network)
                with self.assertRaises(op.Refused):
                    op.mongo_network_admission(runner=docker)

    def test_stage_one_requires_no_tunnel_credentials_even_for_admission(self):
        origin_only = {
            "IDENTITY_PRODUCTION_IMAGE_DIGEST": DIGEST,
            "IDENTITY_PRODUCTION_SOURCE_SHA": SHA,
            "IDENTITY_PRODUCTION_BUNDLE_FILE": "/synthetic/origin-service.json",
            "IDENTITY_PRODUCTION_ORIGIN_CA_FILE": "/synthetic/origin-ca.pem",
        }
        with mock.patch.dict(os.environ, origin_only, clear=True), \
             mock.patch.object(op.runtime, "validate") as runtime_check, \
             mock.patch.object(op.origin, "ca_file", return_value=Path("/synthetic/origin-ca.pem")), \
             mock.patch.object(op.tunnel, "validate", side_effect=AssertionError("tunnel required too early")):
            self.assertEqual(op.origin_env_contract(), (SHA, IMAGE))
            runtime_check.assert_called_once_with(DIGEST, "/synthetic/origin-service.json")
        docker = DockerDouble()
        with mock.patch.object(op, "origin_env_contract", return_value=(SHA, IMAGE)):
            self.assertEqual(op.origin_admission(runner=docker), (SHA, IMAGE))
        self.assertTrue(any("config" in x and str(op.ORIGIN_OVERLAY) in x for x in docker.events))
        self.assertFalse(any("up" in x for x in docker.events))

    def test_project_wide_status_finds_tunnel_even_when_origin_overlay_is_used(self):
        docker = DockerDouble()
        docker.containers = [
            {"Service": op.SERVICE, "State": "running"},
            {"Service": op.TUNNEL, "State": "running"},
        ]
        found = op.project_container_status(runner=docker)
        self.assertEqual({x["Service"] for x in found}, {op.SERVICE, op.TUNNEL})
        self.assertTrue(any(x[:2] == ("docker", "ps") for x in docker.events))
        for malformed in ("unknown|running", "identity-production|garbage",
                          "identity-production|running\nidentity-production|running",
                          "identity-production", "|running"):
            with self.subTest(malformed=malformed):
                with mock.patch.object(op, "run", return_value=malformed):
                    with self.assertRaises(op.Refused):
                        op.project_container_status()

    def test_parse_status_requires_expected_project_and_services(self):
        self.assertEqual(op.parse_ps(""), [])
        self.assertEqual(len(op.parse_ps('[{"Service":"identity-production"}]')), 1)
        self.assertEqual(len(op.parse_ps('{"Service":"identity-production"}\n')), 1)
        for invalid in ("{bad", '{"Service":"staging"}',
                        '{"Service":"identity-production","Project":"foreign"}'):
            with self.subTest(invalid=invalid), self.assertRaises(op.Refused):
                op.parse_ps(invalid)

    def test_manual_gate_does_not_allow_ci_or_nonroot(self):
        with mock.patch.dict(os.environ, {"CI": "true"}):
            with self.assertRaises(op.Refused):
                op.require_manual(op.CONFIRM_START)
        with mock.patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": ""}), \
             mock.patch.object(op.os, "geteuid", return_value=1000):
            with self.assertRaises(op.Refused):
                op.require_manual(op.CONFIRM_START)
        with mock.patch.dict(os.environ, {"CI": "", "GITHUB_ACTIONS": ""}), \
             mock.patch.object(op.os, "geteuid", return_value=0), \
             mock.patch.object(op.sys.stdin, "isatty", return_value=True), \
             mock.patch("builtins.input", return_value="WRONG PHRASE"):
            with self.assertRaises(op.Refused):
                op.require_manual(op.CONFIRM_START)

    def test_admission_checks_pinned_image_revision(self):
        docker = DockerDouble()
        with mock.patch.object(op, "env_contract", return_value=(SHA, IMAGE)), \
             mock.patch.dict(os.environ, {"IDENTITY_PRODUCTION_TUNNEL_DIGEST": TUNNEL_DIGEST}):
            self.assertEqual(op.admission(runner=docker), (SHA, IMAGE))
            docker.image_sha = "d" * 40
            with self.assertRaises(op.Refused):
                op.admission(runner=docker)

    def test_start_only_origin_and_requires_local_tls_health(self):
        docker = DockerDouble()
        with mock.patch.object(op, "require_manual"), \
             mock.patch.object(op, "exclusive", return_value=nullcontext()), \
             mock.patch.object(op, "origin_admission", return_value=(SHA, IMAGE)), \
             mock.patch.object(op, "occupied", return_value=False), \
             mock.patch.object(op.origin, "ca_file", return_value=Path("/fixture/ca.pem")):
            op.start_origin(runner=docker, inspect=lambda ca: {"tls": "verified", "ready": "yes"})
        up = [x for x in docker.events if "up" in x]
        self.assertEqual(len(up), 1)
        self.assertEqual(up[0][-1], op.SERVICE)
        self.assertIn("--no-deps", up[0])
        self.assertIn("--no-build", up[0])
        self.assertIn("never", up[0])
        self.assertNotIn("identity-production-tunnel", up[0])
        self.assertFalse(any("stop" in x for x in docker.events))

    def test_fail_closed_poststart_tls_failure_stops_only_origin(self):
        for poison in ("unhealthy", "up-error", "tunnel-started"):
            with self.subTest(poison=poison):
                docker = DockerDouble()
                docker.fail_up = poison == "up-error"
                docker.extra_service = poison == "tunnel-started"
                with mock.patch.object(op, "require_manual"), \
                     mock.patch.object(op, "exclusive", return_value=nullcontext()), \
                     mock.patch.object(op, "origin_admission", return_value=(SHA, IMAGE)), \
                     mock.patch.object(op, "occupied", return_value=False), \
                     mock.patch.object(op.origin, "ca_file", return_value=Path("/fixture/ca.pem")), \
                     mock.patch.object(op.time, "sleep"):
                    def reject(ca):
                        raise op.Refused("synthetic fixture did not start")
                    with self.assertRaises(op.Refused):
                        op.start_origin(runner=docker, inspect=reject)
                stops = [x for x in docker.events if "stop" in x]
                self.assertEqual(len(stops), 1)
                self.assertEqual(stops[0][-1], op.SERVICE)

    def test_existing_origin_or_port_refuses_any_start(self):
        for condition in ("existing", "port"):
            docker = DockerDouble()
            if condition == "existing":
                docker.containers = [{"Service": op.SERVICE, "State": "running"}]
            with mock.patch.object(op, "require_manual"), \
                 mock.patch.object(op, "exclusive", return_value=nullcontext()), \
                 mock.patch.object(op, "origin_admission", return_value=(SHA, IMAGE)), \
                 mock.patch.object(op, "occupied", return_value=condition == "port"):
                with self.assertRaises(op.Refused):
                    op.start_origin(runner=docker)
                self.assertFalse(any("up" in x for x in docker.events))

    def test_stop_refuses_when_tunnel_running_and_only_stops_origin(self):
        for tunnel_active in (False, True):
            docker = DockerDouble()
            docker.containers = [{"Service": op.SERVICE, "State": "running"},
                                 {"Service": op.TUNNEL, "State": "running" if tunnel_active else "exited"}]
            with mock.patch.object(op, "require_manual"), \
                 mock.patch.object(op, "exclusive", return_value=nullcontext()), \
                 mock.patch.object(op, "origin_admission", return_value=(SHA, IMAGE)):
                if tunnel_active:
                    with self.assertRaises(op.Refused):
                        op.stop_origin(runner=docker)
                else:
                    op.stop_origin(runner=docker)
            stop_commands = [x for x in docker.events if "stop" in x]
            self.assertEqual(len(stop_commands), 0 if tunnel_active else 1)

    def test_lock_is_exclusive(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"operator.lock"
            with op.exclusive(path):
                with self.assertRaises(op.Refused):
                    with op.exclusive(path):
                        pass

if __name__ == "__main__":
    unittest.main()
