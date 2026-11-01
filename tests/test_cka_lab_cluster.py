import copy
import hashlib
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cka_lab_cluster as cluster


class FixedRootlessCluster(unittest.TestCase):
    def test_read_only_tool_check_does_not_create_missing_directory(self):
        with tempfile.TemporaryDirectory() as root:
            account = SimpleNamespace(pw_dir=root, pw_uid=os.getuid())
            with self.assertRaises(cluster.ClusterBootstrapError):
                cluster.tool(account, install=False)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_operator_bootstrap_uses_a_writable_private_home_and_fixed_socket(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            tools = home / "tools"
            tools.mkdir(mode=0o700)
            binary = tools / "kind"
            binary.write_bytes(b"synthetic pinned kind")
            binary.chmod(0o700)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            account = SimpleNamespace(pw_dir=root, pw_uid=os.getuid())
            observed = []
            def prepare(directory, *, env):
                # This real mkdir catches use of a root-owned sibling of home.
                self.assertEqual(directory, home / "cluster")
                directory.mkdir(mode=0o700)
                self.assertEqual(directory.stat().st_uid, os.getuid())
                self.assertEqual(env["DOCKER_HOST"], "unix:///run/user/" + str(os.getuid()) + "/cka-lab-docker.sock")
                observed.append(directory)
                return {"labs_enabled": False}
            with patch.object(cluster.pwd, "getpwnam", return_value=account), \
                 patch.object(cluster.os, "geteuid", return_value=1000), \
                 patch.object(cluster.sys, "argv", ["cka_lab_cluster.py", "bootstrap"]), \
                 patch.dict(cluster.KIND_HASHES, {os.uname().machine: ("native", digest)}), \
                 patch.object(cluster, "operator_headroom") as headroom, \
                 patch.object(cluster, "bootstrap", side_effect=prepare), patch("builtins.print"):
                cluster.main()
            self.assertEqual(observed, [home / "cluster"])
            headroom.assert_called_once_with(root)

    def test_operator_headroom_refuses_low_memory_or_private_disk(self):
        with patch.object(cluster.Path, "read_text", return_value="MemAvailable: 3145728 kB\n"), \
             patch.object(cluster.os, "statvfs", return_value=SimpleNamespace(f_bavail=4 * 1024**2, f_frsize=1024)):
            cluster.operator_headroom("private-home")
        for available, blocks in [(3145727, 4 * 1024**2), (3145728, 4 * 1024**2 - 1)]:
            with self.subTest(available=available, blocks=blocks), \
                 patch.object(cluster.Path, "read_text", return_value=f"MemAvailable: {available} kB\n"), \
                 patch.object(cluster.os, "statvfs", return_value=SimpleNamespace(f_bavail=blocks, f_frsize=1024)):
                with self.assertRaises(cluster.ClusterBootstrapError):
                    cluster.operator_headroom("private-home")

    def test_rootful_or_unenforced_daemon_is_rejected(self):
        good = {"SecurityOptions": ["name=rootless"], "CgroupVersion": "2", "CgroupDriver": "systemd"}
        cluster.rootless_info(good)
        for key, value in [("SecurityOptions", []), ("CgroupVersion", "1"), ("CgroupDriver", "cgroupfs")]:
            with self.assertRaises(cluster.ClusterBootstrapError):
                cluster.rootless_info({**good, key: value})

    def test_bridge_cannot_be_external_or_dual_stack(self):
        good = {"Name": cluster.NETWORK, "Driver": "bridge", "Internal": True,
                "EnableIPv6": False, "IPAM": {"Config": [{"Subnet": cluster.SUBNET}]}}
        cluster.network_policy(good)
        for key, value in [("Internal", False), ("EnableIPv6", True), ("Driver", "host"),
                           ("IPAM", {"Config": [{"Subnet": "0.0.0.0/0"}]})]:
            with self.assertRaises(cluster.ClusterBootstrapError):
                cluster.network_policy({**good, key: value})

    def test_node_requires_limits_private_bridge_and_exact_readonly_module_mount(self):
        good = {"Name": "/" + cluster.NODE, "Config": {"Image": cluster.NODE_IMAGE,
                "Labels": {"desktop.docker.io/ports/6443/tcp": cluster.NODE + ":6443"}},
                "HostConfig": {"Memory": 2 * 1024**3, "MemorySwap": 2 * 1024**3,
                    "NanoCpus": 400000000, "PidsLimit": 768, "NetworkMode": cluster.NETWORK,
                    "ExtraHosts": ["host.docker.internal:172.31.254.1"],
                    "RestartPolicy": {"Name": "unless-stopped"},
                    "Privileged": True, "Binds": ["/lib/modules:/lib/modules:ro"]},
                "NetworkSettings": {"Networks": {cluster.NETWORK: {}}, "Ports": {}},
                "Mounts": [{"Type": "bind", "Source": "/lib/modules", "Destination": "/lib/modules", "RW": False},
                           {"Type": "volume", "Destination": "/var"}]}
        cluster.node_policy(good)
        for key, value in [("Memory", 0), ("MemorySwap", -1), ("NanoCpus", 0),
                           ("PidsLimit", -1), ("NetworkMode", "host"),
                           ("Binds", ["/:/host", "/lib/modules:/lib/modules:ro"])]:
            bad = copy.deepcopy(good)
            bad["HostConfig"][key] = value
            with self.assertRaises(cluster.ClusterBootstrapError):
                cluster.node_policy(bad)
        for key, value in [("Networks", {cluster.NETWORK: {}, "bridge": {}}),
                           ("Ports", {"6443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "39001"}]})]:
            bad = copy.deepcopy(good)
            bad["NetworkSettings"][key] = value
            with self.assertRaises(cluster.ClusterBootstrapError):
                cluster.node_policy(bad)


    def test_verify_cluster_is_read_only_and_rejects_unhealthy_or_unbounded_node(self):
        import json
        import tempfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            for name, data in (("kind.yaml", cluster.CONFIG),
                               ("admin.yaml", "private"),
                               ("controller.yaml", "private")):
                target = directory / name
                target.write_text(data)
                target.chmod(0o600)
            directory.chmod(0o700)

            info = {"SecurityOptions": ["name=rootless"], "CgroupVersion": "2",
                    "CgroupDriver": "systemd"}
            net = {"Name": cluster.NETWORK, "Driver": "bridge", "Internal": True,
                   "EnableIPv6": False, "IPAM": {"Config": [{"Subnet": cluster.SUBNET}]}}
            node = {"Name": "/" + cluster.NODE, "Config": {"Image": cluster.NODE_IMAGE,
                    "Labels": {"desktop.docker.io/ports/6443/tcp": cluster.NODE + ":6443"}},
                    "State": {"Running": True},
                    "HostConfig": {"Memory": 2 * 1024**3, "MemorySwap": 2 * 1024**3,
                        "NanoCpus": 400000000, "PidsLimit": 768, "NetworkMode": cluster.NETWORK,
                        "ExtraHosts": ["host.docker.internal:172.31.254.1"],
                        "RestartPolicy": {"Name": "unless-stopped"},
                        "Privileged": True, "Binds": ["/lib/modules:/lib/modules:ro"]},
                    "NetworkSettings": {"Networks": {cluster.NETWORK: {}}, "Ports": {}},
                    "Mounts": [
                        {"Type": "bind", "Source": "/lib/modules",
                         "Destination": "/lib/modules", "RW": False},
                        {"Type": "volume", "Destination": "/var"}]}
            calls = []

            def fake_call(argv, *, env, timeout, stdin=None):
                calls.append(argv)
                if argv[:2] == ["docker", "info"]:
                    return json.dumps(info)
                if argv[:3] == ["docker", "network", "inspect"]:
                    return json.dumps([net])
                if argv[:2] == ["docker", "inspect"]:
                    return json.dumps([node])
                if argv[:3] == ["docker", "exec", cluster.NODE]:
                    return "ok\n"
                raise AssertionError("Unexpected or mutating CLI operation")

            with patch.object(cluster, "call", side_effect=fake_call):
                receipt = cluster.verify_cluster(directory, env={"DOCKER_HOST": "fixed-test-socket"})
                self.assertEqual(receipt["kubernetes_ready"], True)
                self.assertIs(receipt["labs_enabled"], False)
                self.assertEqual(len(calls), 4)
                for change in [
                    lambda: info.update(CgroupDriver="cgroupfs"),
                    lambda: net.update(Internal=False),
                    lambda: node["State"].update(Running=False),
                    lambda: node["HostConfig"].update(Memory=0),
                ]:
                    info["CgroupDriver"] = "systemd"
                    net["Internal"] = True
                    node["State"]["Running"] = True
                    node["HostConfig"]["Memory"] = 2 * 1024**3
                    change()
                    with self.assertRaises(cluster.ClusterBootstrapError):
                        cluster.verify_cluster(directory, env={})
                info["CgroupDriver"] = "systemd"
                net["Internal"] = True
                node["State"]["Running"] = True
                node["HostConfig"]["Memory"] = 2 * 1024**3
                (directory / "controller.yaml").chmod(0o644)
                with self.assertRaises(cluster.ClusterBootstrapError):
                    cluster.verify_cluster(directory, env={})
                (directory / "controller.yaml").chmod(0o600)
                (directory / "kind.yaml").write_text("changed")
                with self.assertRaises(cluster.ClusterBootstrapError):
                    cluster.verify_cluster(directory, env={})
                (directory / "kind.yaml").write_text(cluster.CONFIG)
                (directory / "kind.yaml").chmod(0o600)
                (directory / "admin.yaml").unlink()
                (directory / "admin.yaml").symlink_to("/etc/passwd")
                with self.assertRaises(cluster.ClusterBootstrapError):
                    cluster.verify_cluster(directory, env={})


if __name__ == "__main__":
    unittest.main()
