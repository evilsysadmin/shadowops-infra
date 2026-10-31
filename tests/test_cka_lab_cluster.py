import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import cka_lab_cluster as cluster


class FixedRootlessCluster(unittest.TestCase):
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
