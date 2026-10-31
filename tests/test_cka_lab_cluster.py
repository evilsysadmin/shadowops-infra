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


if __name__ == "__main__":
    unittest.main()
