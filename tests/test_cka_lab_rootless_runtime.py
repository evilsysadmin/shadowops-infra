"""Rootless isolation, actual limit evidence and nonreplacement publication."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import cka_lab_rootless_policy as policy
spec = importlib.util.spec_from_file_location("cka_rootless_installer", ROOT / "host/install-cka-lab-staging.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class PackageIsolation(unittest.TestCase):
    def test_restart_suppression_is_passed_to_actual_apt_children_only(self):
        result = SimpleNamespace(returncode=0, stdout="done")
        original = dict(os.environ)
        with patch.object(installer.subprocess, "run", return_value=result) as execute:
            installer.run(["apt-get", "update"])
            environment = execute.call_args.kwargs["env"]
            self.assertEqual(environment["NEEDRESTART_SUSPEND"], "1")
            self.assertEqual(environment["NEEDRESTART_MODE"], "l")
            installer.run(["systemctl", "is-active", "example"])
            self.assertNotIn("NEEDRESTART_SUSPEND", execute.call_args.kwargs["env"])
        self.assertEqual(dict(os.environ), original)

    def test_only_new_packages_are_installed_after_simulation(self):
        plan = "Inst uidmap (1.0 Ubuntu:24.04/noble [arm64])\nConf uidmap (1.0 Ubuntu:24.04/noble [arm64])"
        with patch.object(installer, "run", side_effect=["", plan, ""]) as execute:
            installer.install_packages(["uidmap"])
        self.assertEqual(execute.call_count, 3)
        self.assertIn("--simulate", execute.call_args_list[1].args[0])
        actual = execute.call_args_list[2].args[0]
        self.assertIn("--no-upgrade", actual)
        self.assertIn("--no-remove", actual)
        self.assertNotIn("--simulate", actual)

    def test_upgrades_removals_and_foreign_pending_configuration_block_before_install(self):
        for plan in ["Inst systemd [1.0] (2.0 Ubuntu [arm64])",
                     "Remv docker.io [1.0]", "Conf openssh-server (1.0 Ubuntu [arm64])"]:
            with self.subTest(plan=plan), patch.object(installer, "run", side_effect=["", plan]) as execute:
                with self.assertRaises(ValueError):
                    installer.install_packages(["uidmap"])
                self.assertEqual(execute.call_count, 2)


class IdentityMappings(unittest.TestCase):
    def test_preserves_existing_disjoint_identity_ranges(self):
        uid = "other:1000000:65536\n"
        gid = "another:1065536:65536\n"
        start = policy.subordinate_range(uid, gid, [0, 1000, 1131072])
        self.assertGreater(start, 1131072)
        self.assertEqual(uid, "other:1000000:65536\n")

    def test_exact_existing_lab_mapping_is_idempotent(self):
        own = policy.USER + ":1000000:65536\n"
        self.assertEqual(policy.subordinate_range(own, own, [0, 1000]), 1000000)
        self.assertEqual(policy.subordinate_range(own, "", [0, 1000]), 1000000)

    def test_unsafe_malformed_overlapping_or_different_mappings_deny(self):
        own = policy.USER + ":1000000:65536\n"
        for uid, gid, identities in [
            (own, own, [1000001]),
            (own + "another:1000001:1\n", own, []),
            (own, policy.USER + ":2000000:65536\n", []),
            (own + own, own, []), ("other:bad:65536", "", []),
            ("other:0:1", "", []), ("other:1:0", "", []),
            (policy.USER + ":1000000:65535", "", []),
        ]:
            with self.subTest(uid=uid), self.assertRaises(policy.RuntimeError):
                policy.subordinate_range(uid, gid, identities)


class RuntimeEvidence(unittest.TestCase):
    def test_host_docker_cannot_substitute_for_the_dedicated_rootless_daemon(self):
        value = {"CgroupVersion": "2", "CgroupDriver": "systemd",
                 "DefaultRuntime": "cka-rootless-runc",
                 "DockerRootDir": str(policy.RUNTIME / "docker"), "SecurityOptions": ["name=rootless", "name=seccomp"]}
        policy.verify_daemon(value)
        for change in [{"CgroupVersion": "1"}, {"CgroupDriver": "none"},
                       {"DefaultRuntime": "runc"},
                       {"DockerRootDir": "/var/lib/docker"}, {"SecurityOptions": ["name=seccomp"]}]:
            with self.subTest(change=change), self.assertRaises(policy.RuntimeError):
                policy.verify_daemon({**value, **change})
        self.assertEqual(policy.daemon_config(1500)["hosts"], ["unix:///run/user/1500/cka-lab-docker.sock"])
        self.assertFalse(policy.daemon_config(1500)["live-restore"])

    def test_real_cgroup_values_must_bound_cpu_memory_pids_and_swap(self):
        valid = (str(policy.MEMORY_BYTES), "0", "55000 100000", "1024")
        policy.verify_cgroup(*valid)
        for index, value in [(0, "max"), (0, str(policy.MEMORY_BYTES + 1)), (0, "0"),
                             (1, "max"), (1, "1"), (2, "max 100000"), (2, "56000 100000"),
                             (2, "55000 0"), (3, "max"), (3, "1025")]:
            changed = list(valid)
            changed[index] = value
            with self.subTest(index=index, value=value), self.assertRaises(policy.RuntimeError):
                policy.verify_cgroup(*changed)

    def test_unbounded_host_folders_or_foreign_loop_disks_are_rejected(self):
        fs = {"source": "/dev/loop7", "target": str(policy.RUNTIME), "fstype": "ext4", "options": "rw,nodev,nosuid"}
        backing = str(policy.ROOT / "runtime.ext4")
        policy.verify_disk_mount({"filesystems": [fs]}, backing)
        for change in [{"source": "/dev/sda1"}, {"target": "/var/lib/docker"},
                       {"fstype": "xfs"}, {"options": "rw,nodev"}]:
            with self.subTest(change=change), self.assertRaises(policy.RuntimeError):
                policy.verify_disk_mount({"filesystems": [{**fs, **change}]}, backing)
        with self.assertRaises(policy.RuntimeError):
            policy.verify_disk_mount({"filesystems": [fs]}, "/other/runtime.ext4")

    def test_units_limit_only_the_new_user_and_do_not_cycle_with_default_target(self):
        service = (ROOT / "host/cka-lab-rootless-docker.service").read_text()
        self.assertIn("ConditionUser=shadowops-cka-lab", service)
        self.assertNotIn("After=default.target", service)
        self.assertNotIn("User=root", service)
        self.assertNotIn("/var/run/docker.sock", service)
        self.assertIn("DISABLE_HOST_LOOPBACK=true", service)
        self.assertIn("MemorySwapMax=0", policy.slice_dropin())
        self.assertIn("CPUQuota=55%", policy.slice_dropin())


class Publication(unittest.TestCase):
    def test_atomic_publication_is_idempotent_and_never_overwrites_other_content(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unit.service"
            with patch.object(installer, "root_path"):
                installer.publish(path, "fixed-reviewed-unit", mode=0o644)
            before = path.stat().st_mtime_ns
            with patch.object(installer, "root_path") as trusted:
                installer.publish(path, "fixed-reviewed-unit")
                trusted.assert_any_call(path)
                self.assertEqual(before, path.stat().st_mtime_ns)
                with self.assertRaises(ValueError):
                    installer.publish(path, "different-content")
            self.assertEqual(path.read_text(), "fixed-reviewed-unit")
            self.assertFalse(any(p.name.startswith(".cka-install-") for p in Path(temp).iterdir()))

    def test_racing_existing_path_cannot_be_truncated(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unit.service"
            def racing_link(source, destination):
                destination.write_text("other-owner-unit")
                raise FileExistsError()
            with patch.object(installer, "root_path"), patch.object(installer.os, "link", side_effect=racing_link):
                with self.assertRaises(FileExistsError):
                    installer.publish(path, "our-unit")
            self.assertEqual(path.read_text(), "other-owner-unit")
            self.assertEqual([p.name for p in Path(temp).iterdir()], ["unit.service"])

    def test_symlinks_are_rejected_before_any_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "foreign"
            target.write_text("foreign-content")
            link = Path(temp) / "policy"
            link.symlink_to(target)
            validate = installer.root_path
            def directory_only(path, *, directory=False):
                if not directory:
                    validate(path)
            with patch.object(installer, "root_path", side_effect=directory_only):
                with self.assertRaises(ValueError):
                    installer.publish(link, "foreign-content")
            self.assertEqual(target.read_text(), "foreign-content")

    @unittest.skipIf(os.geteuid() == 0, "requires a genuinely unprivileged directory")
    def test_untrusted_parent_denies_before_creating_any_policy_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "unit.service"
            with self.assertRaises(ValueError):
                installer.publish(path, "must-not-be-written")
            self.assertFalse(path.exists())

    def test_installer_cannot_run_as_the_unprivileged_oci_agent(self):
        with patch.object(installer.os, "geteuid", return_value=1000), patch.object(installer, "run") as execute:
            self.assertEqual(installer.main(), 77)
            execute.assert_not_called()

    def test_preflight_rejects_non_sha_before_reading_or_executing_source(self):
        with patch.object(installer, "run") as execute:
            with self.assertRaises(ValueError):
                installer.source_preflight("main; sudo sh")
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
