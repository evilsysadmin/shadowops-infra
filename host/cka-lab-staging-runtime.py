#!/usr/bin/python3 -I
"""Read-only fixed inspection of the dedicated rootless CKA staging runtime."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import grp
import re
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, "/usr/local/libexec/cka-lab-staging")
from cka_lab_rootless_policy import (
    USER, ROOT, RUNTIME, HOME_DIR, CONFIG, DISK_BYTES, RuntimeError,
    private_root_file, subordinate_range, verify_cgroup, verify_daemon, verify_disk_mount,
)


def run(args):
    value = subprocess.run(args, capture_output=True, text=True, timeout=20,
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    if value.returncode or len(value.stdout) > 131072:
        raise RuntimeError("Fixed runtime observation failed")
    return value.stdout.strip()


def inspect():
    policy = CONFIG / "policy.json"
    private_root_file(policy, maximum=16384)
    value = json.loads(policy.read_text())
    if (set(value) != {"schema", "source_sha", "files", "uid", "gid", "subordinate_start"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not re.fullmatch(r"[0-9a-f]{40}", str(value["source_sha"]))):
        raise RuntimeError("Invalid installed runtime receipt")
    user = pwd.getpwnam(USER)
    if (user.pw_uid != value["uid"] or user.pw_gid != value["gid"] or user.pw_uid == 0
            or user.pw_dir != str(HOME_DIR) or user.pw_shell != "/usr/sbin/nologin"
            or os.getgrouplist(USER, user.pw_gid) != [user.pw_gid]):
        raise RuntimeError("Runtime account identity changed")
    for filename, digest in value["files"].items():
        path = Path(filename)
        private_root_file(path, maximum=131072)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise RuntimeError("Runtime policy changed")
    maps = [Path("/etc/subuid"), Path("/etc/subgid")]
    for path in maps:
        private_root_file(path, maximum=1048576)
    start = subordinate_range(*[p.read_text() for p in maps],
                              [p.pw_uid for p in pwd.getpwall()] + [g.gr_gid for g in grp.getgrall()])
    if start != value["subordinate_start"]:
        raise RuntimeError("Runtime subordinate identity mapping changed")
    image = ROOT / "runtime.ext4"
    info = private_root_file(image)
    if info.st_size != DISK_BYTES or info.st_mode & 0o077:
        raise RuntimeError("Private runtime disk size changed")
    mount = json.loads(run(["findmnt", "--json", "--mountpoint", str(RUNTIME),
                            "--output", "SOURCE,TARGET,FSTYPE,OPTIONS"]))
    entries = mount.get("filesystems", [])
    if len(entries) != 1:
        raise RuntimeError("Missing private runtime mount")
    backing = run(["losetup", "--noheadings", "--output", "BACK-FILE", str(entries[0].get("source", ""))])
    verify_disk_mount(mount, backing)
    group = Path(f"/sys/fs/cgroup/user.slice/user-{user.pw_uid}.slice")
    verify_cgroup(*[(group / name).read_text() for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")])
    socket = f"unix:///run/user/{user.pw_uid}/cka-lab-docker.sock"
    data = run(["runuser", "--user", USER, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{user.pw_uid}",
                "/usr/bin/docker", "--host", socket, "info", "--format", "{{json .}}"])
    verify_daemon(json.loads(data))
    return {"schema": 1, "source_sha": value["source_sha"], "runtime": "dedicated-rootless-user",
            "disk_bytes": DISK_BYTES, "rootless_and_cgroups_verified": True,
            "kubernetes_started": False, "labs_enabled": False}


def main():
    if os.geteuid() != 0 or sys.argv[1:] != ["inspect"]:
        return 77
    try:
        value = inspect()
    except Exception:
        print("CKA_LAB_RUNTIME_INSPECTION_BLOCKED")
        return 1
    print("CKA_LAB_ROOTLESS_RUNTIME " + json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
