"""Fixed shared-A1 rootless lab envelope; no cloud or workload mutation."""
from __future__ import annotations

import math
from pathlib import Path
import re

USER = "shadowops-cka-lab"
ROOT = Path("/var/lib/shadowops-cka-lab-staging")
RUNTIME = ROOT / "runtime"
HOME_DIR = RUNTIME / "home"
CONFIG = Path("/etc/cka-lab-staging")
LIB = Path("/usr/local/libexec/cka-lab-staging")
DISK_BYTES = 8 * 1024**3
MEMORY_BYTES = 2816 * 1024**2
CPU_FRACTION = 0.55
PIDS = 1024
MAP_COUNT = 65536


class RuntimeError(ValueError):
    pass


def subordinate_range(uid_rows, gid_rows, system_ids, username=USER):
    """Choose one nonoverlapping UID/GID block; preserve an exact prior block."""
    occupied = []
    own = []
    for lines in (uid_rows, gid_rows):
        current = []
        for line in lines.splitlines():
            if not line.strip():
                continue
            parts = line.split(":")
            if len(parts) != 3 or not re.fullmatch(r"[0-9]+", parts[1]) or not re.fullmatch(r"[0-9]+", parts[2]):
                raise RuntimeError("Invalid subordinate identity map")
            who, start, count = parts[0], int(parts[1]), int(parts[2])
            if start < 1 or count < 1 or start + count > 2**32:
                raise RuntimeError("Invalid subordinate identity range")
            if who == username:
                current.append((start, count))
            else:
                occupied.append((start, start + count))
        if len(current) > 1 or (current and current[0][1] != MAP_COUNT):
            raise RuntimeError("Unexpected existing lab identity mapping")
        own.extend(current)
    if own and len({pair[0] for pair in own}) != 1:
        raise RuntimeError("Lab subordinate UID/GID mappings disagree")
    starts = [own[0][0]] if own else range(1_000_000, 2_000_000_000, MAP_COUNT)
    for start in starts:
        end = start + MAP_COUNT
        if (not any(start < right and left < end for left, right in occupied)
                and not any(start <= identity < end for identity in system_ids)):
            return start
    raise RuntimeError("No isolated subordinate identity mapping")


def daemon_config(uid):
    if type(uid) is not int or not 1 <= uid < 2**31:
        raise RuntimeError("Invalid runtime user")
    return {"hosts": [f"unix:///run/user/{uid}/cka-lab-docker.sock"],
            "data-root": str(RUNTIME / "docker"),
            "exec-root": f"/run/user/{uid}/cka-lab-docker",
            "pidfile": f"/run/user/{uid}/cka-lab-docker.pid",
            "exec-opts": ["native.cgroupdriver=systemd"], "storage-driver": "fuse-overlayfs",
            "log-driver": "local", "log-opts": {"max-size": "5m", "max-file": "2"},
            "live-restore": False, "shutdown-timeout": 15}


def slice_dropin():
    return f"[Slice]\nCPUQuota=55%\nMemoryMax={MEMORY_BYTES}\nMemorySwapMax=0\nTasksMax={PIDS}\nIOWeight=20\n"


def manager_dropin():
    return ("[Unit]\nRequires=shadowops-cka-lab-disk.service\nAfter=shadowops-cka-lab-disk.service\n"
            "[Service]\nDelegate=cpu cpuset io memory pids\n")


def disk_unit():
    return ("[Unit]\nDescription=Bounded private CKA staging runtime disk\n"
            "Before=multi-user.target\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
            f"ExecStart=/usr/bin/mount -t ext4 -o loop,nodev,nosuid {ROOT}/runtime.ext4 {RUNTIME}\n"
            f"ExecStop=/usr/bin/umount {RUNTIME}\nTimeoutStartSec=30\nTimeoutStopSec=30\n")


def verify_daemon(value):
    if (not isinstance(value, dict) or value.get("CgroupVersion") != "2"
            or value.get("CgroupDriver") != "systemd"
            or value.get("DockerRootDir") != str(RUNTIME / "docker")
            or "name=rootless" not in value.get("SecurityOptions", [])):
        raise RuntimeError("Runtime is not the bounded rootless daemon")


def verify_cgroup(memory, swap, cpu, pids):
    try:
        maximum = int(memory.strip())
        quota, period = [int(part) for part in cpu.split()]
        tasks = int(pids.strip())
        swap_maximum = int(swap.strip())
    except (ValueError, AttributeError):
        raise RuntimeError("Missing enforced runtime cgroup limits") from None
    if (not 0 < maximum <= MEMORY_BYTES or swap_maximum != 0 or not 0 < tasks <= PIDS
            or period <= 0 or quota <= 0 or not math.isfinite(quota / period)
            or quota / period > CPU_FRACTION):
        raise RuntimeError("Runtime cgroup envelope is not enforced")


def verify_disk_mount(document, backing):
    """Require the exact private loop filesystem, not an unbounded host folder."""
    filesystems = document.get("filesystems") if isinstance(document, dict) else None
    if not isinstance(filesystems, list) or len(filesystems) != 1:
        raise RuntimeError("Missing private runtime mount")
    fs = filesystems[0]
    if (not isinstance(fs, dict) or fs.get("target") != str(RUNTIME) or fs.get("fstype") != "ext4"
            or not re.fullmatch(r"/dev/loop[0-9]+", str(fs.get("source", "")))
            or not {"nodev", "nosuid"} <= set(str(fs.get("options", "")).split(","))
            or backing.strip() != str(ROOT / "runtime.ext4")):
        raise RuntimeError("Unsafe private runtime mount")


def private_root_file(path, *, maximum=None):
    info = path.lstat()
    if (path.is_symlink() or not path.is_file() or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o022 or (maximum is not None and info.st_size > maximum)):
        raise RuntimeError("Untrusted runtime policy file")
    return info
