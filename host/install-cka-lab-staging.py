#!/usr/bin/python3 -I
"""Operator-only rootless runtime installation for the shared-A1 Compose pilot.

Requires an exact clean root-owned protected-main checkout. Never called through
OCI Run Command. No Kubernetes, cloud allocation, product restart or lab grant.
"""
from __future__ import annotations

import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import shlex
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

REPO = Path("/opt/shadowops-infra")
# A private source import is permitted only after this checkout's ownership and
# exact source are checked in main; tests explicitly import the pure policy.
POLICY_SOURCE = REPO / "scripts/cka_lab_rootless_policy.py"
FILES = {"host/vendor/dockerd-rootless.sh": "/usr/local/libexec/cka-lab-staging/dockerd-rootless.sh",
         "host/cka-lab-runc-rootless.sh": "/usr/local/libexec/cka-lab-staging/runc-rootless.sh",
         "host/vendor/MOBY-LICENSE": "/usr/local/libexec/cka-lab-staging/MOBY-LICENSE",
         "scripts/cka_lab_rootless_policy.py": "/usr/local/libexec/cka-lab-staging/cka_lab_rootless_policy.py",
         "host/cka-lab-enable-rootless.py": "/usr/local/libexec/cka-lab-staging/enable-rootless.py",
         "host/cka-lab-staging-runtime.py": "/usr/local/sbin/shadowops-cka-lab-staging",
         "host/cka-lab-rootless-docker.service": "/etc/systemd/user/cka-lab-rootless-docker.service",
         "host/cka-lab-rootless.sudoers": "/etc/sudoers.d/107-shadowops-cka-lab-staging"}


def run(args, *, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
                                 "DEBIAN_FRONTEND": "noninteractive"})
    if result.returncode or len(result.stdout) > 1_048_576:
        raise ValueError("Fixed installation operation failed")
    return result.stdout.strip()


def root_path(path, *, directory=False):
    info = path.lstat()
    if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Unsafe operator-owned path")
    if directory and not path.is_dir():
        raise ValueError("Operator directory missing")
    if not directory and (not path.is_file() or info.st_nlink != 1):
        raise ValueError("Operator file missing")


def source_preflight(sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid exact source")
    for parent in (REPO, *REPO.parents):
        root_path(parent, directory=True)
    # Git metadata is executable configuration from root's point of view.
    # Refuse user-writable metadata, symlinks and unexpectedly large checkouts.
    metadata = REPO / ".git"
    root_path(metadata, directory=True)
    count = 0
    for current, dirs, files in os.walk(metadata, followlinks=False):
        for name in dirs + files:
            path = Path(current) / name
            root_path(path, directory=path.is_dir())
            count += 1
            if count > 80000:
                raise ValueError("Unbounded operator Git metadata")
    for relative in ["host/install-cka-lab-staging.py", *FILES]:
        path = REPO / relative
        for parent in path.parents:
            root_path(parent, directory=True)
            if parent == REPO:
                break
        root_path(path)
    git = ["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(REPO)]
    if (run(git + ["rev-parse", "--show-toplevel"]) != str(REPO)
            or run(git + ["rev-parse", "HEAD"]) != sha
            or run(git + ["rev-parse", "refs/remotes/origin/main"]) != sha
            or run(git + ["status", "--porcelain", "--untracked-files=normal"])):
        raise ValueError("Clean exact protected-main source required")
    for relative in ["host/install-cka-lab-staging.py", *FILES]:
        data = (REPO / relative).read_bytes()
        digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if run(git + ["rev-parse", f"{sha}:{relative}"]) != digest:
            raise ValueError("Operator source bytes differ from the exact commit")
    if run(["uname", "-m"]) != "aarch64" or not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        raise ValueError("A1 cgroup v2 host required")
    if int(Path("/proc/sys/user/max_user_namespaces").read_text()) <= 0:
        raise ValueError("Host user namespaces unavailable")
    memory = next(int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
                  if line.startswith("MemAvailable:"))
    disk = os.statvfs("/var/lib")
    if memory < 3 * 1024**2 or disk.f_bavail * disk.f_frsize < 12 * 1024**3:
        raise ValueError("Insufficient shared-host reserve")
    for binary in ("docker", "dockerd", "runc", "awk", "nsenter", "sysctl", "systemctl", "loginctl", "runuser", "mount", "losetup", "findmnt", "fallocate", "mkfs.ext4", "blkid", "visudo"):
        if not shutil.which(binary):
            raise ValueError("Missing host runtime prerequisite")


def directory(path, mode=0o755, *, uid=0, gid=0):
    for parent in path.parents:
        root_path(parent, directory=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if path.is_symlink() or not path.is_dir() or info.st_uid != uid or info.st_mode & 0o022:
            raise ValueError("Unsafe existing installation directory")
        return
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    path.chmod(mode)


def publish(path, data, *, mode=0o644):
    for parent in path.parents:
        root_path(parent, directory=True)
    data = data.encode() if isinstance(data, str) else data
    if path.exists() or path.is_symlink():
        root_path(path)
        if path.read_bytes() != data:
            raise ValueError("Existing operator policy differs; explicit upgrade required")
        return
    fd, temporary = tempfile.mkstemp(prefix=".cka-install-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path) # publish without replacing an existing path
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        os.unlink(temporary)


def install(sha, policy):
    # These packages add rootless prerequisites; never install/replace/restart
    # the shared Docker engine and never execute a downloaded install script.
    required = {"newuidmap": "uidmap", "newgidmap": "uidmap", "rootlesskit": "rootlesskit",
                "slirp4netns": "slirp4netns", "fuse-overlayfs": "fuse-overlayfs",
                "dbus-run-session": "dbus-user-session"}
    packages = sorted({package for binary, package in required.items() if not shutil.which(binary)})
    if not Path("/usr/lib/systemd/user/dbus.socket").is_file() and "dbus-user-session" not in packages:
        packages.append("dbus-user-session")
    if packages:
        run(["apt-get", "update"], timeout=180)
        run(["apt-get", "install", "--yes", "--no-install-recommends", *packages], timeout=300)
    directory(policy.ROOT, 0o711)
    directory(policy.RUNTIME)
    directory(policy.CONFIG)
    for parent in [Path("/usr/local/libexec"), policy.LIB, Path("/etc/systemd/user")]:
        directory(parent)
    try:
        user = pwd.getpwnam(policy.USER)
    except KeyError:
        run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(policy.HOME_DIR),
             "--shell", "/usr/sbin/nologin", policy.USER])
        user = pwd.getpwnam(policy.USER)
    if (user.pw_uid == 0 or user.pw_dir != str(policy.HOME_DIR) or user.pw_shell != "/usr/sbin/nologin"
            or os.getgrouplist(policy.USER, user.pw_gid) != [user.pw_gid]):
        raise ValueError("Foreign or privileged existing runtime account")
    maps = [Path("/etc/subuid"), Path("/etc/subgid")]
    for path in maps:
        root_path(path)
    text = [path.read_text() for path in maps]
    start = policy.subordinate_range(*text, [p.pw_uid for p in pwd.getpwall()] + [g.gr_gid for g in grp.getgrall()])
    options = []
    for document, flag in zip(text, ["--add-subuids", "--add-subgids"]):
        if not any(line.startswith(policy.USER + ":") for line in document.splitlines()):
            options += [flag, f"{start}-{start + policy.MAP_COUNT - 1}"]
    if options:
        run(["usermod", *options, policy.USER])
    image = policy.ROOT / "runtime.ext4"
    if not image.exists() and not image.is_symlink():
        fd = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        run(["fallocate", "--length", str(policy.DISK_BYTES), str(image)])
        run(["mkfs.ext4", "-F", "-q", "-L", "cka-lab-stage", str(image)], timeout=120)
    else:
        info = policy.private_root_file(image)
        if (info.st_size != policy.DISK_BYTES or info.st_mode & 0o077
                or run(["blkid", "-s", "LABEL", "-o", "value", str(image)]) != "cka-lab-stage"
                or run(["blkid", "-s", "TYPE", "-o", "value", str(image)]) != "ext4"):
            raise ValueError("Foreign runtime backing filesystem")
    for source, target in FILES.items():
        mode = 0o755 if target.endswith(".sh") or target.endswith("shadowops-cka-lab-staging") else 0o644
        if "/sudoers.d/" in target:
            mode = 0o440
        publish(Path(target), (REPO / source).read_bytes(), mode=mode)
    runc = Path(shutil.which("runc")).resolve()
    root_path(runc)
    for parent in runc.parents:
        root_path(parent, directory=True)
    generated = {policy.CONFIG / "daemon.json": json.dumps(policy.daemon_config(user.pw_uid), sort_keys=True) + "\n",
                 policy.CONFIG / "runc.env": f"CKA_PARENT_UID={user.pw_uid}\nCKA_RUNC={shlex.quote(str(runc))}\n",
                 Path("/etc/systemd/system/shadowops-cka-lab-disk.service"): policy.disk_unit()}
    for parent, name, body in [
        (Path(f"/etc/systemd/system/user@{user.pw_uid}.service.d"), "cka-lab-runtime.conf", policy.manager_dropin()),
        (Path(f"/etc/systemd/system/user-{user.pw_uid}.slice.d"), "cka-lab-limits.conf", policy.slice_dropin()),
    ]:
        directory(parent)
        generated[parent / name] = body
    for path, body in generated.items():
        publish(path, body)
    run(["visudo", "--check", "--file", "/etc/sudoers.d/107-shadowops-cka-lab-staging"])
    run(["systemctl", "daemon-reload"])
    if os.path.ismount(policy.RUNTIME):
        # Never stack another mount over an existing (possibly foreign) disk.
        run(["systemctl", "is-active", "--quiet", "shadowops-cka-lab-disk.service"])
        mounted = json.loads(run(["findmnt", "--json", "--mountpoint", str(policy.RUNTIME),
                                  "--output", "SOURCE,TARGET,FSTYPE,OPTIONS"]))
        fs = mounted.get("filesystems", [])
        if len(fs) != 1:
            raise ValueError("Ambiguous runtime mount")
        backing = run(["losetup", "--noheadings", "--output", "BACK-FILE", str(fs[0].get("source", ""))])
        policy.verify_disk_mount(mounted, backing)
    else:
        if list(policy.RUNTIME.iterdir()):
            raise ValueError("Refusing to cover an existing runtime directory")
        run(["systemctl", "start", "shadowops-cka-lab-disk.service"])
    for path in [policy.HOME_DIR, policy.RUNTIME / "docker"]:
        directory(path, 0o700, uid=user.pw_uid, gid=user.pw_gid)
    # Never let root traverse or create paths below a user-writable home.
    run(["runuser", "--user", policy.USER, "--", "/usr/bin/python3", "-I",
         "/usr/local/libexec/cka-lab-staging/enable-rootless.py"])
    hashes = {str(Path(target)): hashlib.sha256((REPO / source).read_bytes()).hexdigest()
              for source, target in FILES.items()}
    hashes.update({str(path): hashlib.sha256(body.encode()).hexdigest() for path, body in generated.items()})
    receipt = {"schema": 1, "source_sha": sha, "files": hashes,
               "uid": user.pw_uid, "gid": user.pw_gid, "subordinate_start": start}
    publish(policy.CONFIG / "policy.json", json.dumps(receipt, sort_keys=True) + "\n", mode=0o400)
    run(["loginctl", "enable-linger", policy.USER])
    run(["systemctl", "start", f"user@{user.pw_uid}.service"])
    run(["runuser", "--user", policy.USER, "--", "env", f"XDG_RUNTIME_DIR=/run/user/{user.pw_uid}",
         f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{user.pw_uid}/bus", "systemctl", "--user", "start",
         "cka-lab-rootless-docker.service"], timeout=100)
    run(["/usr/local/sbin/shadowops-cka-lab-staging", "inspect"])


def main():
    try:
        if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] not in {"preflight", "install"}:
            return 77
        if Path(__file__).resolve() != REPO / "host/install-cka-lab-staging.py":
            raise ValueError("Run only the operator-owned checkout installer")
        sha = sys.argv[2]
        source_preflight(sha)
        sys.path.insert(0, str(POLICY_SOURCE.parent))
        import cka_lab_rootless_policy as policy
        if sys.argv[1] == "install":
            install(sha, policy)
            print("CKA_LAB_ROOTLESS_RUNTIME_INSTALLED source_sha=" + sha + " labs_enabled=false")
        else:
            print("CKA_LAB_OPERATOR_SOURCE_PREFLIGHT_OK source_sha=" + sha)
    except Exception:
        print("CKA_LAB_RUNTIME_INSTALL_BLOCKED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
