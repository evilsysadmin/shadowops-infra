#!/usr/bin/python3 -I
"""Enable only the fixed user unit, always as the unprivileged runtime user."""
import os
from pathlib import Path
import pwd

user = pwd.getpwnam("shadowops-cka-lab")
expected = Path("/var/lib/shadowops-cka-lab-staging/runtime/home")
if os.geteuid() == 0 or os.geteuid() != user.pw_uid or user.pw_dir != str(expected):
    raise SystemExit(77)
directory = expected / ".config/systemd/user/default.target.wants"
directory.mkdir(parents=True, exist_ok=True, mode=0o700)
link = directory / "cka-lab-rootless-docker.service"
target = "/etc/systemd/user/cka-lab-rootless-docker.service"
if link.is_symlink():
    if os.readlink(link) != target:
        raise SystemExit(66)
elif link.exists():
    raise SystemExit(66)
else:
    os.symlink(target, link)
