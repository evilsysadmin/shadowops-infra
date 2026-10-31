"""Disposable CI only: host positive control and a private bounded controller."""
import os
from pathlib import Path
import socket

from cka_lab_cluster import NODE, NETWORK, call


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise RuntimeError("Disposable Linux CI only")
    with socket.create_connection(("1.1.1.1", 443), timeout=5):
        pass
    env = dict(os.environ)
    for name, value in {"memory.max": str(2 * 1024**3), "memory.swap.max": "0", "pids.max": "768"}.items():
        assert call(["docker", "exec", NODE, "cat", "/sys/fs/cgroup/" + name], env=env).strip() == value
    quota, period = map(int, call(["docker", "exec", NODE, "cat", "/sys/fs/cgroup/cpu.max"], env=env).split())
    assert quota / period <= 0.4
    root = Path(os.environ["RUNNER_TEMP"])
    admin = root / "cka-rootless-cluster/controller.yaml"
    call(["docker", "build", "-f", "deploy/Dockerfile.cka-lab-proof", "-t", "cka-rootless-proof", "."],
         env=env, timeout=300)
    result = call(["docker", "run", "--rm", "--read-only", "--network", NETWORK,
                  "--memory=256m", "--memory-swap=256m", "--cpus=0.1", "--pids-limit=64",
                  "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
                  "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=32m",
                  "--mount", "type=bind,source=" + str(admin) + ",target=/run/secrets/cka-lab-admin.yaml,readonly",
                  "--env", "CKA_DISPOSABLE_CI=true", "cka-rootless-proof"], env=env, timeout=600)
    print(result, end="")


if __name__ == "__main__":
    main()
