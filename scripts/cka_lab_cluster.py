#!/usr/bin/env python3
"""Operator-only bootstrap in the existing dedicated rootless lab daemon.

Not a root wrapper or public API. No Docker authority belongs in the controller.
The imported bootstrap function is also exercised in a disposable rootless CI
daemon. The operator CLI fixes its user/socket/state paths and accepts no paths.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys


NAME = "cka-lab-staging"
NODE = NAME + "-control-plane"
NETWORK = "shadowops-cka-lab-staging-cluster"
SUBNET = "172.31.254.0/24"
NODE_IMAGE = "kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f"
FIXTURE_IMAGE = "ghcr.io/nginxinc/nginx-unprivileged:1.27-alpine@sha256:e234d4f7e346c098f7b22245690372382aded5be988611eb2c53ae62231eece7"
PROBE_IMAGE = "python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f"
CONFIG = """kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: cka-lab-staging
networking:
  apiServerAddress: 127.0.0.1
nodes:
  - role: control-plane
"""


class ClusterBootstrapError(RuntimeError):
    pass


def call(argv, *, env, timeout=30):
    try:
        result = subprocess.run(argv, env=env, capture_output=True, text=True,
                                timeout=timeout, check=False)
        if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 1048576:
            if argv[:3] == ["kind", "create", "cluster"] and env.get("GITHUB_ACTIONS") == "true":
                # Only this disposable cluster initialization: no live Identity
                # configuration or application credential exists in the CI job.
                print(result.stderr[:12000], file=sys.stderr)
            raise ClusterBootstrapError("Lab cluster operation failed")
        return result.stdout
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ClusterBootstrapError("Lab cluster operation unavailable") from None


def rootless_info(info):
    if ("name=rootless" not in info.get("SecurityOptions", [])
            or info.get("CgroupVersion") != "2" or info.get("CgroupDriver") != "systemd"):
        raise ClusterBootstrapError("Dedicated rootless cgroup v2 runtime required")


def network_policy(info):
    ipam = info.get("IPAM", {}).get("Config", [])
    if (info.get("Name") != NETWORK or info.get("Driver") != "bridge"
            or info.get("Internal") is not True or info.get("EnableIPv6") is not False
            or len(ipam) != 1 or ipam[0].get("Subnet") != SUBNET):
        raise ClusterBootstrapError("Private internal lab bridge required")


def node_policy(info):
    config = info.get("HostConfig", {})
    networks = info.get("NetworkSettings", {}).get("Networks", {})
    # Privileged is inside the dedicated rootless user namespace, verified above.
    if (info.get("Name") != "/" + NODE or info.get("Config", {}).get("Image") != NODE_IMAGE
            or config.get("Memory") != 2 * 1024**3 or config.get("MemorySwap") != 2 * 1024**3
            or config.get("NanoCpus") != 400000000 or config.get("PidsLimit") != 768
            or config.get("ExtraHosts") != ["host.docker.internal:172.31.254.1"]
            or set(networks) != {NETWORK} or config.get("NetworkMode") != NETWORK
            or not config.get("Privileged")
            or set(config.get("Binds") or []) - {"/var"} != {"/lib/modules:/lib/modules:ro"}
            or any(m.get("Type") == "bind" and not (
                m.get("Source") == "/lib/modules" and m.get("Destination") == "/lib/modules"
                and m.get("RW") is False) for m in info.get("Mounts", []))
            or not any(m.get("Type") == "volume" and m.get("Destination") == "/var"
                       for m in info.get("Mounts", []))):
        raise ClusterBootstrapError("Bounded private rootless node required")
    ports = info.get("NetworkSettings", {}).get("Ports", {})
    if any(bindings for bindings in ports.values()):
        raise ClusterBootstrapError("The internal Kubernetes API must not publish a host port")
    if info.get("Config", {}).get("Labels", {}).get("desktop.docker.io/ports/6443/tcp") != NODE + ":6443":
        raise ClusterBootstrapError("Explicit container-network API endpoint required")


def bootstrap(directory: Path, *, env=None):
    """Create a new fixed cluster, refusing existing nodes, bridge or credentials.

    The caller provides an explicitly selected dedicated rootless daemon. Never
    fallback to another context/socket if any command or policy check fails.
    Failure leaves this private cluster offline for operator diagnosis/removal.
    """
    env = dict(os.environ if env is None else env)
    env.update(KIND_EXPERIMENTAL_PROVIDER="docker", KIND_EXPERIMENTAL_DOCKER_NETWORK=NETWORK)
    def run(*args, timeout=30):
        return call(list(args), env=env, timeout=timeout)
    def inspect(binary, *args):
        return json.loads(run(binary, *args))

    rootless_info(inspect("docker", "info", "--format", "{{json .}}"))
    if run("kind", "version").split()[1] != "v0.31.0":
        raise ClusterBootstrapError("Reviewed kind v0.31.0 required")
    if run("docker", "ps", "-aq").strip() or run("docker", "network", "ls", "--filter", "name=^" + NETWORK + "$", "-q").strip():
        raise ClusterBootstrapError("Initial cluster bootstrap requires an empty dedicated daemon")
    if not directory.is_absolute() or directory.is_symlink() or directory.exists():
        raise ClusterBootstrapError("New private cluster workspace required")
    directory.mkdir(mode=0o700)
    config = directory / "kind.yaml"
    config.write_text(CONFIG)
    config.chmod(0o600)
    kubeconfig = directory / "admin.yaml"
    # kind's node entrypoint uses host.docker.internal (or a default route) to
    # rewrite Docker DNS rules. Internal bridges deliberately have no default
    # route. Supply only that fixed host alias to the pinned node's docker run;
    # preserve the internal bridge and its egress filtering. kind has no config
    # field for Docker ExtraHosts. Every other Docker call is forwarded intact.
    docker_binary = shutil.which("docker", path=env.get("PATH"))
    if not docker_binary or not Path(docker_binary).is_absolute():
        raise ClusterBootstrapError("Explicit Docker CLI required")
    shim_dir = directory / "tools"
    shim_dir.mkdir(mode=0o700)
    shim = shim_dir / "docker"
    shim.write_text("#!/usr/bin/python3\nimport os,sys\n"
        + "binary=" + repr(docker_binary) + "\nargs=sys.argv[1:]\n"
        + "if args and args[0]=='run' and args[-1]==" + repr(NODE_IMAGE) + ":\n"
        + " args[1:1]=['--add-host=host.docker.internal:172.31.254.1',"
        + repr("--label=desktop.docker.io/ports/6443/tcp=" + NODE + ":6443") + "]\n"
        + "os.execv(binary,[binary,*args])\n")
    shim.chmod(0o700)
    env["PATH"] = str(shim_dir) + os.pathsep + env.get("PATH", "/usr/local/bin:/usr/bin:/bin")
    run("docker", "network", "create", "--internal", "--subnet", SUBNET,
        "--label", "labs.shadowops.org/managed=staging-v1", NETWORK)
    network_policy(inspect("docker", "network", "inspect", NETWORK)[0])
    # Image pulls are trusted bootstrap work in the daemon, never pod egress.
    for image in (NODE_IMAGE, FIXTURE_IMAGE, PROBE_IMAGE):
        run("docker", "pull", "--quiet", image, timeout=300)
    run("kind", "create", "cluster", "--name", NAME, "--image", NODE_IMAGE,
        "--config", str(config), "--kubeconfig", str(kubeconfig), "--retain", "--wait", "300s", timeout=600)
    kubeconfig.chmod(0o600)
    run("docker", "update", "--memory=2g", "--memory-swap=2g", "--cpus=0.4",
        "--pids-limit=768", NODE)
    node_policy(inspect("docker", "inspect", NODE)[0])
    run("kind", "load", "docker-image", FIXTURE_IMAGE, "--name", NAME, timeout=180)
    run("kind", "load", "docker-image", PROBE_IMAGE, "--name", NAME, timeout=180)
    run("docker", "exec", NODE, "kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
        "--request-timeout=10s", "wait", "--for=condition=Ready", "node/" + NODE, "--timeout=120s", timeout=130)
    # Compose can mount a separate config using the TLS SAN already minted by kind.
    internal = directory / "controller.yaml"
    result = run("kind", "get", "kubeconfig", "--name", NAME, "--internal")
    internal.write_text(result)
    internal.chmod(0o600)
    network_policy(inspect("docker", "network", "inspect", NETWORK)[0])
    return {"schema": 1, "rootless": True, "internal_network": True,
            "node_memory_mib": 2048, "node_cpu_percent": 40, "node_pids": 768,
            "labs_enabled": False}


def main():
    if sys.argv[1:] != ["bootstrap"] or os.geteuid() == 0:
        raise ClusterBootstrapError("Run bootstrap as the dedicated non-root runtime user")
    account = pwd.getpwnam("shadowops-cka-lab")
    if os.getuid() != account.pw_uid:
        raise ClusterBootstrapError("Dedicated lab runtime user required")
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
           "HOME": account.pw_dir, "XDG_RUNTIME_DIR": "/run/user/" + str(account.pw_uid),
           "DOCKER_HOST": "unix:///run/user/" + str(account.pw_uid) + "/cka-lab-docker.sock"}
    receipt = bootstrap(Path("/var/lib/shadowops-cka-lab-staging/runtime/cluster"), env=env)
    print("CKA_LAB_CLUSTER_PREPARED " + json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ClusterBootstrapError, KeyError, TypeError, ValueError, IndexError, OSError):
        print("CKA_LAB_CLUSTER_UNAVAILABLE", file=sys.stderr)
        sys.exit(1)
