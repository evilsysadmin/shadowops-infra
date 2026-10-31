#!/usr/bin/env python3
"""Operator-only bootstrap in the existing dedicated rootless lab daemon.

Not a root wrapper or public API. No Docker authority belongs in the controller.
The imported bootstrap function is also exercised in a disposable rootless CI
daemon. The operator CLI fixes its user/socket/state paths and accepts no paths.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import urllib.request


NAME = "cka-lab-staging"
NODE = NAME + "-control-plane"
NETWORK = "shadowops-cka-lab-staging-cluster"
SUBNET = "172.31.254.0/24"
NODE_IMAGE = "kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f"
FIXTURE_IMAGE = "ghcr.io/nginxinc/nginx-unprivileged:1.27-alpine@sha256:e234d4f7e346c098f7b22245690372382aded5be988611eb2c53ae62231eece7"
PROBE_IMAGE = "python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f"
KIND_HASHES = {"aarch64": ("arm64", "8e1014e87c34901cc422a1445866835d1e666f2a61301c27e722bdeab5a1f7e4"),
               "x86_64": ("amd64", "eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa")}
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


def call(argv, *, env, timeout=30, stdin=None):
    try:
        result = subprocess.run(argv, env=env, capture_output=True, text=True,
                                timeout=timeout, check=False, stdin=stdin)
        if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 1048576:
            if argv[:3] in (["kind", "create", "cluster"], ["kind", "load", "docker-image"]) and env.get("GITHUB_ACTIONS") == "true":
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
            or config.get("RestartPolicy", {}).get("Name") != "unless-stopped"
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

    def preload(image):
        # containerd's transfer importer does not advertise unpack platforms for
        # the rootless FUSE snapshotter. Use its local, single-platform importer.
        # Pull remains digest-pinned; verify the final CRI config digest too.
        architecture = inspect("docker", "image", "inspect", image)[0]["Architecture"]
        if architecture not in {"arm64", "amd64"}:
            raise ClusterBootstrapError("Reviewed native image architecture required")
        original_id = inspect("docker", "image", "inspect", image)[0]["Id"]
        alias = "localhost/cka-preloaded:sha-" + image.split("@sha256:")[1]
        run("docker", "image", "tag", image, alias)
        archive = directory / "preload.tar"
        try:
            run("docker", "image", "save", "--output", str(archive), alias, timeout=120)
            archive.chmod(0o600)
            with archive.open("rb") as stream:
                call(["docker", "exec", "--privileged", "-i", NODE, "ctr", "--namespace=k8s.io",
                      "images", "import", "--local", "--platform=linux/" + architecture,
                      "--digests", "--snapshotter=fuse-overlayfs", "-"], env=env, timeout=180, stdin=stream)
        finally:
            archive.unlink(missing_ok=True)
        fully_qualified = image if image.startswith("ghcr.io/") else "docker.io/library/" + image
        without_tag = fully_qualified.split("@")[0].split(":")[0] + "@" + fully_qualified.split("@")[1]
        for target in dict.fromkeys([fully_qualified, without_tag]):
            run("docker", "exec", NODE, "ctr", "--namespace=k8s.io", "images", "tag", alias, target)
        evidence = inspect("docker", "exec", NODE, "crictl", "inspecti", without_tag)
        if evidence.get("status", {}).get("id") != original_id:
            raise ClusterBootstrapError("Preloaded image bytes do not match the pinned pull")

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
        "--pids-limit=768", "--restart=unless-stopped", NODE)
    node_policy(inspect("docker", "inspect", NODE)[0])
    preload(FIXTURE_IMAGE)
    preload(PROBE_IMAGE)
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



def verify_cluster(directory: Path, *, env=None):
    """Read-only operator gate after bootstrap; never creates or heals state.

    This evidence is intentionally narrower than an end-to-end candidate smoke:
    it proves the existing bounded rootless node, internal bridge, private
    credentials and the live Kubernetes API. It never grants lab access.
    """
    env = dict(os.environ if env is None else env)
    if (not directory.is_absolute() or directory.is_symlink() or not directory.is_dir()
            or directory.stat().st_uid != os.geteuid()
            or directory.stat().st_mode & 0o077):
        raise ClusterBootstrapError("Private cluster state unavailable")
    for name in ("kind.yaml", "admin.yaml", "controller.yaml"):
        path = directory / name
        if (path.is_symlink() or not path.is_file()
                or path.stat().st_uid != os.geteuid()
                or path.stat().st_mode & 0o077):
            raise ClusterBootstrapError("Private cluster credentials unavailable")
    if (directory / "kind.yaml").read_text() != CONFIG:
        raise ClusterBootstrapError("Pinned cluster definition changed")

    def read(*args):
        return call(list(args), env=env, timeout=15)

    def inspect(*args):
        try:
            return json.loads(read(*args))
        except (ValueError, TypeError, RecursionError):
            raise ClusterBootstrapError("Malformed private runtime inspection") from None

    rootless_info(inspect("docker", "info", "--format", "{{json .}}"))
    network_policy(inspect("docker", "network", "inspect", NETWORK)[0])
    node = inspect("docker", "inspect", NODE)[0]
    node_policy(node)
    if node.get("State", {}).get("Running") is not True:
        raise ClusterBootstrapError("Private Kubernetes node is stopped")
    # Private node control-plane credentials are internal to the container.
    # No user-supplied host path, kube context, public port or Docker socket.
    if read("docker", "exec", NODE, "kubectl",
            "--kubeconfig=/etc/kubernetes/admin.conf",
            "--request-timeout=8s", "get", "--raw", "/readyz").strip() != "ok":
        raise ClusterBootstrapError("Private Kubernetes API is not ready")
    return {"schema": 1, "rootless_verified": True, "private_network_verified": True,
            "bounded_node_verified": True, "kubernetes_ready": True,
            "labs_enabled": False}


def tool(account, *, install):
    architecture, expected = KIND_HASHES[os.uname().machine]
    directory = Path(account.pw_dir) / "tools"
    if directory.is_symlink():
        raise ClusterBootstrapError("Private tool directory required")
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.stat().st_uid != account.pw_uid or directory.stat().st_mode & 0o077:
        raise ClusterBootstrapError("Private tool directory required")
    target = directory / "kind"
    if not target.exists() and install:
        temporary = directory / "kind.download"
        try:
            with temporary.open("xb") as output:
                temporary.chmod(0o600)
                url = "https://github.com/kubernetes-sigs/kind/releases/download/v0.31.0/kind-linux-" + architecture
                with urllib.request.urlopen(url, timeout=30) as response:
                    if not response.geturl().startswith("https://"):
                        raise ClusterBootstrapError("HTTPS tool distribution required")
                    size = 0
                    while chunk := response.read(65536):
                        size += len(chunk)
                        if size > 32 * 1024**2:
                            raise ClusterBootstrapError("Oversized tool distribution")
                        output.write(chunk)
            if hashlib.file_digest(temporary.open("rb"), "sha256").hexdigest() != expected:
                raise ClusterBootstrapError("Unreviewed kind binary rejected")
            temporary.chmod(0o700)
            os.link(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    if (target.is_symlink() or not target.is_file() or target.stat().st_uid != account.pw_uid
            or target.stat().st_mode & 0o077
            or hashlib.file_digest(target.open("rb"), "sha256").hexdigest() != expected):
        raise ClusterBootstrapError("Reviewed private kind binary required")
    return directory


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"install-tools", "bootstrap", "verify-cluster"} or os.geteuid() == 0:
        raise ClusterBootstrapError("Run the fixed command as the dedicated non-root runtime user")
    account = pwd.getpwnam("shadowops-cka-lab")
    if os.getuid() != account.pw_uid:
        raise ClusterBootstrapError("Dedicated lab runtime user required")
    tools = tool(account, install=sys.argv[1] == "install-tools")
    if sys.argv[1] == "install-tools":
        print("CKA_LAB_KIND_TOOL_VERIFIED v0.31.0")
        return
    env = {"PATH": str(tools) + ":/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
           "HOME": account.pw_dir, "XDG_RUNTIME_DIR": "/run/user/" + str(account.pw_uid),
           "DOCKER_HOST": "unix:///run/user/" + str(account.pw_uid) + "/cka-lab-docker.sock"}
    directory = Path("/var/lib/shadowops-cka-lab-staging/runtime/cluster")
    if sys.argv[1] == "verify-cluster":
        receipt = verify_cluster(directory, env=env)
        print("CKA_LAB_CLUSTER_VERIFIED " + json.dumps(receipt, sort_keys=True))
        return
    receipt = bootstrap(directory, env=env)
    print("CKA_LAB_CLUSTER_PREPARED " + json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ClusterBootstrapError, KeyError, TypeError, ValueError, IndexError, OSError):
        print("CKA_LAB_CLUSTER_UNAVAILABLE", file=sys.stderr)
        sys.exit(1)
