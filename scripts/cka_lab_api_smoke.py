"""Disposable CI only: actual signed image + Compose + rootless Kubernetes.

All Identity material is freshly generated synthetic fixture data. This program
has no OCI SDK/credentials, production secret access or live deployment path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from cka_lab_cluster import NETWORK, NODE, call, rootless_info, verify_cluster


IMAGE = "ghcr.io/evilsysadmin/cka-lab-staging"
IDENTITY = "id-staging.shadowops.dpdns.org"
LAB_HOST = "cka-labs-staging.shadowops.dpdns.org"
PROJECT = "shadowops-cka-published-api-ci"
FIXTURE = "cka-published-api-ci-identity"
CLIENT = "cka-published-api-ci-browser"
RUNTIME = "/var/lib/shadowops-cka-lab-staging/runtime"
EGRESS = "shadowops-cka-lab-staging-identity-egress"


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise RuntimeError("Disposable Linux CI only")
    source, digest = os.environ["CKA_API_TEST_SOURCE"], os.environ["CKA_API_TEST_DIGEST"]
    if not re.fullmatch(r"[a-f0-9]{40}", source) or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise RuntimeError("Immutable reviewed publication required")
    image = IMAGE + "@" + digest
    env = dict(os.environ)
    env["CKA_LAB_IMAGE_DIGEST"] = digest

    def run(*args, timeout=30):
        # Diagnostics are safe here: this disposable job contains only synthetic
        # Identity material. Never invoke this path with live credentials.
        result = subprocess.run(list(args), env=env, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            print((result.stderr or result.stdout)[-8000:])
            raise RuntimeError("Published CKA API proof failed")
        if len(result.stdout) + len(result.stderr) > 1048576:
            raise RuntimeError("Oversized CI command output")
        return result.stdout

    rootless_info(json.loads(call(["docker", "info", "--format", "{{json .}}"], env=env)))
    workspace = Path(env["RUNNER_TEMP"]) / "cka-rootless-cluster"
    verify_cluster(workspace, env=env)
    admitted = run("node", "scripts/cka_lab_image_admission.mjs", source, digest, timeout=120)
    assert admitted.startswith("CKA_LAB_IMAGE_ADMITTED ")
    run("docker", "pull", "--quiet", image, timeout=180)
    metadata = json.loads(run("docker", "image", "inspect", image))[0]
    assert metadata["Config"]["Labels"]["org.opencontainers.image.revision"] == source
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[os.uname().machine]
    assert metadata["Architecture"] == architecture

    with tempfile.TemporaryDirectory(prefix="cka-published-api-ci-", dir=env["RUNNER_TEMP"]) as temporary:
        private = Path(temporary)
        fixture = private / "fixture"
        fixture.mkdir(mode=0o700)
        runtime = private / "runtime"
        for name in ("config", "cluster", "controller-state"):
            (runtime / name).mkdir(mode=0o700, parents=True)
        fixture_script = Path("scripts/cka_lab_api_fixture.py").resolve()
        candidate_script = Path("scripts/cka_lab_api_candidate.py").resolve()
        common = ["docker", "run", "--rm", "--user=0:0", "--read-only", "--cap-drop=ALL",
                  "--security-opt=no-new-privileges:true", "--pids-limit=32", "--memory=128m",
                  "--memory-swap=128m", "--cpus=0.05", "--env=CKA_DISPOSABLE_CI=true",
                  "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=8m", "--entrypoint=python"]
        run(*common, "--network=none", "--volume", str(fixture) + ":/fixture",
            "--volume", str(fixture_script) + ":/test/authority.py:ro", image,
            "/test/authority.py", "generate", source, timeout=60)
        shutil.copyfile(fixture / "lab.json", runtime / "config/lab.json")
        shutil.copyfile(workspace / "controller.yaml", runtime / "cluster/controller.yaml")
        (runtime / "config/tunnel.env").touch(mode=0o600)
        for path in [runtime / "config/lab.json", runtime / "cluster/controller.yaml"]:
            path.chmod(0o600)

        # Use the actual product Compose policy. Only paths and native platform
        # differ in disposable CI; the extra mount supplies the synthetic CA.
        definition = Path("compose.cka-lab.staging.yaml").read_text()
        assert definition.count(RUNTIME) == 4
        definition = definition.replace(RUNTIME, str(runtime)).replace("platform: linux/arm64", "platform: linux/" + architecture)
        compose = private / "compose.yaml"
        compose.write_text(definition)
        trust = private / "test-ca.json"
        trust.write_text(json.dumps({"services": {"cka-lab": {"volumes": [
            str(fixture / "ca.pem") + ":/opt/runtime/certifi/cacert.pem:ro"]}}}))
        command = ["docker", "compose", "--project-name", PROJECT, "-f", str(compose), "-f", str(trust)]

        def namespaces():
            result = json.loads(run("docker", "exec", NODE, "kubectl",
                "--kubeconfig=/etc/kubernetes/admin.conf", "get", "namespace",
                "-l", "labs.shadowops.org/managed=staging-v1", "-o", "json"))
            return [item["metadata"]["name"] for item in result["items"]]

        def candidate(phase):
            result = run(*common, "--name", CLIENT, "--network", EGRESS,
                "--volume", str(fixture / "ca.pem") + ":/fixture/ca.pem:ro",
                "--volume", str(candidate_script) + ":/test/candidate.py:ro",
                "--env", "CKA_TEST_SOURCE=" + source, image, "/test/candidate.py", phase, timeout=600)
            print(result, end="")
            return result

        try:
            assert namespaces() == [], "Prior smoke left dirty candidate namespaces"
            run(*command, "create", "--pull=never", "cka-lab", timeout=60)
            run(*common, "-d", "--name", FIXTURE, "--network", EGRESS,
                "--network-alias", IDENTITY, "--sysctl=net.ipv4.ip_unprivileged_port_start=0",
                "--volume", str(fixture) + ":/fixture:ro",
                "--volume", str(fixture_script) + ":/test/authority.py:ro", image,
                "/test/authority.py", "serve")
            run(*command, "up", "--detach", "--no-deps", "--pull=never", "--wait", "--wait-timeout=120", "cka-lab", timeout=150)
            container = run(*command, "ps", "--quiet", "cka-lab").strip()
            controller = json.loads(run("docker", "inspect", container))[0]
            policy = controller["HostConfig"]
            assert policy["ReadonlyRootfs"] and policy["Memory"] == 256 * 1024**2
            assert policy["MemorySwap"] == policy["Memory"] and policy["PidsLimit"] == 64
            assert policy["NanoCpus"] == 100000000 and "ALL" in policy["CapDrop"]
            assert all(not bindings for bindings in controller["NetworkSettings"]["Ports"].values())
            assert set(controller["NetworkSettings"]["Networks"]) == {
                NETWORK, EGRESS, "shadowops-cka-lab-staging-origin"}
            for setting in ("/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"):
                assert run("docker", "exec", container, "cat", setting).strip() == "0"
            result = candidate("scenarios")
            pending = next(line.removeprefix("CKA_LAB_API_RESTART_PENDING ") for line in result.splitlines()
                           if line.startswith("CKA_LAB_API_RESTART_PENDING "))
            assert namespaces() == [json.loads(pending)["namespace"]], "Revocation did not retain the still-active lease"
            run(*command, "restart", "cka-lab", timeout=60)
            run(*command, "up", "--detach", "--no-deps", "--pull=never", "--wait", "--wait-timeout=120", "cka-lab", timeout=150)
            assert namespaces() == [], "Actual restart failed to reap the durable lease"
            candidate("after-restart")
            assert namespaces() == [], "Confirmed finish left Kubernetes resources behind"
            print("CKA_LAB_PUBLISHED_COMPOSE_API_VERIFIED " + json.dumps({
                "source_sha": source, "image_digest": digest, "curated_exercises": 3,
                "fresh_identity": True, "unexpired_revocation": True, "restart_cleanup": True,
                "real_kubernetes": True, "oci_mutations": False}, sort_keys=True))
        finally:
            for name in (CLIENT, FIXTURE):
                subprocess.run(["docker", "rm", "--force", name], env=env, capture_output=True, timeout=30)
            subprocess.run([*command, "down", "--remove-orphans"], env=env, capture_output=True, timeout=60)


if __name__ == "__main__":
    main()
