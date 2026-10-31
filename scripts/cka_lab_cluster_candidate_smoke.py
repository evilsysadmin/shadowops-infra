"""Disposable CI only: prove actual candidate state and pod egress denial."""
import json
import os
from pathlib import Path
import shutil
import socket
import tempfile
import time

from cka_lab_cluster import NODE, PROBE_IMAGE, call
from cka_sim.catalog import load_bank
from cka_sim.lease_process import LeaseProcess, LeaseRejected
from cka_sim.leased_kube import LeasedCluster
from cka_sim.models import Scenario


PROBE = """import socket
for address in ('1.1.1.1', '169.254.169.254'):
    try:
        connection = socket.create_connection((address, 443 if address == '1.1.1.1' else 80), timeout=2)
    except OSError:
        continue
    connection.close()
    raise SystemExit('candidate egress reachable')
print('CKA_CANDIDATE_EGRESS_DENIED', flush=True)
"""


def main():
    if os.environ.get("CKA_DISPOSABLE_CI") != "true":
        raise RuntimeError("Disposable rootless CI only")
    assert os.geteuid() == 0 and Path("/proc/self/uid_map").read_text().splitlines()[0].split()[2] == "1"
    root = Path("/tmp")
    admin = Path("/run/secrets/cka-lab-admin.yaml")
    source = Path("/app")
    with tempfile.TemporaryDirectory(prefix="cka-rootless-accept-", dir=root) as directory:
        private = Path(directory)
        journal = private / "journal"
        journal.mkdir(mode=0o700)
        cluster = LeasedCluster(admin_config=admin, binary=Path(shutil.which("kubectl")).resolve(),
                                scratch=private / "candidate")
        owner = "11111111-1111-4111-8111-111111111111"
        with LeaseProcess(journal=journal, bank=source / "scenarios",
                          binary=Path("/usr/local/bin/cka-lease-stdio")) as leases:
            for slug in load_bank():
                lease = leases.start(owner, slug)
                scenario = Scenario.model_validate_json(json.dumps(lease["Scenario"]))
                identity, namespace = lease["ID"], lease["Namespace"]
                try:
                    cluster.provision(identity, scenario)
                    assert not cluster.grade(identity, scenario)["passed"], slug
                    if scenario.scenario_type == "deployment_scale":
                        probe = {"apiVersion": "v1", "kind": "Pod", "metadata": {
                            "name": "egress-probe", "namespace": namespace}, "spec": {
                                "automountServiceAccountToken": False, "restartPolicy": "Never",
                                "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                                    "seccompProfile": {"type": "RuntimeDefault"}},
                                "containers": [{"name": "probe", "image": PROBE_IMAGE,
                                    "imagePullPolicy": "IfNotPresent", "command": ["python", "-c", PROBE],
                                    "securityContext": {"allowPrivilegeEscalation": False,
                                                        "capabilities": {"drop": ["ALL"]}},
                                    "resources": {"requests": {"memory": "32Mi", "cpu": "10m"},
                                                  "limits": {"memory": "64Mi", "cpu": "100m"}}}]}}
                        cluster._admin(["create", "-f", "-"], body=probe)
                        cluster._admin(["wait", "--for=jsonpath={.status.phase}=Succeeded",
                                        "pod/egress-probe", "-n", namespace, "--timeout=30s"], timeout=35)
                        assert cluster._admin(["logs", "egress-probe", "-n", namespace]).strip() == "CKA_CANDIDATE_EGRESS_DENIED"
                        print("CKA_CANDIDATE_EGRESS_DENIED", flush=True)
                    if scenario.scenario_type == "deployment_scale":
                        command = f"kubectl scale deployment/{scenario.deployment} --replicas={scenario.target_replicas}"
                    elif scenario.scenario_type == "deployment_resources":
                        command = f"kubectl set resources deployment/{scenario.deployment} --requests=cpu=10m --limits=cpu=250m"
                    else:
                        patch = json.dumps({"spec": {"selector": {"app": scenario.target_selector}}})
                        command = f"kubectl patch service/{scenario.service} --type=merge -p '{patch}'"
                    cluster.command(identity, scenario, command)
                    deadline = time.monotonic() + 150
                    while not cluster.grade(identity, scenario)["passed"]:
                        assert time.monotonic() < deadline, "Curated repair did not become healthy"
                        time.sleep(2)
                finally:
                    clean = leases.finish(owner, identity)
                    try:
                        leases.start(owner, slug)
                    except LeaseRejected:
                        pass
                    else:
                        raise AssertionError("Uncleaned capacity was reused")
                    cluster.cleanup(clean["ID"], clean["Namespace"])
                    leases.confirm_cleanup(clean["ID"], clean["Namespace"])
                print("CKA_ROOTLESS_LEASED_SCENARIO_OK " + slug, flush=True)


if __name__ == "__main__":
    main()

