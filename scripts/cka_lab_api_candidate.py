"""Disposable CI browser-side HTTP contract against the real published API.

This client has no Kubernetes or Docker credential and no signing key. Only the
synthetic TLS authority can issue its short-lived signed test tokens.
"""
import base64
import json
import os
from pathlib import Path
import sys
import time

import httpx
from cka_sim.catalog import load_bank


IDENTITY = "https://id-staging.shadowops.dpdns.org"
ORIGIN = "https://staging.cka.shadowops.dpdns.org"
LAB_HOST = "cka-labs-staging.shadowops.dpdns.org"
API = "http://cka-lab:8080"


def main(phase):
    if os.environ.get("CKA_DISPOSABLE_CI") != "true":
        raise RuntimeError("Disposable CI only")
    with httpx.Client(verify="/fixture/ca.pem", trust_env=False, follow_redirects=False, timeout=75) as client:
        def authority(path, *, case="owner"):
            response = client.post(IDENTITY + path, headers={"Origin": ORIGIN,
                "Cookie": "ci-browser=" + case}, json={})
            assert response.status_code == 200, "Synthetic authority request failed"
            return response.json()

        def token(case="owner"):
            return authority("/api/identity/token", case=case)["token"]

        def api(action, data=None, *, bearer=None, expected=200):
            current = token() if bearer is None else bearer
            for _ in range(6):
                response = client.post(API + "/api/labs/" + action, headers={"Host": LAB_HOST,
                    "Origin": ORIGIN, "Authorization": "Bearer " + current},
                    json={} if data is None else data)
                # The private reaper can briefly own the serialized actor. An
                # explicit 409 performs no candidate mutation; bounded retries
                # are safe. Never retry timeouts, 503 or ambiguous preparation.
                if response.status_code != 409 or expected == 409:
                    break
                time.sleep(1)
            assert response.status_code == expected, "Published lab API returned unexpected status for " + action
            assert response.headers.get("cache-control") == "no-store"
            assert "set-cookie" not in response.headers
            return response.json()

        release = client.get(API + "/api/labs/release", headers={"Host": LAB_HOST})
        assert release.status_code == 200 and release.json()["build"] == os.environ["CKA_TEST_SOURCE"]
        if phase == "after-restart":
            authority("/fixture/restore")
            assert api("capabilities")["current"] is None, "Restart retained a dirty candidate view"
            attempt = api("prepare", {"slug": "scale-payment-api"})
            api("finish", {"id": attempt["session"]["id"]})
            print("CKA_LAB_PUBLISHED_API_RESTART_CLEANUP_OK", flush=True)
            return
        assert phase == "scenarios"
        capabilities = api("capabilities")
        assert capabilities["labs_enabled"] is True and capabilities["capacity"] == 1
        assert capabilities["current"] is None
        assert len(capabilities["scenarios"]) == 3
        api("capabilities", bearer=token("wrong-audience"), expected=401)
        api("prepare", {"slug": "scale-payment-api"}, bearer=token("foreign"), expected=401)
        api("capabilities", bearer=token() + "bad", expected=401)
        for slug, scenario in load_bank().items():
            attempt = api("prepare", {"slug": slug})
            identity, namespace = attempt["session"]["id"], attempt["scenario"]["namespace"]
            assert namespace.startswith("cka-lab-") and namespace != scenario.namespace
            assert "initial_replicas" not in json.dumps(attempt)
            assert not api("grade", {"id": identity})["passed"], "Exercise did not start broken"
            if scenario.scenario_type == "deployment_scale":
                api("prepare", {"slug": slug}, expected=409)
                api("command", {"id": "f" * 32, "command": "kubectl get pods"}, expected=401)
                command = f"kubectl scale deployment/{scenario.deployment} --replicas={scenario.target_replicas}"
            elif scenario.scenario_type == "deployment_resources":
                command = f"kubectl set resources deployment/{scenario.deployment} --requests=cpu=10m --limits=cpu=250m"
            else:
                patch = json.dumps({"spec": {"selector": {"app": scenario.target_selector}}})
                command = f"kubectl patch service/{scenario.service} --type=merge -p '{patch}'"
            api("command", {"id": identity, "command": command})
            passed = False
            for _ in range(4):
                time.sleep(8)
                grade = api("grade", {"id": identity})
                if grade["passed"]:
                    assert grade["score"] == 100
                    passed = True
                    break
            assert passed, "Real Kubernetes repair did not pass through the published API"
            assert api("finish", {"id": identity})["status"] == "closed"
            print("CKA_LAB_PUBLISHED_API_SCENARIO_OK " + slug, flush=True)

        assert api("capabilities")["current"] is None
        attempt = api("prepare", {"slug": "scale-payment-api"})
        identity = attempt["session"]["id"]
        held = token()
        claims = json.loads(base64.urlsafe_b64decode(held.split(".")[1] + "=="))
        before = authority("/fixture/status")["freshness_checks"]
        authority("/fixture/revoke")
        for action, body in [("capabilities", {}), ("status", {"id": identity}),
                             ("command", {"id": identity, "command": "kubectl get pods"}),
                             ("grade", {"id": identity}), ("finish", {"id": identity})]:
            api(action, body, bearer=held, expected=401)
        after = authority("/fixture/status")["freshness_checks"]
        assert after == before + 5, "Denial did not perform each live authority check"
        assert claims["exp"] > time.time(), "Revocation check only proved token expiry"
        print("CKA_LAB_PUBLISHED_API_UNEXPIRED_REVOCATION_OK", flush=True)
        print("CKA_LAB_API_RESTART_PENDING " + json.dumps({"namespace": attempt["scenario"]["namespace"]}), flush=True)


if __name__ == "__main__":
    main(sys.argv[1])
