#!/usr/bin/env python3
"""One-off protected Cloudflare Access quarantine for Star Adventures staging."""
from __future__ import annotations
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
import pages_access_readiness as access
import staradvs_access_challenge as challenge
import staradvs_pages as pages
import staradvs_identity_readiness as readiness

PROJECT = "staradvs-staging"
CONFIRM = "STARADVS_QUARANTINE_ACCESS"
SCOPES = (
    ("immutable", "*.staradvs-staging.pages.dev"),
    ("main", "staradvs-staging.pages.dev"),
    ("custom_companion", "staging.staradvs.shadowops.dpdns.org"),
)
SAFE = {"missing", "restricted-policy-candidate"}


class QuarantineError(Exception):
    pass


class AccessWriter:
    """Use dedicated Access Apps+Policies Write token, never Pages API token."""
    def __init__(self, env):
        self.account = env.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
        self._token = env.get("CLOUDFLARE_ACCESS_WRITE_TOKEN", "").strip()
        if not self._token or access.ACCOUNT_PATTERN.fullmatch(self.account) is None:
            raise QuarantineError("Dedicated Access write token unavailable")
        self._reader = access.AccessClient({
            "CLOUDFLARE_ACCOUNT_ID": self.account,
            "CLOUDFLARE_ACCESS_READ_TOKEN": self._token,
        })

    def get(self, path):
        return self._reader.get(path)

    def post(self, path, body):
        endpoint = f"/accounts/{self.account}/access/apps"
        if path != endpoint or not isinstance(body, dict):
            raise QuarantineError("Foreign Access write blocked")
        # This HTTP client must refuse unrelated apps, widened destinations,
        # non-email allows or injected extra provider configuration even if a
        # future caller bypasses payload_for().
        try:
            destinations = body["destinations"]
            policies = body["policies"]
            if len(destinations) != 1 or len(policies) != 1:
                raise ValueError("Unexpected Access application cardinality")
            host = destinations[0]["uri"]
            scope = next(key for key, expected in SCOPES if expected == host)
            operator = policies[0]["include"][0]["email"]["email"]
            canonical = payload_for(scope, host, operator)
        except (KeyError, IndexError, TypeError, ValueError, StopIteration):
            raise QuarantineError("Unapproved Access policy payload") from None
        if body != canonical:
            raise QuarantineError("Unapproved Access policy payload")
        req = urllib.request.Request(
            access.API + endpoint, data=json.dumps(body).encode(),
            method="POST", headers={
                "Authorization": "Bearer " + self._token,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "ShadowOps-StarAdvs-Quarantine/1.0",
            },
        )
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
            access.NoRedirect(),
        )
        try:
            with opener.open(req, timeout=20) as response:
                status, raw = response.status, response.read(1_000_001)
        except urllib.error.HTTPError as exc:
            exc.close()
            raise QuarantineError("Cloudflare Access write rejected") from None
        except (OSError, urllib.error.URLError, TimeoutError):
            raise QuarantineError("Cloudflare Access unavailable") from None
        if status not in (200, 201) or len(raw) > 1_000_000:
            raise QuarantineError("Invalid Access response")
        try:
            obj = json.loads(raw)
        except (UnicodeError, ValueError):
            raise QuarantineError("Access returned malformed JSON") from None
        if not isinstance(obj, dict) or obj.get("success") is not True:
            raise QuarantineError("Access write not confirmed")
        return obj.get("result")


def verify_owner(client):
    _, state = pages.inspect(client)
    if state != {"dns": "owned", "domain": "owned", "project": "owned"}:
        raise QuarantineError("Unexpected Pages owner")
    status, project = client.request(
        "GET", f"/accounts/{client.account}/pages/projects/{PROJECT}"
    )
    if status != 200 or not isinstance(project, dict):
        raise QuarantineError("Pages project unavailable")
    if (project.get("name") != PROJECT or
            project.get("production_branch") != "main" or
            project.get("subdomain") != pages.TARGET or
            project.get("source")):
        raise QuarantineError("Unexpected Pages project identity")
    domains = project.get("domains") or []
    if not isinstance(domains, list) or any(
        not isinstance(host, str) or host not in {pages.HOST, pages.TARGET}
        for host in domains
    ):
        raise QuarantineError("Foreign Pages domain")


def inspect_scopes(client, pages_client):
    if client.account != pages_client.account:
        raise QuarantineError("Cloudflare account mismatch")
    verify_owner(pages_client)
    result = access.inspect(client, project_filter=PROJECT)
    rows = result.get("projects") or []
    if len(rows) != 1 or rows[0].get("project") != PROJECT:
        raise QuarantineError("Access project mismatch")
    states = rows[0]["application_scopes"]
    if set(states) != {key for key, _ in SCOPES} or any(
        value not in SAFE for value in states.values()
    ):
        raise QuarantineError("Ambiguous or broad Access policy")
    return states


def payload_for(scope, host, operator):
    if (scope, host) not in SCOPES:
        raise QuarantineError("Foreign Access scope")
    if (not isinstance(operator, str) or len(operator) > 254 or
            access.EXACT_OPERATOR_EMAIL.fullmatch(operator) is None):
        raise QuarantineError("Individual operator email required")
    return {
        "type": "self_hosted",
        "name": f"ShadowOps Star Adventures staging quarantine - {scope}",
        "destinations": [{"type": "public", "uri": host}],
        "session_duration": "4h",
        "policies": [{
            "name": "StarAdvs staging operator only",
            "decision": "allow",
            "include": [{"email": {"email": operator}}],
        }],
    }


def plan(client, pages_client):
    return inspect_scopes(client, pages_client)


def apply(client, pages_client, operator, *, confirmation):
    if confirmation != CONFIRM:
        raise QuarantineError("Protected apply confirmation required")
    writes = [(scope, payload_for(scope, host, operator))
              for scope, host in SCOPES]
    inspect_scopes(client, pages_client)
    created = 0
    for scope, body in writes:
        before = inspect_scopes(client, pages_client)
        if before[scope] == "restricted-policy-candidate":
            continue
        if before[scope] != "missing":
            raise QuarantineError("Scope changed during preflight")
        client.post(f"/accounts/{client.account}/access/apps", body)
        after = inspect_scopes(client, pages_client)
        if after[scope] != "restricted-policy-candidate":
            raise QuarantineError("Created policy not independently verified")
        created += 1
    states = inspect_scopes(client, pages_client)
    if any(value != "restricted-policy-candidate" for value in states.values()):
        raise QuarantineError("Access quarantine incomplete")
    return created, states


def judge_guest_quarantine(report, evidence=None):
    """Proof of no public app bytes is not proof of Access login enforcement.

    Fail closed on incomplete API enumeration, redirects, timeouts, or
    inconsistent responses. Neither a 302 nor a generic 403 certifies Access.
    """
    if not isinstance(report, dict):
        return "inventory-unverified"
    values = tuple(report.get(key) for key in (
        "historical_aliases_scanned", "historical_aliases_exposed",
        "historical_aliases_denied", "historical_aliases_unverified",
        "historical_deployments_scanned",
        "historical_deployments_reported_total",
    ))
    if any(type(n) is not int or n < 0 for n in values):
        return "inventory-unverified"
    hosts, exposed, denied, unknown, scanned, total = values
    if (not hosts or not total or scanned != total or
            report.get("historical_enumeration_status") != "reported-total-observed" or
            exposed + denied + unknown != hosts):
        return "inventory-unverified"
    if (exposed or report.get("pages_alias_guest") == "anonymous-content-observed" or
            report.get("canonical_guest") == "anonymous-content-observed"):
        return "guest-content-still-exposed"
    if (not unknown and denied == hosts and
            report.get("pages_historical_guest") == "sample-denied-404" and
            report.get("pages_alias_guest") == "denied-404" and
            report.get("canonical_guest") == "denied-401"):
        return "all-observed-guest-paths-denied"
    # Cloudflare Access's documented default guest response is HTTP 302.
    # A team-domain login challenge on both paths of every owned alias is
    # only candidate evidence, tied to independently restrictive Access apps.
    if report.get("cloudflare_access") != "restricted-policy-candidate":
        return "guest-denial-unverified"
    if not isinstance(evidence, dict) or evidence.get("can_activate") is not False:
        return "guest-denial-unverified"
    historical = evidence.get("historical")
    current = evidence.get("current_pages")
    canonical = evidence.get("canonical")
    if not all(isinstance(row, dict) for row in (historical, current, canonical)):
        return "guest-denial-unverified"
    if (historical.get("hosts") != hosts or
            type(current.get("hosts")) is not int or current["hosts"] < 1 or
            canonical.get("hosts") != 1):
        return "guest-denial-unverified"
    for row in (historical, current, canonical):
        vals = [row.get(k) for k in ("hosts", "denied", "challenged", "exposed", "unverified")]
        if (any(type(v) is not int or v < 0 for v in vals) or
                sum(vals[1:]) != vals[0] or vals[3] or vals[4]):
            return "guest-denial-unverified"
    if (historical["challenged"] + historical["denied"] != hosts or
            current["challenged"] + current["denied"] != current["hosts"] or
            canonical["challenged"] != 1):
        return "guest-denial-unverified"
    return "access-login-challenge-candidate"


def main(argv):
    if argv not in (["plan"], ["apply"]):
        print("Usage: staradvs_access_quarantine.py plan|apply", file=sys.stderr)
        return 64
    try:
        writer = AccessWriter(os.environ)
        owner = pages.CloudflareClient(os.environ)
        if argv == ["plan"]:
            print(json.dumps({"operation": "plan", "project": PROJECT,
                              "scopes": plan(writer, owner),
                              "can_activate": False}, sort_keys=True))
            return 0
        created, states = apply(
            writer, owner, os.environ.get("STARADVS_OPERATOR_EMAIL", ""),
            confirmation=os.environ.get("STARADVS_ACCESS_CONFIRM", ""),
        )
        guest = readiness.collect(owner, access_client=writer)
        evidence = None
        if (guest["historical_aliases_exposed"] == 0 and
                guest["cloudflare_access"] == "restricted-policy-candidate"):
            try:
                evidence = challenge.collect(owner, guest)
            except (challenge.ChallengeError, readiness.CutoverBlocked,
                    pages.AdmissionError):
                # Never log provider URLs or partially verified redirects.
                evidence = None
        verdict = judge_guest_quarantine(guest, evidence)
        print(json.dumps({
            "operation": "apply", "project": PROJECT,
            "created": created, "scopes": states,
            "historical_aliases_scanned": guest["historical_aliases_scanned"],
            "historical_aliases_exposed": guest["historical_aliases_exposed"],
            "historical_aliases_denied": guest["historical_aliases_denied"],
            "historical_aliases_unverified": guest["historical_aliases_unverified"],
            "historical_deployments_reported_total":
                guest["historical_deployments_reported_total"],
            "historical_deployments_scanned":
                guest["historical_deployments_scanned"],
            "guest_verdict": verdict,
            "access_challenge_evidence": evidence,
            "can_activate": False,
        }, sort_keys=True))
        if verdict not in (
                "all-observed-guest-paths-denied",
                "access-login-challenge-candidate"):

            print("STARADVS_QUARANTINE_PENDING reason=" + verdict)
            return 10
        print("STARADVS_QUARANTINE_GUEST_CANDIDATE signed-in E2E still required")
        return 0
    except Exception as exc:
        # No Access/Pages data, operator emails or credentials in logs.
        print("STARADVS_ACCESS_QUARANTINE_BLOCKED kind=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
