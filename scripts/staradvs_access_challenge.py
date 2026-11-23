#!/usr/bin/env python3
"""Independent, no-redirect guest evidence for an Access quarantine candidate.

Never follows a login Location, presents cookies or claims authenticated
Identity acceptance. Cloudflare Access ordinarily challenges guests with a
302, while the old Pages static site could fabricate such a response.
Therefore even exact redirect matching is only a *candidate* coupled with
Access API policy metadata; never an authority to unpause publication.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

import staradvs_identity_readiness as readiness
import staradvs_pages as pages

TEAM = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\.cloudflareaccess\.com\Z")
MAX_ALIAS = readiness.MAX_HISTORY_ALIASES


class ChallengeError(Exception):
    pass


def access_team(host, status, location):
    """Return a candidate Cloudflare Access team hostname, never the URL."""
    if status != 302 or not isinstance(location, str) or len(location) > 4096:
        return None
    if location != location.strip() or any(ord(ch) < 32 for ch in location):
        return None
    try:
        dest = urllib.parse.urlsplit(location)
        port = dest.port
    except ValueError:
        return None
    if (dest.scheme != "https" or dest.username or dest.password or
            port is not None or dest.fragment or
            not dest.hostname or TEAM.fullmatch(dest.hostname) is None or
            dest.path != "/cdn-cgi/access/login/" + host):
        return None
    return dest.hostname


def public_response(url):
    """Request one HTTPS resource, do not follow or expose redirect targets."""
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "ShadowOps-StarAdvs-Access-Challenge/1.0",
        "Cache-Control": "no-cache",
        "Accept": "text/html,application/json",
    })
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        readiness.NoRedirect(),
    )
    try:
        with opener.open(req, timeout=10) as response:
            return response.status, response.headers.get("Location")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.headers.get("Location")
        finally:
            exc.close()
    except (OSError, urllib.error.URLError, TimeoutError):
        return 0, None


def classify(host, path, response):
    """One of: denied, access-challenge, exposed, unverified; with team."""
    if path not in ("/", "/release.json"):
        raise ChallengeError("Unapproved guest path")
    status, location = response
    if status in (200, 206):
        return "exposed", None
    if status == 404:
        return "denied", None
    team = access_team(host, status, location)
    return ("access-challenge", team) if team else ("unverified", None)


def assess(hosts, probe=public_response):
    """Both tested paths must agree per host; no URL or team appears in output."""
    if not isinstance(hosts, list) or not hosts or len(hosts) > MAX_ALIAS:
        raise ChallengeError("Guest host inventory unavailable or too large")
    if len(set(hosts)) != len(hosts):
        raise ChallengeError("Repeated guest host")
    for host in hosts:
        if not isinstance(host, str) or (
            host != pages.HOST and
            host != pages.TARGET and
            not host.endswith("." + pages.TARGET)
        ) or host != host.lower() or len(host) > 253:
            raise ChallengeError("Foreign guest host")
    requests = [(host, path) for host in hosts for path in ("/", "/release.json")]
    with ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(
            lambda item: probe("https://" + item[0] + item[1]), requests
        ))
    counts = {"hosts": len(hosts), "denied": 0, "challenged": 0,
              "exposed": 0, "unverified": 0}
    teams = set()
    for i, host in enumerate(hosts):
        pairs = [classify(host, path, responses[2 * i + pos])
                 for pos, path in enumerate(("/", "/release.json"))]
        statuses = {pair[0] for pair in pairs}
        if "exposed" in statuses:
            counts["exposed"] += 1
        elif statuses == {"denied"}:
            counts["denied"] += 1
        elif statuses == {"access-challenge"} and pairs[0][1] == pairs[1][1]:
            counts["challenged"] += 1
            teams.add(pairs[0][1])
        else:
            counts["unverified"] += 1
    # All Access challenges in the same Cloudflare account should use one
    # team hostname. Reject mixed teams without printing those hostnames.
    if len(teams) > 1:
        counts["unverified"] += counts["challenged"]
        counts["challenged"] = 0
    return counts


def enumerate_historical(client, project, reported_total, expected_aliases):
    """Independently enumerate the same owned bounded history; never log URLs."""
    if (type(reported_total) is not int or reported_total < 1 or
            type(expected_aliases) is not int or expected_aliases < 1):
        raise ChallengeError("Historical inventory metadata absent")
    all_hosts = set()
    signatures = set()
    total_seen = 0
    for page in range(1, readiness.MAX_HISTORY_PAGES + 1):
        try:
            hosts, count, total = readiness.historical_alias_hosts(
                client, project, max_hosts=MAX_ALIAS, page=page
            )
        except (pages.AdmissionError, readiness.CutoverBlocked):
            raise ChallengeError("Historical page unavailable") from None
        signature = tuple(hosts)
        if (total != reported_total or not count or
                total_seen + count > reported_total or signature in signatures):
            raise ChallengeError("Historical API page drift or duplicate")
        signatures.add(signature)
        all_hosts.update(hosts)
        if len(all_hosts) > MAX_ALIAS:
            raise ChallengeError("Historical alias cap exceeded")
        total_seen += count
        if total_seen == reported_total:
            break
    if total_seen != reported_total or len(all_hosts) != expected_aliases:
        raise ChallengeError("Historical alias inventory changed during audit")
    return sorted(all_hosts)


def collect(client, report, probe=public_response):
    """A second bounded pass, only after independent Access policy metadata."""
    if report.get("cloudflare_access") != "restricted-policy-candidate":
        raise ChallengeError("Independent restrictive Access metadata missing")
    if report.get("historical_enumeration_status") != "reported-total-observed":
        raise ChallengeError("Historical enumeration incomplete")
    status, project = client.request(
        "GET", f"/accounts/{client.account}/pages/projects/{pages.PROJECT}"
    )
    if status != 200 or not isinstance(project, dict):
        raise ChallengeError("Pages project disappeared")
    if (project.get("name") != pages.PROJECT or
            project.get("subdomain") != pages.TARGET or
            project.get("production_branch") != "main" or
            project.get("source")):
        raise ChallengeError("Pages project changed during quarantine")
    historical = enumerate_historical(
        client, project, report.get("historical_deployments_reported_total"),
        report.get("historical_aliases_scanned")
    )
    current = readiness.alias_hosts(project)
    return {
        "historical": assess(historical, probe),
        "current_pages": assess(current, probe),
        "canonical": assess([pages.HOST], probe),
        "can_activate": False,
    }
