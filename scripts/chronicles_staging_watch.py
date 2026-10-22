#!/usr/bin/env python3
"""Low-noise Chronicles staging watch: confirmed probes, one actionable issue.

Checks public API health and real Pages game HTML/JS/CSS unconditionally.
Reports frontend or live API revision drift only after the source SHA has all
three green push workflows and a 90-minute deploy grace; receipts alone do not
prove the live API version.
No secrets outside the GitHub token are needed.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Callable

import chronicles_source_ci as ci
import chronicles_api_before_pages as receipts
import chronicles_pages as pages

INFRA = "evilsysadmin/shadowops-infra"
TITLE = "[staging-watch] Chronicles staging necesita atención"
ORIGIN = "https://staging.chronicles.shadowops.dpdns.org"
API = "https://chronicles-api-staging.shadowops.dpdns.org/api"
GRACE_SECONDS = 90 * 60
RECHECK_SECONDS = 90
ISSUES_PER_PAGE = 100
MAX_ISSUE_PAGES = 20  # Fail closed instead of creating duplicates if enumeration is incomplete.
PAGES_FAMILIES = {
    "game": ("pages-game", "pages-edge"),
    "manifest": ("pages-manifest", "pages-manifest-edge"),
}
PAGES_KEYS = frozenset(key for keys in PAGES_FAMILIES.values() for key in keys)


def pages_failure_key(result: str) -> str | None:
    """Distinguish edge/transport failures from broken HTML or assets.

    Provider data is deliberately not included in issue text or logs.
    """
    if result == "ok":
        return None
    if result in {"unavailable", "http_error"}:
        return "pages-edge"
    if result.startswith("http_"):
        status = result.removeprefix("http_")
        if status.isdecimal() and (status == "429" or 500 <= int(status) <= 599):
            return "pages-edge"
    return "pages-game"


def manifest_error_key(exc: Exception) -> str:
    """An invalid manifest is structural; 429/5xx and network faults are edge.

    HTTPError inherits from URLError: classify it first, without reporting
    any response body, URL, headers or exceptions to GitHub issues.
    """
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 429 or 500 <= exc.code <= 599:
            return "pages-manifest-edge"
        return "pages-manifest"
    if isinstance(exc, (urllib.error.URLError, TimeoutError, OSError)):
        return "pages-manifest-edge"
    return "pages-manifest"


def get_url(url: str, token: str = "") -> dict:
    headers = {"Accept": "application/vnd.github+json" if token else "application/json",
               "User-Agent": "shadowops-chronicles-watch/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=15) as response:
        data = json.load(response)
    if not isinstance(data, (dict, list)):
        raise ValueError("Expected JSON object or issue list")
    return data


def github(path: str, token: str, *, method="GET", payload=None) -> dict:
    url = "https://api.github.com/" + path
    if method == "GET":
        return get_url(url, token)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method,
        headers={"Authorization": "Bearer " + token,
                 "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json",
                 "User-Agent": "shadowops-chronicles-watch/1"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def failures(token: str, *, get: Callable = get_url, gh: Callable = github,
             now: dt.datetime | None = None) -> dict[str, str]:
    now = now or dt.datetime.now(dt.timezone.utc)
    bad = {}
    try:
        get(API + "/health")
        get(API + "/ready")
    except (urllib.error.URLError, ValueError, TimeoutError, OSError):
        bad["api-health"] = "La API pública /health o /ready no responde correctamente"
    live_sha = None
    try:
        manifest = get(ORIGIN + "/release.json?watch=" + str(int(now.timestamp())))
        if not isinstance(manifest, dict):
            bad["pages-manifest"] = "El release.json público no contiene un objeto JSON válido"
        else:
            sha = manifest.get("build")
            if isinstance(sha, str) and ci.SHA.fullmatch(sha):
                live_sha = sha
            else:
                bad["pages-manifest"] = "El release.json público no expone un SHA válido"
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError,
            OSError, ValueError, UnicodeError) as exc:
        key = manifest_error_key(exc)
        bad[key] = ("El release.json público no es accesible por CDN/conexión HTTPS"
                    if key == "pages-manifest-edge"
                    else "El release.json público no devuelve un manifiesto válido")

    # The manifest may still answer 200 while the actual game root or its
    # Vite entry JS/CSS is broken. Reuse the same strict, same-origin HTTPS
    # checks performed by the release owner, but keep this watch read-only.
    # This is an asset availability probe, NOT a substitute for Playwright.
    if pages.HOST != ORIGIN.removeprefix("https://"):
        raise RuntimeError("Watchdog Pages host is not its pinned staging origin")
    game_probe = pages.probe_react_preview(
        path="/", assets=b"/assets/", manifest_path=None
    )
    pages_key = pages_failure_key(game_probe)
    if pages_key == "pages-game":
        bad[pages_key] = "La portada o los JS/CSS públicos de Chronicles no se sirven correctamente"
    elif pages_key == "pages-edge":
        bad[pages_key] = "El borde/CDN o la conexión HTTPS de Pages no sirve el juego"

    source = gh("repos/" + ci.SOURCE + "/commits/main", token)
    source_sha = source.get("sha")
    if not isinstance(source_sha, str) or not ci.SHA.fullmatch(source_sha):
        raise RuntimeError("Cannot verify protected Chronicles source")
    verdict = ci.inspect(source_sha, token)
    if verdict != "ready":
        # Do not complain about an unshipped or unfinished source commit.
        return bad

    stamp = (source.get("commit") or {}).get("committer", {}).get("date", "")
    try:
        age = (now - dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))).total_seconds()
    except (TypeError, ValueError):
        raise RuntimeError("Cannot date the verified source main")
    if age < GRACE_SECONDS:
        return bad
    # Missing/unreadable manifest is already an availability problem; it
    # cannot prove release drift. Report frontend-lag only with a valid live SHA.
    if live_sha is not None and live_sha != source_sha:
        bad["frontend-lag"] = "Pages no publica el último SHA verde después del margen de 90 minutos"

    try:
        listing = gh("repos/" + INFRA + "/actions/artifacts?name=chronicles-api-staging-" + source_sha + "&per_page=100", token)
        if not receipts.evidence_ok(source_sha, listing,
                lambda rid: gh("repos/" + INFRA + "/actions/runs/" + str(rid), token)):
            bad["backend-lag"] = "No hay recibo válido de OCI/E2E para el SHA verde"
    except (urllib.error.URLError, ValueError, TimeoutError, OSError):
        raise RuntimeError("Cannot verify staging deployment receipt")

    # A historical successful OCI receipt is not proof that the API is STILL
    # serving that build. Compare the public /api/release revision to the
    # current green source, using the same strict HTTPS reader as Pages.
    # Avoid duplicate alarms when /health or /ready already failed.
    if "api-health" not in bad:
        revision = receipts.public_api_revision_state(source_sha)
        if revision == "different":
            bad["api-revision"] = "La API pública sirve un SHA distinto del último main verde"
        elif revision == "unknown":
            bad["api-revision"] = "No se puede verificar el SHA servido por la API pública"
        elif revision != "match":
            raise RuntimeError("Unexpected public API revision state")
    return bad


ISSUE_DIAGNOSTIC_START = "<!-- chronicles-staging-watch:diagnostic:start -->"
ISSUE_DIAGNOSTIC_END = "<!-- chronicles-staging-watch:diagnostic:end -->"
ISSUE_LEGACY_FOOTER = (
    "Revisar los workflows en https://github.com/" + INFRA +
    "/actions y los SHA publicados. Esta incidencia se cerrará automáticamente cuando el staging se recupere."
)


def existing_issue(token: str, gh: Callable = github) -> dict | None:
    """Find the unique open watchdog issue across paginated GitHub issues + PRs.

    GitHub's /issues API returns both issues and pull requests. Never assume
    the first 100 rows contain our incident: otherwise a watchdog can open a
    duplicate or fail to close/reconcile the original. Enumeration is bounded
    and fails closed when completeness cannot be proved.
    """
    found = None
    for page in range(1, MAX_ISSUE_PAGES + 1):
        path = (f"repos/{INFRA}/issues?state=open&per_page={ISSUES_PER_PAGE}"
                f"&page={page}")
        rows = gh(path, token)
        if not isinstance(rows, list) or len(rows) > ISSUES_PER_PAGE:
            raise RuntimeError("Malformed staging watchdog issue listing")
        for entry in rows:
            if not isinstance(entry, dict):
                raise RuntimeError("Malformed staging watchdog issue entry")
            if entry.get("title") != TITLE or entry.get("pull_request"):
                continue
            if (type(entry.get("number")) is not int or
                    entry["number"] <= 0 or
                    not isinstance(entry.get("body"), (str, type(None)))):
                raise RuntimeError("Malformed staging watchdog issue metadata")
            if found is not None:
                raise RuntimeError("Multiple open staging watchdog incidents")
            found = entry
        # Only a short page proves this enumeration has reached its end.
        if len(rows) < ISSUES_PER_PAGE:
            return found
    raise RuntimeError("Staging watchdog issue pagination limit reached")


def diagnostic_body(persistent: dict[str, str]) -> str:
    # Stable ordering, no timestamp: unchanged diagnostics never cause an
    # unnecessary PATCH, issue notification or rewrite of human annotations.
    details = "\n".join("- **" + key + "**: " + persistent[key]
                        for key in sorted(persistent))
    return (ISSUE_DIAGNOSTIC_START + "\n" +
            "Detectado en comprobaciones consecutivas. Estado público, sin datos de usuarios.\n\n" +
            details + "\n\n" + ISSUE_LEGACY_FOOTER + "\n" +
            ISSUE_DIAGNOSTIC_END)


def updated_issue_body(old_body: str, diagnostic: str) -> str:
    """Replace only our managed diagnosis while preserving manual issue notes."""
    begin = ISSUE_DIAGNOSTIC_START
    end = ISSUE_DIAGNOSTIC_END
    if old_body.count(begin) != old_body.count(end) or old_body.count(begin) > 1:
        raise RuntimeError("Malformed staging watchdog diagnostic boundaries")
    if begin in old_body:
        prefix, rest = old_body.split(begin, 1)
        _, suffix = rest.split(end, 1)
        return prefix + diagnostic + suffix

    # One-time migration from the previous, unmarked automation-owned body.
    # Preserve any notes appended after the original generated footer.
    if (old_body.startswith(("Detectado en comprobaciones consecutivas.",
                              "Detectado en dos comprobaciones separadas.")) and
            ISSUE_LEGACY_FOOTER in old_body):
        _, suffix = old_body.split(ISSUE_LEGACY_FOOTER, 1)
        return diagnostic + suffix

    # Unknown or manually replaced bodies: never discard user-authored text.
    return diagnostic + ("\n\n---\n\n" + old_body if old_body else "")


def manage_issue(token: str, persistent: dict[str, str], *, gh: Callable = github,
                 probe: Callable | None = None, pause: Callable | None = None) -> str:
    issue = existing_issue(token, gh=gh)
    if not persistent:
        if issue is not None:
            # Opening an incident needs repeated evidence, so recovery should
            # too. One good reading can be a momentary CDN/API recovery.
            # Do not add a delay to healthy staging without an open incident.
            print("CHRONICLES_STAGING_WATCH_RECOVERY_CONFIRM", flush=True)
            (pause or time.sleep)(RECHECK_SECONDS)
            if (probe or failures)(token):
                # Never close or replace a confirmed incident using a single
                # new failure sample. The next scheduled watch re-evaluates it.
                return "CHRONICLES_STAGING_WATCH_RECOVERY_UNCONFIRMED"
            gh(f"repos/{INFRA}/issues/{issue['number']}", token, method="PATCH",
               payload={"state": "closed", "state_reason": "completed"})
            return "CHRONICLES_STAGING_WATCH_RECOVERED"
        return "CHRONICLES_STAGING_WATCH_OK"

    diagnostic = diagnostic_body(persistent)
    if issue is not None:
        body = issue.get("body") or ""
        replacement = updated_issue_body(body, diagnostic)
        if replacement == body:
            return "CHRONICLES_STAGING_WATCH_ALREADY_OPEN"
        gh(f"repos/{INFRA}/issues/{issue['number']}", token, method="PATCH",
           payload={"body": replacement})
        return "CHRONICLES_STAGING_WATCH_UPDATED"

    gh(f"repos/{INFRA}/issues", token, method="POST",
       payload={"title": TITLE, "body": diagnostic})
    return "CHRONICLES_STAGING_WATCH_ISSUE_OPENED"


def confirmed_failures(token: str, *, probe: Callable | None = None,
                       pause: Callable | None = None) -> dict[str, str]:
    """Confirm persistent failures; CDN/transport faults need three samples.

    Structural HTML, JS/CSS and invalid JSON manifest failures need two samples.
    CDN 429/5xx and connection timeouts need three; a transition between edge
    and structural errors still counts as continued unavailability per resource.
    """
    probe = probe or failures
    pause = pause or time.sleep
    first = probe(token)
    if not first:
        return {}
    print("CHRONICLES_STAGING_WATCH_RECHECK " + ",".join(sorted(first)), flush=True)
    pause(RECHECK_SECONDS)
    second = probe(token)
    persistent = {k: second[k] for k in first.keys() & second.keys()
                  if k not in PAGES_KEYS}
    pending_third = []
    for structural, edge in PAGES_FAMILIES.values():
        # Stable invalid content is structural; two consecutive samples are
        # enough even if a *different* Pages family also has an edge problem.
        if structural in first and structural in second:
            persistent[structural] = second[structural]
        elif ({structural, edge} & first.keys() and
              {structural, edge} & second.keys()):
            pending_third.append((structural, edge))
    if not pending_third:
        return persistent

    # A 429/5xx/timeout needs three samples, also across transitions between
    # edge and structural errors. One third probe confirms all waiting families;
    # unrelated persistent API/version failures retain their two-sample signal.
    print("CHRONICLES_STAGING_WATCH_EDGE_CONFIRM", flush=True)
    pause(RECHECK_SECONDS)
    third = probe(token)
    for structural, edge in pending_third:
        if structural in third:
            persistent[structural] = third[structural]
        elif edge in third:
            persistent[edge] = third[edge]
    return persistent


def main() -> int:
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        print("Missing GitHub token", file=sys.stderr)
        return 2
    try:
        persistent = confirmed_failures(token)
        print(manage_issue(token, persistent))
        return 0
    except Exception as exc:
        # A broken watchdog must not create a false outage or leak credentials.
        print("CHRONICLES_STAGING_WATCH_INCONCLUSIVE " + type(exc).__name__, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
