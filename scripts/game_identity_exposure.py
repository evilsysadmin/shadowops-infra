#!/usr/bin/env python3
"""Read-only, anonymous game surface audit. Not a live ShadowOps ID login test."""
from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Game:
    slug: str
    environment: str
    hostname: str
    pages_project: str | None = None


# Explicit coverage of games not yet separately published.
UNPUBLISHED = ("tactics-of-matthias",)
GAMES = (
    Game("chess-studio", "staging", "staging.chess-studio.shadowops.dpdns.org"),
    Game("chess-studio", "production", "chess-studio.shadowops.dpdns.org"),
    Game("chronicles-of-matthias", "staging", "staging.chronicles.shadowops.dpdns.org", "chronicles-staging"),
    Game("chronicles-of-matthias", "production", "chronicles.shadowops.dpdns.org", "chronicles-production"),
    Game("star-adventures", "staging", "staging.staradvs.shadowops.dpdns.org", "staradvs-staging"),
    Game("football-of-matthias", "staging", "staging.football.shadowops.dpdns.org", "football-staging"),
    Game("snooker-of-matthias", "staging", "staging.snooker.shadowops.dpdns.org", "snooker-staging"),
    Game("pawn-action", "staging", "staging.pawnaction.shadowops.dpdns.org", "pawn-action-staging"),
    Game("matthias-bridge-squad", "production", "bridgesquad.shadowops.dpdns.org", "bridgesquad-production"),
)
ROUTES = ("/", "/index.html")
METHODS = ("GET", "HEAD")


@dataclass(frozen=True)
class Observation:
    game: str
    environment: str
    surface: str
    hostname: str
    path: str
    method: str
    status: int
    finding: str


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def endpoints():
    for game in GAMES:
        yield game, "canonical", game.hostname
        if game.pages_project:
            # Does not cover immutable preview aliases; they need Cloudflare inventory.
            yield game, "pages-dev-main", game.pages_project + ".pages.dev"


def classify(status: int, surface: str) -> str:
    if status in (200, 206):
        return "anonymous_content_review"
    if status in (401, 403):
        return "guest_denied"
    if status == 404:
        return "alias_denied" if surface == "pages-dev-main" else "not_found_unverified"
    if status == 503:
        return "fail_closed_unavailable"
    if 300 <= status < 400:
        return "redirect_unverified"
    if status == 0:
        return "network_unverified"
    return "unexpected_response"


def fetch_status(url: str, method: str) -> int:
    # Only fixed trusted hosts, no cookies, bearer tokens, redirects or TLS bypass.
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
    request = urllib.request.Request(url, method=method, headers={
        "User-Agent": "ShadowOps-Identity-Guest-Exposure/1.0",
        "Accept": "text/html, application/json",
        "Cache-Control": "no-cache",
    })
    try:
        with opener.open(request, timeout=8) as response:
            response.read(2048)
            return response.status
    except urllib.error.HTTPError as exc:
        exc.close()
        return exc.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0


def audit(request_status=fetch_status):
    observations = []
    for game, surface, host in endpoints():
        for path in ROUTES:
            for method in METHODS:
                status = request_status("https://" + host + path, method)
                observations.append(Observation(
                    game.slug, game.environment, surface, host, path, method,
                    status, classify(status, surface)))
    return observations


def outcome(observations):
    findings = {o.finding for o in observations}
    if "anonymous_content_review" in findings:
        return "REVIEW_ANONYMOUS_200", 1
    if findings.intersection({"redirect_unverified", "unexpected_response"}):
        return "REVIEW_UNEXPECTED", 1
    if findings.intersection({"network_unverified", "not_found_unverified", "fail_closed_unavailable"}):
        return "NOT_FULLY_VERIFIED", 2
    return "GUEST_DENIAL_OBSERVED", 0


def main(argv):
    if argv != ["audit"]:
        print("Usage: game_identity_exposure.py audit", file=sys.stderr)
        return 64
    observations = audit()
    state, exit_code = outcome(observations)
    # Never log response bodies, server error text, authentication data or cookies.
    print(json.dumps({
        "state": state,
        "published_game_origins": len(GAMES),
        "unpublished_games": UNPUBLISHED,
        "note": "No live login, Identity freshness or immutable Pages aliases verified",
        "observations": [asdict(o) for o in observations],
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
