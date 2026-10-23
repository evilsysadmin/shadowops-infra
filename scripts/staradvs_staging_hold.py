#!/usr/bin/env python3
"""Staging-only automatic-publication hold; never mutates any deployment.

On an active hold exit 10 (the candidate may deliberately skip), automatic exit 0.
Malformed or expired holds exit 2: never silently resume normal staging release.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SHA = re.compile(r"^[a-f0-9]{40}$")
UTC_EXPIRY = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
ISSUE = re.compile(r"^#[1-9][0-9]{0,6}$")
MAX_DURATION = timedelta(hours=24)
CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "staradvs-staging-hold.json"


class HoldConfigError(Exception):
    pass


def parse_hold(data: object, now: datetime) -> dict:
    if not isinstance(data, dict) or not isinstance(data.get("mode"), str):
        raise HoldConfigError("Hold config must be a JSON object with mode")
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise HoldConfigError("Hold clock must be UTC-aware")
    if data["mode"] == "auto":
        if set(data) != {"mode"}:
            raise HoldConfigError("Auto mode must have no extra fields")
        return {"mode": "auto"}
    if data["mode"] != "hold":
        raise HoldConfigError("Unknown staging publication mode")
    if set(data) != {"mode", "anchor_sha", "expires_at", "reason", "issue"}:
        raise HoldConfigError("Hold requires exact SHA, expiry, reason and issue")
    sha = data["anchor_sha"]
    expiry = data["expires_at"]
    reason = data["reason"]
    issue = data["issue"]
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise HoldConfigError("Invalid hold anchor SHA")
    if not isinstance(issue, str) or not ISSUE.fullmatch(issue):
        raise HoldConfigError("Hold must reference an issue number")
    if (not isinstance(reason, str) or not 12 <= len(reason) <= 240 or
            any(ord(char) < 32 or ord(char) == 127 for char in reason)):
        raise HoldConfigError("Hold reason must be 12-240 printable characters")
    if not isinstance(expiry, str) or not UTC_EXPIRY.fullmatch(expiry):
        raise HoldConfigError("Hold expiry must be explicit UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        expiry_time = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise HoldConfigError("Invalid UTC hold expiry") from None
    if expiry_time <= now:
        raise HoldConfigError("Hold expired: explicit reviewed resume required")
    if expiry_time - now > MAX_DURATION:
        raise HoldConfigError("Hold cannot be extended beyond 24 hours without a new review")
    return {"mode": "hold", "anchor_sha": sha, "expires_at": expiry,
            "reason": reason, "issue": issue}


def load_hold(path: Path = CONFIG_PATH, now: datetime | None = None) -> dict:
    clock = now if now is not None else datetime.now(timezone.utc)
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        raise HoldConfigError("Hold config absent or unreadable; fail closed") from None
    if len(content) > 4096:
        raise HoldConfigError("Hold config oversized")
    try:
        data = json.loads(content)
    except (ValueError, UnicodeError):
        raise HoldConfigError("Hold config not valid JSON") from None
    return parse_hold(data, clock)


def main() -> int:
    if len(sys.argv) != 1:
        print("Usage: staradvs_staging_hold.py", file=sys.stderr)
        return 2
    try:
        state = load_hold()
    except HoldConfigError as exc:
        print("STARADVS_STAGING_HOLD_BLOCKED " + str(exc), file=sys.stderr)
        return 2
    if state["mode"] == "hold":
        print("STARADVS_STAGING_HOLD_ACTIVE anchor_sha={anchor_sha} expires_at={expires_at} issue={issue}".format(**state))
        return 10
    print("STARADVS_STAGING_AUTO_ALLOWED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
