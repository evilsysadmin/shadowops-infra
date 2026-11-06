#!/usr/bin/env python3
"""Manual, read-only inventory for the existing Chronicles R2 bucket.

Handoff preparation, NOT a Cloudflare ownership cutover. Never print object
keys, raw API responses, credentials, cursor values or error bodies.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from typing import Any, Callable

API_ROOT = "https://api.cloudflare.com/client/v4"
BUCKET = "chronicles"
EXPECTED_DOMAIN = "assets.chronicles.shadowops.dpdns.org"
ACCOUNT_RE = re.compile(r"^[0-9a-fA-F]{32}$")
MAX_PAGES = 100
MAX_API_RESPONSE_BYTES = 2_000_000
SAFE_FAMILIES = frozenset({"sprites", "music", "models"})
MEDIA_EXTENSIONS = frozenset({
    ".webp", ".png", ".jpg", ".jpeg", ".avif", ".glb", ".gltf",
    ".mp3", ".ogg", ".wav", ".webm", ".svg", ".woff2",
})
REVIEW_SEGMENTS = frozenset({
    "backup", "backups", "private", "secret", "secrets", "draft",
    "drafts", "source", "sources", "master", "masters",
    "users", "customer", "customers", "export", "exports",
})


class InventoryError(RuntimeError):
    """Fail closed with a sanitized diagnostic; never include provider bodies."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _account_id(raw: str) -> str:
    if not ACCOUNT_RE.fullmatch(raw):
        raise InventoryError("account ID must be a 32-digit hex identifier")
    return raw


def _endpoint(account: str, kind: str, cursor: str | None) -> str:
    base = f"{API_ROOT}/accounts/{_account_id(account)}/r2/buckets/{BUCKET}"
    if kind == "domains" and cursor is None:
        return base + "/domains/custom"
    if kind == "objects":
        query = {"per_page": "1000"}
        if cursor:
            query["cursor"] = cursor
        return base + "/objects?" + urllib.parse.urlencode(query)
    raise InventoryError("unexpected read-only inventory endpoint")


def cloudflare_get(token: str, account: str, kind: str, cursor: str | None) -> dict[str, Any]:
    if not token:
        raise InventoryError("missing dedicated R2 read-only token")
    url = _endpoint(account, kind, cursor)
    request = urllib.request.Request(
        url, method="GET",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json",
                 "User-Agent": "shadowops-chronicles-r2-readonly/1"},
    )
    try:
        with urllib.request.build_opener(_NoRedirects).open(request, timeout=20) as response:
            body = response.read(MAX_API_RESPONSE_BYTES + 1)
            if len(body) > MAX_API_RESPONSE_BYTES:
                raise InventoryError("Cloudflare response exceeded bounded size")
            payload = json.loads(body)
    except urllib.error.HTTPError as exc:
        raise InventoryError(f"Cloudflare {kind} HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise InventoryError(f"Cloudflare {kind} transport or JSON failure") from None
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise InventoryError(f"Cloudflare {kind} result not successful")
    return payload


def _verified_domain(payload: dict[str, Any]) -> None:
    result = payload.get("result")
    rows = result.get("domains") if isinstance(result, dict) else None
    if not isinstance(rows, list):
        raise InventoryError("Cloudflare domain inventory malformed")
    active = []
    for row in rows:
        if not isinstance(row, dict):
            raise InventoryError("Cloudflare domain inventory row malformed")
        status = row.get("status")
        if row.get("enabled") is True and isinstance(status, dict) and (
            status.get("ssl") == "active" and status.get("ownership") == "active"
        ):
            active.append(row.get("domain"))
    if active != [EXPECTED_DOMAIN]:
        raise InventoryError("expected exactly one approved active Chronicles R2 domain")


def _is_suspect(key: str) -> bool:
    parts = key.lower().split("/")
    suffix = "." + parts[-1].rsplit(".", 1)[-1] if "." in parts[-1] else ""
    return any(part in REVIEW_SEGMENTS for part in parts) or suffix not in MEDIA_EXTENSIONS


def inspect(fetch: Callable[[str, str | None], dict[str, Any]]) -> dict[str, str]:
    """Observe bucket metadata without returning any object keys or cursors."""
    _verified_domain(fetch("domains", None))
    category_counts: Counter[str] = Counter()
    seen_keys: set[str] = set()
    seen_cursors: set[str] = set()
    total_bytes = 0
    review = 0
    cursor: str | None = None
    pages = 0
    while True:
        if pages >= MAX_PAGES:
            raise InventoryError("R2 inventory exceeds bounded page count")
        payload = fetch("objects", cursor)
        rows = payload.get("result")
        if not isinstance(rows, list) or len(rows) > 1000:
            raise InventoryError("R2 object inventory page malformed")
        pages += 1
        for row in rows:
            if not isinstance(row, dict):
                raise InventoryError("R2 object inventory row malformed")
            key, size = row.get("key"), row.get("size")
            if (not isinstance(key, str) or not key or key.startswith("/")
                or key in seen_keys or isinstance(size, bool) or not isinstance(size, int) or size < 0):
                raise InventoryError("R2 object inventory key/size invalid or duplicated")
            seen_keys.add(key)
            total_bytes += size
            family = key.split("/", 1)[0].lower()
            category_counts[family if family in SAFE_FAMILIES and "/" in key else "other"] += 1
            review += int(_is_suspect(key))
        info = payload.get("result_info")
        if not isinstance(info, dict):
            raise InventoryError("R2 object inventory pagination metadata missing")
        if info.get("is_truncated") is not True:
            break
        next_cursor = info.get("cursor")
        if (not isinstance(next_cursor, str) or not next_cursor or
            next_cursor in seen_cursors or next_cursor == cursor):
            raise InventoryError("R2 object inventory continuation invalid")
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    return {
        "domain": "approved-active",
        "objects": str(len(seen_keys)),
        "bytes": str(total_bytes),
        "pages": str(pages),
        "needs_review": str(review),
        "sprites": str(category_counts["sprites"]),
        "music": str(category_counts["music"]),
        "models": str(category_counts["models"]),
        "other": str(category_counts["other"]),
        "publication": "not-authorized",
    }


def main() -> int:
    token = os.environ.get("CHRONICLES_R2_READ_TOKEN", "").strip()
    account = os.environ.get("CHRONICLES_R2_ACCOUNT_ID", "").strip()
    try:
        if not token or not account:
            raise InventoryError("dedicated read-only credential/account not configured")
        _account_id(account)
        metrics = inspect(lambda kind, cursor: cloudflare_get(token, account, kind, cursor))
    except InventoryError as exc:
        print(f"CHRONICLES_R2_INVENTORY_BLOCKED {exc}", file=sys.stderr)
        return 1
    for key, value in sorted(metrics.items()):
        print(f"CHRONICLES_R2_INVENTORY {key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
