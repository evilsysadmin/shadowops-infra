#!/usr/bin/env python3
"""Wait briefly for Cloudflare Pages to serve the exact deployed staging build.

The deploy API can report success before the public custom hostname converges.
Never issue a release receipt for an older or malformed manifest.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from urllib.error import URLError

from chronicles_api_before_pages import SHA
from chronicles_pages_verified_receipt import ORIGIN, read_manifest


def wait_for_public_manifest(sha, run_id, destination, *,
                             read=read_manifest, sleep=time.sleep,
                             attempts=10, delay_seconds=3):
    """Return true only after strict HTTPS proof of the expected source SHA."""
    if not SHA.fullmatch(sha) or not str(run_id).isdigit() or int(run_id) <= 0:
        raise ValueError("Invalid expected SHA or workflow run ID")
    if attempts < 1 or delay_seconds < 0:
        raise ValueError("Invalid manifest polling budget")
    for attempt in range(1, attempts + 1):
        # Change the cache-buster each time; a stale edge response is not proof.
        url = f"{ORIGIN}/release.json?receipt_check={run_id}-{attempt}"
        try:
            manifest = read(url)
            if manifest.get("build") == sha:
                Path(destination).write_text(json.dumps(manifest) + "\n", encoding="utf-8")
                print("CHRONICLES_PUBLIC_RELEASE_MANIFEST_OK", flush=True)
                return True
        except (URLError, TimeoutError, OSError, ValueError):
            # Only a subsequent *valid exact-SHA* response can certify staging.
            pass
        if attempt < attempts:
            print(f"CHRONICLES_PUBLIC_RELEASE_MANIFEST_WAIT attempt={attempt}/{attempts}",
                  flush=True)
            sleep(delay_seconds)
    print("CHRONICLES_PUBLIC_RELEASE_MANIFEST_MISMATCH", file=sys.stderr)
    return False


def main():
    try:
        destination = Path(os.environ["RUNNER_TEMP"]) / "chronicles-published-release.json"
        ok = wait_for_public_manifest(os.environ["EXPECTED_SHA"],
                                      os.environ["GITHUB_RUN_ID"], destination)
    except (KeyError, ValueError) as exc:
        print(f"CHRONICLES_PUBLIC_RELEASE_MANIFEST_CONFIG_ERROR: {exc}", file=sys.stderr)
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
