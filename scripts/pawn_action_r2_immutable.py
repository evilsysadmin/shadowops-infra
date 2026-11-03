#!/usr/bin/env python3
"""Manual-only, create-once Cloudflare R2 uploader for Pawn Action staging.

No mutable pointer, Cloudflare Pages, DNS, deletion or production operations.
All writes target one immutable pawn-action/releases/<digest>/ key and require
R2 S3 conditional PutObject (If-None-Match: *) for atomic non-overwrite.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys

from pawn_action_source_admission import AdmissionError, GithubReader, admit
import pawn_action_web_package as package

BUCKET = "chess-studio-assets"
PREFIX = "pawn-action/releases/"
ACCOUNT_RE = re.compile(r"[a-f0-9]{32}\Z")
SHARED_SOFT_LIMIT = 7_000_000_000
OWN_SOFT_LIMIT = 536_870_912
MAX_INVENTORY_PAGES = 100
R2_ACCESS = ("PAWN_ACTION_R2_ACCESS_KEY_ID", "PAWN_ACTION_R2_SECRET_ACCESS_KEY")


def _content_sha(stream, *, size: int) -> str:
    hasher = hashlib.sha256()
    remaining = size
    while remaining:
        part = stream.read(min(1024 * 1024, remaining))
        if not part:
            raise AdmissionError("R2 object is truncated")
        hasher.update(part)
        remaining -= len(part)
    if stream.read(1):
        raise AdmissionError("R2 object is longer than the immutable manifest")
    return hasher.hexdigest()


def _entries(candidate: Path, sha: str) -> tuple[dict, dict]:
    manifest = package.validate(candidate, sha)
    release = manifest["release"]
    if not re.fullmatch(r"[a-f0-9]{16}", release):
        raise AdmissionError("Unsafe Pawn Action release identifier")
    entries = {}
    for relative, entry in manifest["files"].items():
        key = f"{PREFIX}{release}/{relative}"
        if (entry.get("key") != key or not key.startswith(PREFIX)
                or key == "pawn-action/current.json"
                or not re.fullmatch(r"[a-f0-9]{64}", str(entry.get("sha256", "")))
                or type(entry.get("bytes")) is not int or not 0 < entry["bytes"] <= 128 * 1024**2):
            raise AdmissionError("R2 upload key/bytes outside immutable Pawn Action prefix")
        entries[key] = (candidate / "runtime" / relative, entry)
    if len(entries) != len(manifest["files"]):
        raise AdmissionError("Duplicate R2 object keys")
    return manifest, entries


def require_receipt(manifest: dict, receipt: dict) -> None:
    origin = manifest["sourceArtifact"]
    if (not isinstance(receipt, dict)
            or receipt.get("source_sha") != manifest["sourceSha"]
            or receipt.get("run_id") != origin["runId"]
            or receipt.get("artifact_id") != origin["artifactId"]
            or receipt.get("artifact_digest") != origin["digest"]
            or type(receipt.get("visual_artifact_id")) is not int
            or receipt["visual_artifact_id"] <= 0
            or not re.fullmatch(r"sha256:[a-f0-9]{64}",
                                 str(receipt.get("visual_artifact_digest", "")))):
        raise AdmissionError("Source CI receipt differs from exact runtime candidate")


def inventory(client) -> dict[str, int]:
    """Inventory entire shared bucket; never budget only this game's prefix."""
    keys = {}
    cursor = None
    visited = set()
    for _ in range(MAX_INVENTORY_PAGES):
        params = {"Bucket": BUCKET, "MaxKeys": 1000}
        if cursor:
            params["ContinuationToken"] = cursor
        try:
            result = client.list_objects_v2(**params)
        except Exception as exc:
            raise AdmissionError("Shared R2 inventory unavailable: " + type(exc).__name__) from None
        if not isinstance(result, dict) or type(result.get("IsTruncated")) is not bool:
            raise AdmissionError("Incomplete R2 inventory response")
        rows = result.get("Contents", [])
        if not isinstance(rows, list):
            raise AdmissionError("Malformed R2 object list")
        for entry in rows:
            if (not isinstance(entry, dict) or not isinstance(entry.get("Key"), str)
                    or not entry["Key"] or type(entry.get("Size")) is not int
                    or entry["Size"] < 0 or entry["Key"] in keys):
                raise AdmissionError("Invalid or duplicated shared R2 object")
            keys[entry["Key"]] = entry["Size"]
        if not result["IsTruncated"]:
            return keys
        cursor = result.get("NextContinuationToken")
        if not isinstance(cursor, str) or not cursor or cursor in visited:
            raise AdmissionError("R2 inventory truncated without a valid unique cursor")
        visited.add(cursor)
    raise AdmissionError("R2 inventory scan exceeded bounded page count")


def budget(existing: dict[str, int], entries: dict) -> dict:
    if (not isinstance(existing, dict) or any(
            not isinstance(key, str) or not key or type(size) is not int or size < 0
            for key, size in existing.items())):
        raise AdmissionError("Invalid shared R2 inventory")
    additions = 0
    own_additions = 0
    for key, (_, entry) in entries.items():
        if not key.startswith(PREFIX):
            raise AdmissionError("Foreign R2 key in Pawn Action plan")
        if key in existing:
            if existing[key] != entry["bytes"]:
                raise AdmissionError("Existing release key has different size: " + key)
        else:
            additions += entry["bytes"]
            own_additions += entry["bytes"]
    shared = sum(existing.values()) + additions
    own = sum(size for key, size in existing.items() if key.startswith("pawn-action/")) + own_additions
    if shared > SHARED_SOFT_LIMIT or own > OWN_SOFT_LIMIT:
        raise AdmissionError("R2 capacity budget exceeded; no write authorized")
    return {
        "sharedProjectedBytes": shared,
        "pawnActionProjectedBytes": own,
        "newBytes": additions,
        "objects": len(entries),
        "existingObjects": sum(key in existing for key in entries),
    }


def verify_remote(client, key: str, metadata: dict) -> None:
    try:
        result = client.get_object(Bucket=BUCKET, Key=key)
        body = result.get("Body")
        if body is None or not hasattr(body, "read"):
            raise AdmissionError("R2 object body unavailable")
        try:
            digest = _content_sha(body, size=metadata["bytes"])
        finally:
            if hasattr(body, "close"):
                body.close()
    except AdmissionError:
        raise
    except Exception as exc:
        raise AdmissionError("Cannot read R2 object for SHA256 verification: "
                             + type(exc).__name__) from None
    if digest != metadata["sha256"]:
        raise AdmissionError("Existing or uploaded R2 object SHA256 mismatch: " + key)


def _precondition_failure(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    error = response.get("Error")
    return isinstance(error, dict) and str(error.get("Code")) in {
        "PreconditionFailed", "412", "ConditionalRequestConflict",
    }


def upload_immutable(client, candidate: Path, sha: str, receipt: dict) -> dict:
    """Write only missing immutable keys, atomically; validate existing before PUT."""
    manifest, entries = _entries(candidate, sha)
    require_receipt(manifest, receipt)
    existing = inventory(client)
    projection = budget(existing, entries)
    # If any existing key is corrupt, fail before starting any upload.
    for key, (_, metadata) in entries.items():
        if key in existing:
            verify_remote(client, key, metadata)

    uploaded = []
    for key, (path, metadata) in entries.items():
        if key in existing:
            continue
        data = path.read_bytes()
        if len(data) != metadata["bytes"] or hashlib.sha256(data).hexdigest() != metadata["sha256"]:
            raise AdmissionError("Candidate changed after admission: " + key)
        try:
            client.put_object(
                Bucket=BUCKET, Key=key, Body=data, ContentType=metadata["contentType"],
                IfNoneMatch="*",  # S3-compatible R2 atomic create-once guarantee
            )
        except Exception as exc:
            if not _precondition_failure(exc):
                raise AdmissionError("Create-once R2 upload failed: "
                                     + type(exc).__name__) from None
            # A concurrent create is safe *only* if its exact bytes match.
        verify_remote(client, key, metadata)
        uploaded.append(key)
    return {"release": manifest["release"], "sourceSha": sha,
            "uploaded": len(uploaded), "reused": len(entries) - len(uploaded),
            **projection}


def create_client(environ: dict[str, str]):
    account = environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    if not ACCOUNT_RE.fullmatch(account):
        raise AdmissionError("Exact Cloudflare account identity required")
    if any(not environ.get(key) for key in R2_ACCESS):
        raise AdmissionError("Dedicated Pawn Action bucket-scoped R2 S3 credentials required")
    # Lazy import: offline plan and CI tests never need boto3 or secrets.
    try:
        import boto3
    except ImportError:
        raise AdmissionError("boto3 required only for manual live upload") from None
    return boto3.client(
        "s3", endpoint_url=f"https://{account}.r2.cloudflarestorage.com",
        region_name="auto",
        aws_access_key_id=environ[R2_ACCESS[0]],
        aws_secret_access_key=environ[R2_ACCESS[1]],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("plan", "apply"))
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--confirm-immutable-upload", default="",
                        help="Manual apply only: exact pawn-action/releases/<release-id>")
    args = parser.parse_args()
    try:
        manifest, entries = _entries(args.candidate, args.source_sha)
        if args.command == "plan":
            print("PAWN_ACTION_R2_OFFLINE_PLAN " + json.dumps({
                "sourceSha": args.source_sha, "release": manifest["release"],
                "bucket": BUCKET, "prefix": PREFIX, "objects": len(entries),
                "bytes": sum(x["bytes"] for _, x in entries.values()),
                "mutablePointers": 0, "writes": 0,
            }, sort_keys=True))
            return 0
        confirmation = f"{PREFIX}{manifest['release']}"
        if args.confirm_immutable_upload != confirmation:
            raise AdmissionError("Manual apply requires exact --confirm-immutable-upload "
                                 + confirmation)
        # Re-admit current main immediately before opening R2 credentials.
        receipt = admit(GithubReader(os.environ.get("GH_TOKEN", "")), args.source_sha)
        require_receipt(manifest, receipt)
        result = upload_immutable(create_client(os.environ), args.candidate,
                                  args.source_sha, receipt)
        print("PAWN_ACTION_R2_IMMUTABLE_OBJECTS_VERIFIED "
              + json.dumps(result, sort_keys=True))
        return 0
    except (AdmissionError, OSError) as exc:
        print("PAWN_ACTION_R2_IMMUTABLE_BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
