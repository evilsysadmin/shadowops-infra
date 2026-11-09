#!/usr/bin/env python3
"""Rebuild and publish eight *immutable* Football action WebPs via Infra custody.

The inputs are six independently SHA-pinned, publicly served runtime R2
atlases. No binary source enters Git or this workflow, and PRs can only run
the read-only verification. Cloud writes require trusted Infra main.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import football_delivery as delivery
import football_pages as pages

ORIGIN = "https://staging.football.shadowops.dpdns.org"
ROOT = "https://pub-cda6a24cd2f94f7eaaf4d112351bf526.r2.dev"
SOURCE_SHA = "17f8286085869caaa9319310d467cca24a5eb24c"
BUCKET = "football"
TEAMS = ("fc_matthias", "real_enroque")
ACTIONS = ("dribble_cut", "dribble_burst", "tackle", "slide_tackle")
SOURCES = {
    "fc_matthias_run_v3_clean.webp": ("v3", "8208785adbda34a893c8445299c32a04714932feabcb8aa41ae39b8a1f9177af"),
    "real_enroque_run_v3_clean.webp": ("v3", "be73bb8fee9b1fa830ae7f405c533cb4e2fc7538c9fe248c65b0f9e63a655e01"),
    "fc_matthias_carry_dribble_v1.webp": ("v1", "d77d23b1a19bd454a829e6a2368aeefbeaa0ca42ee5b1a2ec530218437a0ef9d"),
    "real_enroque_carry_dribble_v1.webp": ("v1", "39606797cb05c582c598cb5b599cc59104e3926a963bbc445dc0444aaa80bbeb"),
    "fc_matthias_pass_shoot_v1.webp": ("v1", "ad286ff56d0f1461efaa9aad20fc349203ed9a90b3ea3e45f60d41493b9c2b24"),
    "real_enroque_pass_shoot_v1.webp": ("v1", "5dae02988c73e1353a17d3ef521949049a1b41c89b97fc01a5042cca691afc36"),
}
EXPECTED = {
    "fc_matthias_dribble_cut_poses_v2.webp": "0ebe3ed766f9adf90e3c8327315cbf53282bdb3e1d6dbceac1fa0e4e81cd8c93",
    "fc_matthias_dribble_burst_poses_v2.webp": "d516759fb53668d5fc02daf0581b8d61e1bddbb29b9725e9e4fa3edcd9729d9b",
    "fc_matthias_tackle_poses_v2.webp": "a3c50d36bc62104bb88e60e96da2134c99180bd4afe50dc7d92115271d08b18c",
    "fc_matthias_slide_tackle_poses_v2.webp": "21b1f297d52752977d20d7d6d4f2952c5158605922157bf1edb6a063fdd76071",
    "real_enroque_dribble_cut_poses_v2.webp": "6acec93d0e91c227c9367ba326330083a4d358b965f78b1df339d588353c37aa",
    "real_enroque_dribble_burst_poses_v2.webp": "2625c30ae31784008c3f2c665ec22ce79bfa664f663510ce5d463933c67f54b5",
    "real_enroque_tackle_poses_v2.webp": "1e64f42753f9a30d4361008abb99e6f71092d74dc85f05104a822ae9fa82fb77",
    "real_enroque_slide_tackle_poses_v2.webp": "819e008a135797e4d3fd901457f2433e08f94358bc43b8b3ef0f1ddc756ec564",
}
KEYFRAMES = {
    "dribble_cut": (("c",0),("c",1),("d",2),("d",3),("p",4),("d",5),("d",6),("c",7)),
    "dribble_burst": (("d",0),("d",1),("s",0),("s",2),("s",3),("s",4),("d",5),("c",7)),
    "tackle": (("p",0),("p",1),("p",2),("s",3),("s",4),("s",5),("p",6),("p",7)),
    "slide_tackle": (("d",0),("s",1),("s",3),("s",4),("s",5),("s",6),("s",7),("p",7)),
}
MAX_OBJECT = 1_048_576


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fetch_public(path: str, *, allow_404=False) -> bytes | None:
    uri = ROOT + "/" + path
    req = urllib.request.Request(uri, headers={
        "Origin": ORIGIN, "User-Agent": "ShadowOps-Infra-Football-Action-v2/1.0",
        "Cache-Control": "no-cache",
    })
    try:
        with urllib.request.urlopen(req, timeout=22) as response:
            if response.status != 200 or response.geturl() != uri:
                raise delivery.DeliveryError("Public R2 object redirected or not HTTP 200")
            cors = response.headers.get("Access-Control-Allow-Origin", "")
            if cors not in ("*", ORIGIN) or "image/webp" not in response.headers.get("Content-Type", "").lower():
                raise delivery.DeliveryError("Public R2 object lacks WebP content type or staging CORS")
            raw = response.read(MAX_OBJECT + 1)
            if not 25 <= len(raw) <= MAX_OBJECT:
                raise delivery.DeliveryError("Public R2 WebP exceeds bounded size")
            return raw
    except urllib.error.HTTPError as error:
        if allow_404 and error.code == 404:
            return None
        raise delivery.DeliveryError("Public R2 returned HTTP " + str(error.code)) from None
    except (OSError, ValueError) as error:
        if isinstance(error, delivery.DeliveryError):
            raise
        raise delivery.DeliveryError("Public R2 unavailable") from None


def fetch_sources() -> dict[str, bytes]:
    source = {}
    for name, (family, expected_sha) in SOURCES.items():
        raw = fetch_public("atlases/" + family + "/" + name)
        if digest(raw) != expected_sha:
            raise delivery.DeliveryError("Canonical R2 source SHA mismatch: " + name)
        source[name] = raw
    return source


def rotate_grounded(src, angle, height, dx=0):
    # Identical composition to the reviewed local v2 authoring script.
    from PIL import Image, ImageDraw, ImageFilter
    import numpy as np
    import cv2
    rgba = np.array(src.copy())
    mask = (rgba[:, :, 3] > 3).astype(np.uint8)
    count, labels, stats, _ = cv2.connectedComponentsWithStats(mask, 8)
    for k in range(1, count):
        x, y, w, h, area = (int(v) for v in stats[k])
        if y >= 125 and h <= 12 and area < 120:
            rgba[labels == k, 3] = 0
    clean = Image.fromarray(rgba, "RGBA")
    box = clean.getchannel("A").getbbox()
    if not box:
        raise delivery.DeliveryError("Empty slide source")
    crop = clean.crop(box)
    rotated = crop.rotate(angle, Image.Resampling.BICUBIC, expand=True)
    rotated = rotated.crop(rotated.getchannel("A").getbbox())
    tw, th = min(114, rotated.width), min(height, rotated.height)
    rotated = rotated.resize((tw, th), Image.Resampling.LANCZOS)
    out = Image.new("RGBA", (128, 144))
    shadow = Image.new("RGBA", (128, 144))
    draw = ImageDraw.Draw(shadow)
    draw.ellipse((15, 128, 114, 134), fill=(8, 11, 19, 52))
    shadow = shadow.filter(ImageFilter.GaussianBlur(0.75))
    out.alpha_composite(shadow)
    x = max(4, min(124 - tw, round((128 - tw) / 2 + dx)))
    out.alpha_composite(rotated, (x, 134 - th))
    return out


def build(source: dict[str, bytes]) -> dict[str, bytes]:
    from PIL import Image
    result = {}
    for team in TEAMS:
        run = Image.open(io.BytesIO(source[team + "_run_v3_clean.webp"])).convert("RGBA")
        carry = Image.open(io.BytesIO(source[team + "_carry_dribble_v1.webp"])).convert("RGBA")
        kick = Image.open(io.BytesIO(source[team + "_pass_shoot_v1.webp"])).convert("RGBA")
        if (run.size, carry.size, kick.size) != ((1536, 720), (1024, 288), (1024, 288)):
            raise delivery.DeliveryError("Unexpected canonical source sheet geometry")
        sheets = {
            "c": [carry.crop((i * 128, 0, (i + 1) * 128, 144)) for i in range(8)],
            "d": [carry.crop((i * 128, 144, (i + 1) * 128, 288)) for i in range(8)],
            "p": [kick.crop((i * 128, 0, (i + 1) * 128, 144)) for i in range(8)],
            "s": [kick.crop((i * 128, 144, (i + 1) * 128, 288)) for i in range(8)],
        }
        for action in ACTIONS:
            poses = [sheets[key][index].copy() for key, index in KEYFRAMES[action]]
            if action == "slide_tackle":
                for i, angle, height, dx in ((3, 19, 88, 0), (4, 27, 75, 2), (5, 21, 83, 3)):
                    poses[i] = rotate_grounded(sheets["s"][4], angle, height, dx)
            assert len(poses) == 8
            for i, frame in enumerate(poses):
                box = frame.getchannel("A").getbbox()
                if not box:
                    raise delivery.DeliveryError("Blank pose")
                x, y, right, bottom = box
                if not (frame.size == (128, 144) and x >= 4 and right <= 124
                        and 4 <= y <= 78 and 130 <= bottom <= 139
                        and bottom - y >= 60 and right - x >= 45
                        and frame.getpixel((0, 0))[3] < 15
                        and frame.getpixel((127, 0))[3] < 15):
                    raise delivery.DeliveryError("Clipped/ungrounded pose")
                if i and frame.tobytes() == poses[i-1].tobytes():
                    raise delivery.DeliveryError("Repeated animation pose")
            merged = Image.new("RGBA", (1024, 144))
            for i, frame in enumerate(poses):
                merged.alpha_composite(frame, (i * 128, 0))
            output = io.BytesIO()
            merged.save(output, "WEBP", lossless=True, method=6)
            filename = f"{team}_{action}_poses_v2.webp"
            raw = output.getvalue()
            if len(raw) > MAX_OBJECT or digest(raw) != EXPECTED[filename]:
                raise delivery.DeliveryError("Generated v2 art does not match immutable reviewed hash: " + filename)
            result[filename] = raw
    if set(result) != set(EXPECTED) or sum(map(len, result.values())) > 1_000_000:
        raise delivery.DeliveryError("Incomplete/out-of-budget v2 pack")
    return result


def inventory(account: str, bucket: str) -> dict[str, int]:
    root = f"/accounts/{account}/r2/buckets/{bucket}/objects"
    items, cursor = {}, None
    seen = set()
    for _ in range(25):
        args = {"per_page": 1000}
        if cursor:
            args["cursor"] = cursor
        response = delivery.r2_request("GET", root + "?" + urllib.parse.urlencode(args))
        rows = response.get("result")
        if not isinstance(rows, list):
            raise delivery.DeliveryError("Bounded object inventory required")
        for item in rows:
            key, size = item.get("key"), item.get("size")
            if not isinstance(key, str) or not isinstance(size, int) or size < 0 or key in items:
                raise delivery.DeliveryError("Invalid object inventory")
            items[key] = size
        info = response.get("result_info", {})
        if info.get("is_truncated") is False or (not info.get("is_truncated") and len(rows) < 1000):
            return items
        cursor = info.get("cursor")
        if not isinstance(cursor, str) or cursor in seen:
            raise delivery.DeliveryError("Truncated R2 inventory")
        seen.add(cursor)
    raise delivery.DeliveryError("R2 inventory unbounded")


def publish(pack: dict[str, bytes]):
    if (os.getenv("GITHUB_REPOSITORY") != "evilsysadmin/shadowops-infra"
            or os.getenv("GITHUB_REF") != "refs/heads/main"
            or os.getenv("GITHUB_EVENT_NAME") not in ("push", "workflow_dispatch")):
        raise delivery.DeliveryError("Only trusted Infra main may publish")
    admitted = delivery.admit()
    if admitted is None or admitted["source_sha"] != SOURCE_SHA:
        raise delivery.DeliveryError("Source SHA or main CI changed, refusing publish")
    account = pages.required("CLOUDFLARE_ACCOUNT_ID")
    if not re.fullmatch(r"[a-f0-9]{32}", account):
        raise delivery.DeliveryError("Cloudflare account identity invalid")
    owned = inventory(account, BUCKET)
    shared = delivery.inventory(account)
    addition = {f"atlases/v2/{name}": len(raw) for name, raw in pack.items()
                if f"atlases/v2/{name}" not in owned}
    if (sum(owned.values()) + sum(shared.values()) + sum(addition.values()) > delivery.BUDGET
            or sum(addition.values()) > 1_000_000):
        raise delivery.DeliveryError("R2 free-tier capacity insufficient")
    # No mutation of preexisting keys, including the previous v1 pack.
    for name, raw in pack.items():
        if f"atlases/v2/{name}" in owned:
            actual = fetch_public("atlases/v2/" + name)
            if digest(actual) != digest(raw) or owned[f"atlases/v2/{name}"] != len(raw):
                raise delivery.DeliveryError("Refuse overwrite: published v2 object differs")
    admitted = delivery.admit()
    if admitted is None or admitted["source_sha"] != SOURCE_SHA:
        raise delivery.DeliveryError("Football source changed before cloud write")
    for name in sorted(pack):
        key = f"atlases/v2/{name}"
        if key in owned:
            continue
        endpoint = (f"/accounts/{account}/r2/buckets/{BUCKET}/objects/"
                    + urllib.parse.quote(key, safe="/-._~"))
        delivery.r2_request("PUT", endpoint, data=pack[name], content_type="image/webp")
    # R2 public endpoint may lag PUT very briefly; never report success early.
    for attempt in range(5):
        try:
            for name, raw in pack.items():
                found = fetch_public("atlases/v2/" + name)
                if digest(found) != digest(raw):
                    raise delivery.DeliveryError("Published v2 SHA differs")
            break
        except delivery.DeliveryError:
            if attempt == 4:
                raise
            time.sleep(2)
    print("FOOTBALL_ACTION_POSES_V2_PUBLIC_VERIFIED sheets=8 source_sha=" + SOURCE_SHA)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("verify", "publish"):
        raise delivery.DeliveryError("Usage: football_action_poses_v2_publish.py verify|publish")
    source = fetch_sources()
    pack = build(source)
    print("FOOTBALL_ACTION_POSES_V2_REBUILT_EXACT sheets=8 source_sha=" + SOURCE_SHA)
    if sys.argv[1] == "publish":
        publish(pack)


if __name__ == "__main__":
    try:
        main()
    except (delivery.DeliveryError, ValueError, OSError) as exc:
        print("FOOTBALL_ACTION_POSES_V2_BLOCKED " + str(exc), file=sys.stderr)
        raise SystemExit(1)
