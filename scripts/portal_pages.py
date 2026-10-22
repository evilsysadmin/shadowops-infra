#!/usr/bin/env python3
"""Owner of ONLY the isolated ShadowOps Universe staging Pages project and hostname.

Fail-closed before mutation on any foreign/ambiguous record, project or domain.
Never reconcile the root domain or Chess/Chronicles/Star Adventures resources.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.cloudflare.com/client/v4"
ZONE = "shadowops.dpdns.org"
HOST = "staging.shadowops.dpdns.org"
PROJECT = "shadowops-universe-staging"
TARGET = PROJECT + ".pages.dev"
BASE = "https://" + HOST
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
GLB_RE = re.compile(r"^/art/(?:celestial-vault|gallery-frame|armillary|relic-[a-z]+)-[a-f0-9]{12}\.glb$")
UNHEALTHY = {"blocked", "deactivated", "error"}

class AdmissionError(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise AdmissionError("Redirect refused for credentialed Cloudflare request")

def required(env, name):
    value = env.get(name, "").strip()
    if not value:
        raise AdmissionError("Missing required Cloudflare credential: " + name)
    return value

class CloudflareClient:
    def __init__(self, env):
        self.token = required(env, "CLOUDFLARE_API_TOKEN")
        self.account = required(env, "CLOUDFLARE_ACCOUNT_ID")
        if not re.fullmatch("[0-9a-fA-F]{32}", self.account):
            raise AdmissionError("Malformed Cloudflare account ID")
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, data=None):
        if not path.startswith("/") or ".." in path or "://" in path:
            raise AdmissionError("Unsafe Cloudflare request target")
        request = urllib.request.Request(API + path, method=method,
            data=None if data is None else json.dumps(data).encode("utf-8"),
            headers={"Authorization": "Bearer " + self.token,
                     "Accept": "application/json", "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=20) as response:
                status, content = response.status, response.read(2_000_000)
        except urllib.error.HTTPError as exc:
            status, content = exc.code, exc.read(2_000_000)
        if status == 404:
            return status, None
        if status not in (200, 201):
            raise AdmissionError("Cloudflare " + method + " failed (HTTP " + str(status) + ")")
        try:
            body = json.loads(content)
        except (ValueError, UnicodeError):
            raise AdmissionError("Malformed Cloudflare API JSON") from None
        if not isinstance(body, dict) or body.get("success") is not True:
            raise AdmissionError("Cloudflare denied staging operation")
        return status, body.get("result")

def endpoints(account, zone):
    project = f"/accounts/{account}/pages/projects/{PROJECT}"
    return {
        "project": project,
        "projects": f"/accounts/{account}/pages/projects",
        "domain": project + "/domains/" + urllib.parse.quote(HOST, safe=""),
        "domains": project + "/domains",
        "dns": f"/zones/{zone}/dns_records",
    }

def inspect(client):
    if HOST != "staging." + ZONE or PROJECT != "shadowops-universe-staging":
        raise AdmissionError("Staging ownership constants do not match")
    query = urllib.parse.urlencode({"name": ZONE, "account.id": client.account})
    _, zones = client.request("GET", "/zones?" + query)
    found = [z for z in zones if isinstance(z, dict) and z.get("name") == ZONE] if isinstance(zones, list) else []
    if len(found) != 1 or not found[0].get("id"):
        raise AdmissionError("Cloudflare staging zone absent or ambiguous")
    p = endpoints(client.account, str(found[0]["id"]))
    _, records = client.request("GET", p["dns"]+"?"+urllib.parse.urlencode({"name": HOST, "per_page": "100"}))
    if not isinstance(records, list):
        raise AdmissionError("Cloudflare DNS inventory unavailable")
    matches = [row for row in records if isinstance(row, dict) and row.get("name") == HOST]
    if len(matches) > 1:
        raise AdmissionError("Multiple records already own staging hostname")
    if matches:
        record = matches[0]
        if record.get("type") != "CNAME" or record.get("proxied") is not True or str(record.get("content","")).rstrip(".") != TARGET:
            raise AdmissionError("Existing staging DNS belongs to another target")
    status, project = client.request("GET", p["project"])
    domain_state = "absent"
    if status == 200:
        if not isinstance(project, dict) or project.get("name") != PROJECT or project.get("production_branch") != "main":
            raise AdmissionError("Existing Pages staging project belongs to another owner")
        domain_status, domain = client.request("GET", p["domain"])
        if domain_status == 200:
            if not isinstance(domain, dict) or domain.get("name") != HOST or domain.get("status") in UNHEALTHY:
                raise AdmissionError("Pages domain identity/status invalid")
            domain_state = "owned"
        elif domain_status != 404:
            raise AdmissionError("Pages domain lookup refused")
    elif status != 404:
        raise AdmissionError("Pages project lookup refused")
    return p, {"dns":"owned" if matches else "absent",
               "project":"owned" if status == 200 else "absent",
               "domain":domain_state}

def project(client):
    p, inventory = inspect(client)
    if inventory["project"] == "absent":
        _, result = client.request("POST", p["projects"], {"name":PROJECT, "production_branch":"main"})
        if not isinstance(result, dict) or result.get("name") != PROJECT:
            raise AdmissionError("Staging Pages creation did not confirm project owner")
    else:
        _, result = client.request("GET", p["project"])
        if not isinstance(result, dict) or result.get("name") != PROJECT:
            raise AdmissionError("Staging Pages project identity changed")

def domain(client):
    p, inventory = inspect(client)
    if inventory["project"] != "owned":
        raise AdmissionError("Dedicated Pages staging project must exist first")
    if inventory["domain"] == "absent":
        _, result = client.request("POST", p["domains"], {"name":HOST})
        if not isinstance(result, dict) or result.get("name") != HOST or result.get("status") in UNHEALTHY:
            raise AdmissionError("Pages custom-domain association not confirmed")
    # Pages sometimes creates a same-zone DNS record automatically.
    p, inventory = inspect(client)
    if inventory["dns"] == "absent":
        client.request("POST", p["dns"], {
            "name": HOST, "type": "CNAME", "content": TARGET, "proxied":True, "ttl":1,
            "comment":"ShadowOps Universe staging Pages (shadowops-infra owner)",
        })
    _, inventory = inspect(client)
    if inventory != {"dns":"owned", "project":"owned", "domain":"owned"}:
        raise AdmissionError("Staging Pages DNS/domain not reconciled")

def read_https(path, limit=2_000_000):
    # HTTPS certificate validation is mandatory. Refuse redirect to foreign
    # origins and any unauthorized CDN rewrite; a 200 SPA fallback is not a JS/GLB.
    url = BASE + path
    request = urllib.request.Request(url, headers={
        "User-Agent":"Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36",
        "Accept":"text/html,application/json,application/javascript,model/gltf-binary,*/*",
        "Cache-Control":"no-cache",
    })
    class PublicNoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            raise AdmissionError("Unexpected public URL redirect")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context()), PublicNoRedirect())
    try:
        with opener.open(request, timeout=18) as response:
            if response.status != 200:
                raise AdmissionError("Public staging status is not HTTP 200")
            return response.headers.get("Content-Type","").lower(), response.read(limit+1)
    except (urllib.error.URLError, TimeoutError, urllib.error.HTTPError) as exc:
        raise AdmissionError("Staging HTTPS/DNS/TLS unavailable (" + type(exc).__name__ + ")") from None

def public_check(expected_sha):
    if not SHA_RE.fullmatch(expected_sha):
        raise AdmissionError("Invalid immutable staging SHA")
    mime, html = read_https("/")
    if "text/html" not in mime or b"ShadowOps Universe" not in html or b'id="app"' not in html:
        raise AdmissionError("Public root is not the ShadowOps Universe portal")
    entry = re.search(rb'<script[^>]+src="(/assets/[^"]+\.js)"', html)
    if not entry:
        raise AdmissionError("Portal HTML lacks Vite JavaScript entrypoint")
    mime, js = read_https(entry.group(1).decode("ascii"))
    if "javascript" not in mime or len(js) < 200:
        raise AdmissionError("Portal JavaScript replaced with HTML/fallback")
    mime, release = read_https("/release.json")
    try:
        manifest = json.loads(release)
    except (ValueError, UnicodeDecodeError):
        raise AdmissionError("Staging release manifest not valid JSON") from None
    if "json" not in mime or not isinstance(manifest, dict) or manifest.get("build") != expected_sha or manifest.get("environment") != "staging":
        raise AdmissionError("Staging is not running expected Git SHA")
    artifacts = manifest.get("glb_assets")
    if not isinstance(artifacts, dict) or len(artifacts) < 6:
        raise AdmissionError("Published release lacks six authored GLB assets")
    for asset, checksum in artifacts.items():
        if not GLB_RE.fullmatch(asset) or not re.fullmatch(r"[a-f0-9]{64}", str(checksum)):
            raise AdmissionError("Unexpected model path/checksum in release")
        if asset.split("/")[-1].split("-")[-1].removesuffix(".glb") != str(checksum)[:12]:
            raise AdmissionError("GLB filename does not match its digest")
        mime, data = read_https(asset)
        if len(data) < 64 or len(data) > 2_000_000 or data[:4] != b"glTF" or int.from_bytes(data[4:8],"little") != 2:
            raise AdmissionError("Staging returned invalid/incomplete GLB asset")
        if hashlib.sha256(data).hexdigest() != checksum:
            raise AdmissionError("Staging GLB checksum mismatch")
    print("SHADOWOPS_PORTAL_STAGING_LIVE sha="+expected_sha+" glbs="+str(len(artifacts)))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("self-test","preflight","project","domain","verify"))
    parser.add_argument("--sha", default="")
    args = parser.parse_args()
    try:
        if args.operation == "self-test":
            assert HOST == "staging.shadowops.dpdns.org" and TARGET == "shadowops-universe-staging.pages.dev"
            print("SHADOWOPS_PORTAL_STAGING_OWNER_OK")
        elif args.operation == "verify":
            public_check(args.sha)
        else:
            client = CloudflareClient(os.environ)
            if args.operation == "preflight":
                _, inventory = inspect(client)
                print("SHADOWOPS_PORTAL_STAGING_PREFLIGHT "+json.dumps(inventory,sort_keys=True))
            elif args.operation == "project":
                project(client)
            else:
                domain(client)
        return 0
    except AdmissionError as exc:
        print("SHADOWOPS_PORTAL_STAGING_BLOCKED "+str(exc),file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
