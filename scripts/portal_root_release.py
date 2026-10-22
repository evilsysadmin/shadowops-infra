#!/usr/bin/env python3
"""Production owner for ONLY shadowops.dpdns.org and shadowops-universe-production Pages.

No deletion or overwrite of pre-existing apex DNS; accepts empty or exact-owned.
Publishes only a previously live-verified immutable staging artifact.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import urllib.parse
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import portal_pages as staging
import portal_root_inventory as root
from portal_release import assemble

Admit = staging.AdmissionError
SHA_RE=staging.SHA_RE
API=staging.API

def inspect(client):
    status=root.inspect(client)
    if status["apex_dns"] not in {"absent","owned"}:
        raise Admit("Foreign/ambiguous apex DNS: NEVER replace an existing root owner")
    if status["pages_project"] not in {"absent","owned"}:
        raise Admit("A foreign production Pages project already exists")
    if status["pages_domain"] not in {"absent","owned"}:
        raise Admit("A foreign Pages custom domain already exists")
    return status

def paths(client):
    query=urllib.parse.urlencode({"name":root.ZONE,"account.id":client.account})
    _,zones=client.request("GET","/zones?"+query)
    exact=[z for z in zones if isinstance(z,dict) and z.get("name")==root.ZONE] if isinstance(zones,list) else []
    if len(exact)!=1 or not exact[0].get("id"):
        raise Admit("Root Cloudflare zone missing/ambiguous")
    project=f"/accounts/{client.account}/pages/projects/{root.PROJECT}"
    return (project,f"/zones/{exact[0]['id']}/dns_records")

def ensure_project(client):
    state=inspect(client)
    project,_=paths(client)
    if state["pages_project"]=="absent":
        _,result=client.request("POST",f"/accounts/{client.account}/pages/projects",
            {"name":root.PROJECT,"production_branch":"main"})
        if not isinstance(result,dict) or result.get("name")!=root.PROJECT:
            raise Admit("Production Pages project identity mismatch")

def ensure_domain(client):
    state=inspect(client)
    if state["pages_project"]!="owned":
        raise Admit("Dedicated production Pages project must exist before root DNS change")
    project,dns=paths(client)
    domain=project+"/domains/"+urllib.parse.quote(root.ROOT,safe="")
    if state["pages_domain"]=="absent":
        _,result=client.request("POST",project+"/domains",{"name":root.ROOT})
        if not isinstance(result,dict) or result.get("name")!=root.ROOT or result.get("status") in {"blocked","deactivated","error"}:
            raise Admit("Root custom domain association was not confirmed")
    # Recheck after Pages may have automatically installed the same-zone CNAME.
    state=inspect(client)
    if state["apex_dns"]=="absent":
        client.request("POST",dns,{
            "name":root.ROOT,"type":"CNAME","content":root.TARGET,
            "proxied":True,"ttl":1,
            "comment":"ShadowOps Universe production Pages (shadowops-infra owner)",
        })
    state=inspect(client)
    if state!={"apex_dns":"owned","pages_project":"owned","pages_domain":"owned"}:
        raise Admit("Root DNS/Pages identity not reconciled to exact owner")

def validate_verified_dist(path,sha):
    if not SHA_RE.fullmatch(sha):
        raise Admit("Invalid exact staging SHA")
    dist=pathlib.Path(path)
    try:
        actual=assemble(dist,sha)
        manifest=json.loads((dist/"release.json").read_text(encoding="utf-8"))
    except (OSError,ValueError) as exc:
        raise Admit("Downloaded staging build is missing or invalid") from None
    if manifest!=actual:
        raise Admit("Downloaded staging build does not match its verified GLB manifest")
    return actual

def prepare_promotion(dist,sha):
    manifest=validate_verified_dist(dist,sha)
    # Only the environment label differs from the exact verified static asset.
    manifest["environment"]="production"
    path=pathlib.Path(dist)
    (path/"release.json").write_text(json.dumps(manifest,sort_keys=True)+"\n",encoding="utf-8")
    print("SHADOWOPS_UNIVERSE_PROMOTION_ASSETS_VERIFIED sha="+sha)

def verify(sha):
    if not SHA_RE.fullmatch(sha):
        raise Admit("Invalid immutable production SHA")
    original=staging.BASE
    staging.BASE="https://"+root.ROOT
    try:
        mime,html=staging.read_https("/")
        if "html" not in mime or b"ShadowOps Universe" not in html or b'id="app"' not in html:
            raise Admit("Root HTTPS is not the expected Universe portal")
        entry=re.search(rb'<script[^>]+src="(/assets/[^"]+\.js)"',html)
        if not entry:raise Admit("Root HTML has no Vite JS entry")
        mime,data=staging.read_https(entry.group(1).decode("ascii"))
        if "javascript" not in mime or len(data)<200:raise Admit("Root JavaScript is missing/HTML fallback")
        mime,release=staging.read_https("/release.json")
        try:manifest=json.loads(release)
        except (ValueError,UnicodeError):raise Admit("Root release manifest malformed") from None
        if "json" not in mime or not isinstance(manifest,dict) or manifest.get("build")!=sha or manifest.get("environment")!="production":
            raise Admit("Root does not serve expected production SHA")
        glbs=manifest.get("glb_assets")
        if not isinstance(glbs,dict) or len(glbs)!=6:raise Admit("Root GLB release set incomplete")
        for asset,digest in glbs.items():
            if not staging.GLB_RE.fullmatch(asset) or not re.fullmatch("[a-f0-9]{64}",str(digest)):
                raise Admit("Invalid root GLB identity")
            _,content=staging.read_https(asset)
            if len(content)<64 or content[:4]!=b"glTF" or hashlib.sha256(content).hexdigest()!=digest:
                raise Admit("Root model missing or checksum mismatch")
        print("SHADOWOPS_UNIVERSE_PRODUCTION_PUBLIC_READY sha="+sha+" https://"+root.ROOT)
    finally:
        staging.BASE=original

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("operation",choices=("self-test","preflight","project","domain","prepare","verify"))
    parser.add_argument("--sha",default="")
    parser.add_argument("--dist",default="")
    args=parser.parse_args()
    try:
        if args.operation=="self-test":
            assert root.ROOT=="shadowops.dpdns.org" and root.PROJECT=="shadowops-universe-production"
            print("SHADOWOPS_UNIVERSE_ROOT_RELEASE_OWNER_OK")
        elif args.operation=="prepare":
            prepare_promotion(args.dist,args.sha)
        elif args.operation=="verify":
            verify(args.sha)
        else:
            client=staging.CloudflareClient(os.environ)
            if args.operation=="preflight":
                print("SHADOWOPS_UNIVERSE_ROOT_PREFLIGHT "+json.dumps(inspect(client),sort_keys=True))
            elif args.operation=="project":ensure_project(client)
            else:ensure_domain(client)
        return 0
    except Admit as exc:
        print("SHADOWOPS_UNIVERSE_ROOT_BLOCKED "+str(exc),file=sys.stderr)
        return 1

if __name__=="__main__":raise SystemExit(main())
