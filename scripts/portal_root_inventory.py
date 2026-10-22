#!/usr/bin/env python3
"""Read-only apex DNS/Pages inventory before ShadowOps Universe promotion.

Never mutate a root record, replace existing game routes, or print secrets.
"""
from __future__ import annotations
import argparse
import json
import sys
import urllib.parse
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from portal_pages import CloudflareClient, AdmissionError, ZONE

ROOT=ZONE
PROJECT="shadowops-universe-production"
TARGET=PROJECT+".pages.dev"
ADDR_TYPES={"A","AAAA","CNAME"}

def inspect(client):
    query=urllib.parse.urlencode({"name":ZONE,"account.id":client.account})
    _,zones=client.request("GET","/zones?"+query)
    exact=[x for x in zones if isinstance(x,dict) and x.get("name")==ZONE] if isinstance(zones,list) else []
    if len(exact)!=1 or not exact[0].get("id"):
        raise AdmissionError("Root zone absent or ambiguous")
    z=str(exact[0]["id"])
    dns=f"/zones/{z}/dns_records"
    _,rows=client.request("GET",dns+"?"+urllib.parse.urlencode({"name":ROOT,"per_page":"100"}))
    if not isinstance(rows,list):raise AdmissionError("Root DNS inventory malformed")
    apex=[r for r in rows if isinstance(r,dict) and r.get("name")==ROOT and r.get("type") in ADDR_TYPES]
    if not apex:status="absent"
    elif len(apex)!=1:status="ambiguous"
    elif apex[0].get("type")=="CNAME" and str(apex[0].get("content","")).rstrip(".")==TARGET and apex[0].get("proxied") is True:
        status="owned"
    else:status="foreign"
    prefix=f"/accounts/{client.account}/pages/projects/{PROJECT}"
    pstatus,payload=client.request("GET",prefix)
    if pstatus==404:project="absent"
    elif pstatus==200 and isinstance(payload,dict) and payload.get("name")==PROJECT and payload.get("production_branch")=="main":project="owned"
    else:project="foreign"
    domain="absent"
    if project=="owned":
        ds,dp=client.request("GET",prefix+"/domains/"+urllib.parse.quote(ROOT,safe=""))
        if ds==200 and isinstance(dp,dict) and dp.get("name")==ROOT and dp.get("status") not in {"blocked","deactivated","error"}:
            domain="owned"
        elif ds!=404:domain="foreign"
    return {"apex_dns":status,"pages_project":project,"pages_domain":domain}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("operation",choices=("inventory","self-test"))
    args=parser.parse_args()
    try:
        if args.operation=="self-test":
            assert ROOT=="shadowops.dpdns.org" and TARGET=="shadowops-universe-production.pages.dev"
            print("SHADOWOPS_UNIVERSE_APEX_INVENTORY_CONTRACT_OK")
        else:
            print("SHADOWOPS_UNIVERSE_APEX_OWNERSHIP "+json.dumps(inspect(CloudflareClient(__import__("os").environ)),sort_keys=True))
        return 0
    except AdmissionError as ex:
        print("SHADOWOPS_UNIVERSE_APEX_INVENTORY_BLOCKED "+str(ex),file=sys.stderr)
        return 1
if __name__=="__main__":raise SystemExit(main())
