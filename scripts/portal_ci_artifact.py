#!/usr/bin/env python3
"""Reuse verified GLB art only when every art authoring source and dependency match.

Routing, prose and CSS changes must not rerender identical assets. Art-source or
dependency changes, stale CI evidence, or missing artifacts fail over to Blender.
"""
import json
import pathlib
import subprocess
import sys

ART_TREE="bc1b350d156122071575ab47438a5081afe9037b"
PACKAGE_BLOB="7c2ae589560f0b8f30b35909e5bb1f9d420d42ee"
CI_HEAD="d5f890f38b9be1d479f52e472e5dee1f58213353"
CI_RUN=39793813918

def eligible(art_tree,package_blob,run,artifacts):
    if art_tree!=ART_TREE or package_blob!=PACKAGE_BLOB or not isinstance(run,dict):return False
    if run.get("id")!=CI_RUN or run.get("head_sha")!=CI_HEAD or run.get("event")!="pull_request":
        return False
    if run.get("status")!="completed" or run.get("conclusion")!="success":
        return False
    return isinstance(artifacts,list) and any(
        x.get("name")=="portal-compiled-art" and x.get("expired") is False and
        isinstance(x.get("size_in_bytes"),int) and x["size_in_bytes"]>200000
        for x in artifacts if isinstance(x,dict))

def cmd(*args):
    return subprocess.check_output(args,stderr=subprocess.DEVNULL,timeout=25).decode().strip()

def choose():
    art_tree=cmd("git","rev-parse","HEAD:portal/art")
    package_blob=cmd("git","rev-parse","HEAD:portal/package.json")
    if art_tree!=ART_TREE or package_blob!=PACKAGE_BLOB:return "blender"
    try:
        run=json.loads(cmd("gh","api",f"repos/evilsysadmin/shadowops-infra/actions/runs/{CI_RUN}"))
        data=json.loads(cmd("gh","api",f"repos/evilsysadmin/shadowops-infra/actions/runs/{CI_RUN}/artifacts"))
    except (OSError,ValueError,subprocess.SubprocessError):
        return "blender"
    return "ci" if eligible(art_tree,package_blob,run,data.get("artifacts")) else "blender"

if __name__=="__main__":
    mode=choose()
    if mode not in ("ci","blender"):raise SystemExit(1)
    print(mode)
