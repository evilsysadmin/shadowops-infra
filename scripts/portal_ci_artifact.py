#!/usr/bin/env python3
"""Select a previously validated Blender asset artifact for identical portal tree.

Fail over to headless Blender when the art source has changed or the artifact
is unavailable. Never reuse a successful CI artifact against different source.
"""
import json
import pathlib
import subprocess
import sys

PORTAL_TREE="51381d6246b05ba90bed256e94001b15ff0a46a7"
CI_HEAD="d5f890f38b9be1d479f52e472e5dee1f58213353"
CI_RUN=39793813918

def eligible(tree,run,artifacts):
    if tree!=PORTAL_TREE or not isinstance(run,dict):return False
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
    tree=cmd("git","rev-parse","HEAD:portal")
    if tree!=PORTAL_TREE:return "blender"
    try:
        run=json.loads(cmd("gh","api",f"repos/evilsysadmin/shadowops-infra/actions/runs/{CI_RUN}"))
        data=json.loads(cmd("gh","api",f"repos/evilsysadmin/shadowops-infra/actions/runs/{CI_RUN}/artifacts"))
    except (OSError,ValueError,subprocess.SubprocessError):
        return "blender"
    return "ci" if eligible(tree,run,data.get("artifacts")) else "blender"

if __name__=="__main__":
    mode=choose()
    if mode not in ("ci","blender"):raise SystemExit(1)
    print(mode)
