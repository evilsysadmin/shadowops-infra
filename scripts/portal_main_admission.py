#!/usr/bin/env python3
"""Allow exact portal release after unrelated Infra main merges only.

Never promote if current main changed portal code, release code, relevant tests
or the Pages workflow; reject ambiguous, divergent or truncated comparisons.
"""
import json
import os
import re
import subprocess
import sys

REPO="evilsysadmin/shadowops-infra"
SHA=re.compile(r"^[a-f0-9]{40}$")
WATCH=("portal/","scripts/portal_","tests/test_portal_",".github/workflows/portal-")
EXACT={".github/workflows/shadowops-portal-ci.yml"}

def check(candidate,current,compare=None):
    if not SHA.fullmatch(candidate) or not SHA.fullmatch(current):
        raise ValueError("Invalid immutable SHA")
    if candidate==current:return "same-sha"
    if not isinstance(compare,dict) or compare.get("status")!="ahead":
        raise ValueError("Candidate is not an ancestor of current main")
    files=compare.get("files")
    if not isinstance(files,list) or len(files)>=300 or not isinstance(compare.get("total_commits"),int) or compare["total_commits"]>100:
        raise ValueError("Diff evidence incomplete or too large")
    for f in files:
        if not isinstance(f,dict) or not isinstance(f.get("filename"),str):
            raise ValueError("Malformed compare file")
        for name in [f["filename"],f.get("previous_filename","")]:
            if name in EXACT or any(name.startswith(prefix) for prefix in WATCH):
                raise ValueError("Portal source or publisher superseded: "+name)
    return "unrelated-infra-only"

def api(path):
    raw=subprocess.check_output(["gh","api",path],stderr=subprocess.DEVNULL,timeout=30)
    return json.loads(raw)

def main():
    candidate=os.environ.get("GITHUB_SHA","")
    if not SHA.fullmatch(candidate):raise ValueError("Missing immutable checkout SHA")
    current=api("repos/"+REPO+"/commits/main").get("sha","")
    compare=None if current==candidate else api(f"repos/{REPO}/compare/{candidate}...{current}")
    print("SHADOWOPS_PORTAL_MAIN_ADMISSION "+check(candidate,current,compare))

if __name__=="__main__":
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        print("SHADOWOPS_PORTAL_SUPERSEDED "+str(e),file=sys.stderr)
        raise SystemExit(1)
