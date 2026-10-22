#!/usr/bin/env python3
"""Emit staging identity from exact local dist GLB assets after build."""
from __future__ import annotations
import hashlib
import json
import pathlib
import re
import sys

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ASSET_RE = re.compile(r"^(celestial-vault|gallery-frame|armillary|relic-[a-z]+)-[0-9a-f]{12}\.glb$")
EXPECTED = {"celestial-vault","gallery-frame","armillary","relic-chess","relic-chronicles","relic-star"}

def assemble(dist: pathlib.Path, sha: str) -> dict:
    if not SHA_RE.fullmatch(sha):
        raise ValueError("Portal release requires immutable 40-hex SHA")
    if not (dist/"index.html").is_file():
        raise ValueError("Portal static root missing index.html")
    artifact = {}
    kinds = set()
    for file in sorted((dist/"art").glob("*.glb")):
        m=ASSET_RE.fullmatch(file.name)
        if not m:raise ValueError("Unexpected GLB in portal dist: "+file.name)
        data=file.read_bytes()
        if len(data)<64 or len(data)>2_000_000 or data[:4]!=b"glTF" or int.from_bytes(data[4:8],"little")!=2:
            raise ValueError("Bad GLB exported: "+file.name)
        digest=hashlib.sha256(data).hexdigest()
        if digest[:12] != file.name.removesuffix(".glb").split("-")[-1]:
            raise ValueError("GLB output not content addressed: "+file.name)
        artifact["/art/"+file.name]=digest
        kinds.add(m.group(1))
    if kinds!=EXPECTED or len(artifact)!=6:
        raise ValueError("Portal requires six authored GLB outputs, got "+repr(kinds))
    return {"build":sha,"environment":"staging","glb_assets":artifact}

if __name__=="__main__":
    if len(sys.argv)!=3:raise SystemExit("usage: portal_release.py dist/ git-sha")
    folder=pathlib.Path(sys.argv[1])
    data=assemble(folder,sys.argv[2])
    (folder/"release.json").write_text(json.dumps(data,sort_keys=True)+"\n",encoding="utf8")
    (folder/"_headers").write_text("/release.json\n  Cache-Control: no-store, max-age=0\n",encoding="utf8")
    print("SHADOWOPS_PORTAL_ASSETS_READY sha="+data["build"]+" glbs="+str(len(data["glb_assets"])))
