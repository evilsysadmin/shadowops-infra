#!/opt/shadowops/oci-venv/bin/python -I
"""Explicit root-only Bridge Squad Atlas release; no database or tunnel writes.

Thin fixed entrypoint over the reviewed single-audience Atlas operator
(installed as shadowops-identity-atlas-staradvs). The audience, candidate
config path and receipt are fixed here, never taken from the client.
Do not delegate this executable until the protected workflow admission is wired.
"""
import os
import sys
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_loader, module_from_spec

OPERATOR = "/usr/local/sbin/shadowops-identity-atlas-staradvs"
AUDIENCE = "bridgesquad"


def load(path=OPERATOR):
    loader = SourceFileLoader("atlas_single_audience_operator", path)
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


def main(argv=None, *, euid=os.geteuid, loader=load):
    argv = sys.argv if argv is None else argv
    if euid() != 0 or len(argv) != 5 or argv[1] != "deploy":
        print("IDENTITY_ATLAS_BRIDGESQUAD_BLOCKED reason=authority", file=sys.stderr)
        return 1
    try:
        print(loader().update(argv[2], argv[3], argv[4], audience=AUDIENCE))
        return 0
    except Exception:
        print("IDENTITY_ATLAS_BRIDGESQUAD_BLOCKED reason=unverified", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
