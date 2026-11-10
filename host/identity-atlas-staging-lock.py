#!/opt/shadowops/oci-venv/bin/python -I
"""Fixed root-only Atlas deploy.lock status and one-time legacy permission repair.

No secrets, no lock deletion, no chmod outside a validated legacy 0644 inode.
The repair is an explicit human operation, NOT a deploy fallback.
"""
import os
import sys

sys.path.insert(0, "/usr/local/lib/shadowops")
from identity_staging_atlas_lock import AtlasLockBlocked, status, repair_legacy


def main():
    if os.geteuid() != 0 or sys.argv[1:] not in (["status"], ["repair"]):
        print("IDENTITY_ATLAS_LOCK_BLOCKED reason=authority")
        return 1
    try:
        if sys.argv[1] == "status":
            result = status()
            print("IDENTITY_ATLAS_LOCK_STATUS state=" + result)
            return 0
        repaired = repair_legacy()
        print("IDENTITY_ATLAS_LOCK_REPAIR result=" + repaired)
        return 0
    except Exception:
        # No exception text, inode, file path, credential or arbitrary output.
        print("IDENTITY_ATLAS_LOCK_BLOCKED reason=unsafe-or-busy")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
