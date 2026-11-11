#!/usr/bin/env python3
"""Check only public staging Identity login/release endpoints. No secrets or writes.

This is diagnostic evidence, not an Identity deploy, a Snooker Vault proof,
Cloudflare Pages protection, authenticated login or cutover authorization.
"""
from __future__ import annotations

import re
import sys

import snooker_staging_operator as operator
import snooker_staging_publish as publish

SOURCE_SHA = re.compile(r"[a-f0-9]{40}\Z")


def inspect(*, login_probe=None, release_probe=None):
    if login_probe is None:
        login_probe = publish.issuer_ready
    if release_probe is None:
        release_probe = operator.deployed_identity_sha

    login = "unavailable-or-unrecognized"
    release = "unavailable"
    try:
        login_probe()
        login = "snooker-target-present"
    except publish.ProvisionError:
        pass

    try:
        candidate = release_probe()
        if not isinstance(candidate, str) or not SOURCE_SHA.fullmatch(candidate):
            raise operator.ActivationBlocked("Untrusted public release SHA")
        release = candidate
    except operator.ActivationBlocked:
        pass

    return "SNOOKER_IDENTITY_PUBLIC_CHECK login=" + login + " release_sha=" + release


def is_ready(receipt):
    """Only both live public Identity proofs can make the CI step green."""
    return isinstance(receipt, str) and bool(re.fullmatch(
        r"SNOOKER_IDENTITY_PUBLIC_CHECK login=snooker-target-present "
        r"release_sha=[a-f0-9]{40}", receipt))


def main():
    if sys.argv[1:]:
        print("SNOOKER_IDENTITY_PUBLIC_PROBE_BLOCKED reason=arguments", file=sys.stderr)
        return 1
    try:
        receipt = inspect()
        # Never classify "unavailable" as green, nor print untrusted values.
        if not is_ready(receipt):
            print("SNOOKER_IDENTITY_PUBLIC_PROBE_BLOCKED reason=not-ready", file=sys.stderr)
            return 1
        print(receipt)
        return 0
    except Exception:
        # Never forward a remote response or exception text into CI.
        print("SNOOKER_IDENTITY_PUBLIC_PROBE_BLOCKED reason=unexpected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
