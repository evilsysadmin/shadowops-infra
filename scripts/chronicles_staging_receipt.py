#!/usr/bin/env python3
"""One fail-closed identity contract for verified Chronicles staging receipts.

The API and Pages pipelines have distinct workflow IDs and artifact names,
but must apply the same exact-SHA, source-owner and completed-success rules.
No caller may supply an arbitrary trusted workflow or repository.
"""
from __future__ import annotations

import re

INFRA = "evilsysadmin/shadowops-infra"
SHA = re.compile(r"^[0-9a-f]{40}$")
API_WORKFLOW = ".github/workflows/chronicles-api-staging.yml"
PAGES_WORKFLOW = ".github/workflows/chronicles-pages-release.yml"
TRUSTED = {
    "api": ("chronicles-api-staging-", API_WORKFLOW),
    "pages": ("chronicles-pages-staging-", PAGES_WORKFLOW),
}
EVENTS = frozenset({"push", "schedule", "workflow_dispatch"})


class ReceiptError(ValueError):
    """Malformed evidence must not be confused with a missing valid receipt."""


def trusted_staging_receipt(sha: str, listing: dict, read_run, *, kind: str) -> bool:
    """Verify named artifact AND its owning successful main workflow run.

    An expired, untrusted, or mismatched artifact cannot authorize a release.
    Only API and Pages are admissible; this is not a generic caller-supplied
    workflow escape hatch. The surrounding deploy gates still verify live
    public API/Pages and current protected main independently.
    """
    if kind not in TRUSTED:
        raise ReceiptError("Unknown Chronicles receipt kind")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ReceiptError("Invalid Chronicles source SHA")
    if not isinstance(listing, dict) or not isinstance(listing.get("artifacts"), list):
        raise ReceiptError("Malformed staging artifact listing")
    prefix, workflow = TRUSTED[kind]
    for artifact in listing["artifacts"]:
        if (not isinstance(artifact, dict)
                or artifact.get("name") != prefix + sha
                or artifact.get("expired") is not False):
            continue
        origin = artifact.get("workflow_run")
        if not isinstance(origin, dict) or origin.get("head_branch") != "main":
            continue
        run_id = origin.get("id")
        if type(run_id) is not int or run_id <= 0:
            continue
        run = read_run(run_id)
        if not isinstance(run, dict):
            raise ReceiptError("Malformed staging workflow evidence")
        repository = run.get("repository")
        if (type(run.get("id")) is int and run["id"] == run_id
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and run.get("path") == workflow
                and run.get("head_branch") == "main"
                and isinstance(repository, dict)
                and repository.get("full_name") == INFRA
                and run.get("event") in EVENTS):
            return True
    return False
