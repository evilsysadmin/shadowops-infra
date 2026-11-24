"""Offline Atlas image+configuration identity and rollback checkpoint.

No deployment or provider access. A privileged caller must independently admit
the image, verify custody of both immutable private configs, backup/restore and
public audiences before clearing a transition.
"""
from copy import deepcopy
import re

from identity_staging_atlas_transition import (
    ALLOWED_CONFIGS, CONFIG, SNOOKER_CONFIG, STARADVS_CONFIG, BRIDGESQUAD_CONFIG, TARGET, DIGEST,
    AtlasTransitionBlocked, TransitionCheckpoint, image_from_atlas_container,
)

SHA = re.compile(r"[a-f0-9]{40}\Z")
SOURCE = "https://github.com/evilsysadmin/shadowops-infra"
# Each isolated single-audience candidate may only replace an existing reviewed
# config, never itself. The two opt-in extensions are independent of order.
TRANSITIONS = {
    STARADVS_CONFIG: frozenset({CONFIG, SNOOKER_CONFIG, BRIDGESQUAD_CONFIG}),
    BRIDGESQUAD_CONFIG: frozenset({CONFIG, SNOOKER_CONFIG, STARADVS_CONFIG}),
}


def live_release(rows):
    """Identify the actual allowed read-only mount, digest and source SHA."""
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise AtlasTransitionBlocked("Ambiguous Atlas release")
    mounts = rows[0].get("Mounts")
    if not isinstance(mounts, list) or len(mounts) > 16:
        raise AtlasTransitionBlocked("Ambiguous Atlas mounts")
    sources = [m.get("Source") for m in mounts if isinstance(m, dict)
               and m.get("Destination") == TARGET]
    if (len(sources) != 1 or not isinstance(sources[0], str)
            or sources[0] not in ALLOWED_CONFIGS):
        raise AtlasTransitionBlocked("Untrusted Atlas config source")
    digest = image_from_atlas_container(rows, config_source=sources[0])
    labels = rows[0]["Config"]["Labels"]
    sha = labels.get("org.opencontainers.image.revision")
    if (labels.get("org.opencontainers.image.source") != SOURCE
            or not isinstance(sha, str) or not SHA.fullmatch(sha)):
        raise AtlasTransitionBlocked("Untrusted Atlas source identity")
    return {"digest": digest, "source_sha": sha, "config": sources[0]}


def check_pair(previous, candidate):
    for release in (previous, candidate):
        if (not isinstance(release, dict)
                or set(release) != {"digest", "source_sha", "config"}
                or not isinstance(release["digest"], str)
                or not DIGEST.fullmatch(release["digest"])
                or not isinstance(release["source_sha"], str)
                or not SHA.fullmatch(release["source_sha"])
                or not isinstance(release["config"], str)
                or release["config"] not in ALLOWED_CONFIGS):
            raise AtlasTransitionBlocked("Invalid Atlas release identity")
    if previous["config"] not in TRANSITIONS.get(candidate["config"], ()):
        raise AtlasTransitionBlocked("Invalid isolated audience config transition")
    if (previous["digest"] == candidate["digest"]
            and previous["source_sha"] != candidate["source_sha"]):
        raise AtlasTransitionBlocked("Conflicting image source identity")


class ReleaseCheckpoint(TransitionCheckpoint):
    """Same exclusive pending path as legacy deploy; persist only fixed identities.

    The legacy reader cannot clear a pair-shaped record. A pending legacy
    record likewise cannot be cleared by this class.
    """
    MAX_CHECKPOINT_BYTES = 1024
    _check_digests = staticmethod(check_pair)


def guarded_release(previous, candidate, *, journal, activate, verify):
    """Verify exact image AND config; a config-only change may reuse the image."""
    check_pair(previous, candidate)
    previous, candidate = deepcopy(previous), deepcopy(candidate)
    journal.begin(previous, candidate)
    try:
        activate(deepcopy(candidate))
        if verify(deepcopy(candidate)) is not True:
            raise AtlasTransitionBlocked("Candidate release not proven")
    except Exception:
        try:
            activate(deepcopy(previous))
            if verify(deepcopy(previous)) is not True:
                raise AtlasTransitionBlocked("Previous release not proven")
        except Exception:
            raise AtlasTransitionBlocked(
                "Atlas rollback unverified; checkpoint retained") from None
        journal.clear(previous, candidate)
        raise AtlasTransitionBlocked("Candidate failed; previous release verified") from None
    journal.clear(previous, candidate)
