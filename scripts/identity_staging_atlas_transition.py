"""Validate the current Identity container before an Atlas-only update.

This module does not change containers or authorize an image. Its result is a
rollback image candidate, not proof that the public service can be restored.
"""
import re

IMAGE = 'ghcr.io/evilsysadmin/shadowops-identity@'
CONFIG = '/etc/shadowops/identity-staging/atlas-service.json'
TARGET = '/run/secrets/identity-staging.json'
PROJECT = 'shadowops-identity-staging'


class TransitionError(ValueError):
    pass


def current_atlas_image(rows):
    """Accept exactly one healthy, project-owned Atlas Identity container."""
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict):
        raise TransitionError('Ambiguous current Identity container')
    row = rows[0]
    labels = row.get('Config', {}).get('Labels') or {}
    image = row.get('Config', {}).get('Image')
    state = row.get('State', {})
    mounts = row.get('Mounts')
    bindings = row.get('HostConfig', {}).get('PortBindings')
    if (labels.get('com.docker.compose.project') != PROJECT
            or labels.get('com.docker.compose.service') != 'identity'
            or not isinstance(image, str)
            or not re.fullmatch(re.escape(IMAGE) + r'sha256:[a-f0-9]{64}', image)
            or state.get('Status') != 'running'
            or state.get('Health', {}).get('Status') != 'healthy'
            or bindings or not isinstance(mounts, list)):
        raise TransitionError('Unsafe current Identity container')
    configs = [m for m in mounts if isinstance(m, dict) and m.get('Destination') == TARGET]
    if len(configs) != 1 or configs[0].get('Source') != CONFIG or configs[0].get('RW') is not False:
        raise TransitionError('Current Identity is not using the Atlas configuration')
    return image.removeprefix(IMAGE)
