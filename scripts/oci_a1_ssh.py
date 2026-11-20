#!/usr/bin/env python3
"""Operator-only SSH access to the adopted OCI A1 via Cloudflare Access.

Ported from chess-studio/scripts/oci_a1.py (ssh / ssh-check modes).
This tool does not use OCI API credentials, perform remote commands, install
software, elevate permissions, or deploy anything. No TCP/22 public exposure.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import stat
import sys

SSH_HOST = "ssh-chess-studio-staging.shadowops.dpdns.org"
SSH_USER = "ubuntu"


class Refused(ValueError):
    pass


def operator_settings(env: dict[str, str]) -> tuple[str, str, str]:
    """Reject accidental redirection to an unreviewed host/user."""
    hostname = env.get("OCI_SSH_HOSTNAME", SSH_HOST)
    username = env.get("OCI_SSH_USER", SSH_USER)
    key = env.get("OCI_SSH_KEY", "")
    if hostname != SSH_HOST or username != SSH_USER:
        raise Refused("SSH target must be the existing adopted A1 and its ubuntu operator")
    if "\x00" in key or "\n" in key or "\r" in key:
        raise Refused("invalid private key path")
    if key:
        # Never expand an environment variable into a shell command. The key
        # remains a local path; only ssh itself reads the private key.
        path = Path(key).expanduser()
        try:
            info = path.lstat()
        except OSError:
            raise Refused("operator SSH private key not found") from None
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise Refused("operator SSH private key must be regular and private")
        key = str(path)
    return hostname, username, key


def check_edge_tls(hostname: str, timeout: float = 8.0) -> str:
    """Validate DNS and Cloudflare TLS before presenting SSH login."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                return tls.version() or "TLS"
    except socket.gaierror:
        raise Refused("Cloudflare Access SSH hostname does not resolve") from None
    except ssl.SSLCertVerificationError:
        raise Refused("Cloudflare Access SSH edge certificate is invalid") from None
    except (ssl.SSLError, OSError):
        raise Refused("Cloudflare Access SSH TLS handshake is unavailable") from None


def command(cloudflared: str, ssh: str, host: str, user: str, key: str) -> list[str]:
    # The path may contain spaces; quote it INSIDE the OpenSSH ProxyCommand.
    proxy = shlex.quote(cloudflared) + " access ssh --hostname %h"
    args = [ssh, "-o", "ProxyCommand=" + proxy,
            "-o", "StrictHostKeyChecking=ask",
            "-o", "ConnectTimeout=20",
            "-o", "ServerAliveInterval=15"]
    if key:
        args.extend(["-i", key, "-o", "IdentitiesOnly=yes"])
    args.append(user + "@" + host)
    return args


def main(argv: list[str], env=None) -> int:
    if argv not in (["check"], ["ssh"]):
        print("Usage: oci_a1_ssh.py check|ssh", file=sys.stderr)
        return 2
    env = os.environ if env is None else env
    try:
        host, user, key = operator_settings(env)
        if argv == ["ssh"] and (env.get("CI") or env.get("GITHUB_ACTIONS") or
                                 not sys.stdin.isatty()):
            raise Refused("interactive operator terminal required; CI is prohibited")
        cloudflared = shutil.which("cloudflared")
        ssh = shutil.which("ssh")
        if not cloudflared or not ssh:
            raise Refused("local cloudflared and OpenSSH are required")
        protocol = check_edge_tls(host)
        print("OCI_A1_SSH_EDGE_OK host=" + host + " tls=" + protocol +
              " cloudflared=present ssh=present", file=sys.stderr)
        if argv == ["check"]:
            print("OCI_A1_SSH_CHECK_OK edge_only=yes host_login=not-verified")
            return 0
        print("OCI_A1_SSH_CONNECT target=" + user + "@" + host +
              " via=cloudflare-access host_key=verify", file=sys.stderr)
        args = command(cloudflared, ssh, host, user, key)
        os.execv(ssh, args)
        return 0  # not reached after successful exec
    except Refused as exc:
        print("OCI_A1_SSH_REFUSED reason=" + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
