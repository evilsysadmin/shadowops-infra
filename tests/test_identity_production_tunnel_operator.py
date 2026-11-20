"""Operator phase-2 tunnel: simulate Docker and public responses, never deploy."""
from __future__ import annotations

import base64
from contextlib import nullcontext
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "identity_production_tunnel_operator", ROOT / "host/identity-production-tunnel.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
KEY = {
    "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
    "kid": "synthetic-identity-prod",
    "x": base64.urlsafe_b64encode(b"\x13"*32).decode().rstrip("="),
}
JWKS = json.dumps({"keys": [KEY]}).encode()
BACK = m.public.ORIGIN + "/?shadowops=central"
LOGIN = (f'<html><body data-return-url="{BACK}"><h1>Bridge Squad</h1>'
         f'<a class="brand" href="{BACK}">SHADOWOPS</a>'
         f'<a class="return-link" href="{BACK}">Volver a Bridge Squad</a>'
         f'</body></html>').encode()
CSP = "default-src 'none'; form-action 'self'; frame-ancestors 'none'"
CA = Path("/synthetic/ca.pem")
DIGEST = "sha256:"+"b"*64
LOCAL = {
    "tls": "verified", "ready": "yes",
    "jwks": "ed25519-public", "foreign_host": "denied",
    "registration": "disabled",
}


class FakeDocker:
    def __init__(self):
        self.events = []
        self.origin_running = True
        self.tunnel_running = False
        self.fail_up = False
        self.add_rogue = False

    def __call__(self, args, **kwargs):
        self.events.append(tuple(args))
        if args[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="sha256:"+"c"*64+"\n")
        if args[:2] != ["docker", "compose"]:
            raise AssertionError("foreign executable used")
        if "ps" in args:
            rows = []
            if self.origin_running:
                rows.append({"Project":m.op.PROJECT,"Service":m.op.SERVICE,"State":"running"})
            if self.tunnel_running:
                rows.append({"Project":m.op.PROJECT,"Service":m.op.TUNNEL,"State":"running"})
            if self.add_rogue and self.tunnel_running:
                rows.append({"Project":m.op.PROJECT,"Service":"rogue","State":"running"})
            return SimpleNamespace(returncode=0, stdout="\n".join(json.dumps(x) for x in rows))
        if "up" in args:
            self.tunnel_running = True
            if self.fail_up:
                return SimpleNamespace(returncode=1, stdout="", stderr="synthetic failure")
            return SimpleNamespace(returncode=0, stdout="")
        if "stop" in args:
            if args[-1] != m.op.TUNNEL:
                raise AssertionError("would stop the production origin")
            self.tunnel_running = False
            return SimpleNamespace(returncode=0, stdout="")
        raise AssertionError("unadmitted compose verb")


def public_read(url):
    if url == m.public.ISSUER+"/readyz":
        return 200, {}, b"ready"
    if url == m.public.ISSUER+"/api/identity/jwks":
        return 200, {"Content-Type":"application/json"}, JWKS
    if url == m.public.ISSUER+"/login?app=bridgesquad":
        return 200, {"Content-Type":"text/html", "Content-Security-Policy":CSP}, LOGIN
    raise AssertionError("unexpected production endpoint")


class OperatorTests(unittest.TestCase):
    def env_gate(self):
        return (
            mock.patch.object(m.op, "admission", return_value=("a"*40, "expected-image")),
            mock.patch.object(m.op, "exclusive", return_value=nullcontext()),
            mock.patch.object(m.op, "require_manual"),
            mock.patch.object(m.origin, "ca_file", return_value=CA),
            mock.patch.dict(os.environ, {"IDENTITY_PRODUCTION_TUNNEL_DIGEST":DIGEST}),
        )

    def test_plan_is_offline_and_ci_start_stop_are_refused(self):
        self.assertEqual(m.main(["plan"]), 0)
        self.assertEqual(m.main([]), 2)
        self.assertEqual(m.main(["deploy"]), 2)
        with mock.patch.dict(os.environ, {"CI":"true"}):
            self.assertEqual(m.main(["start-tunnel"]), 1)
            self.assertEqual(m.main(["stop-tunnel"]), 1)

    def test_exact_realistic_public_key_and_no_private_key(self):
        self.assertEqual(m.exact_jwk(JWKS), KEY)
        for bad in (
            json.dumps({"keys":[{**KEY,"d":"private"}]}).encode(),
            json.dumps({"keys":[KEY, KEY]}).encode(),
            json.dumps({"keys":[{**KEY,"alg":"RS256"}]}).encode(),
            json.dumps({"keys":[{**KEY,"x":"a"}]}).encode(),
            b'{"keys":[]}',
            ('{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig",'
             '"alg":"EdDSA","kid":"one","kid":"two","x":"'+KEY["x"]+'"}]}').encode(),
        ):
            with self.subTest(sample=bad[:34]), self.assertRaises(m.Refused):
                m.exact_jwk(bad)

    def test_public_binding_requires_exact_same_key_and_safe_login(self):
        m.public_binding(KEY, read=public_read)
        with self.assertRaises(m.Refused):
            m.public_binding({**KEY,"kid":"staging"}, read=public_read)
        def redirected(url):
            if url.endswith("/readyz"):
                return 302, {"Location": "https://id-staging.shadowops.dpdns.org"}, b""
            return public_read(url)
        with self.assertRaises((m.Refused,m.public.UnsafeIssuer)):
            m.public_binding(KEY, read=redirected)
        def stale(url):
            if url.endswith("/api/identity/jwks"):
                return 503, {}, b""
            return public_read(url)
        with self.assertRaises(m.Refused):
            m.public_binding(KEY, read=stale)

    def test_game_quarantine_rejects_any_guest_escape(self):
        calls = []
        def denied(url, method):
            calls.append((url,method))
            return 401
        m.guest_quarantine(observe=denied)
        self.assertEqual(calls, [
            (m.public.ORIGIN+"/","GET"),(m.public.ORIGIN+"/","HEAD"),
            (m.public.ORIGIN+"/index.html","GET"),
        ])
        with self.assertRaises(m.Refused):
            m.guest_quarantine(observe=lambda url, method: 200)
        with self.assertRaises(m.Refused):
            m.guest_quarantine(observe=lambda url, method: 404)

    def test_local_admission_rejects_missing_origin_and_tunnel(self):
        env = self.env_gate()
        for context in env:
            context.__enter__()
        try:
            for case in ("absent", "existing_tunnel", "bad_tls", "not_ready"):
                docker = FakeDocker()
                if case == "absent": docker.origin_running = False
                if case == "existing_tunnel": docker.tunnel_running = True
                inspected = dict(LOCAL)
                if case == "bad_tls": inspected["tls"] = "unverified"
                if case == "not_ready": inspected["ready"] = "no"
                with self.subTest(case=case), self.assertRaises(m.Refused):
                    m.local_admission(runner=docker, inspect=lambda ca: inspected)
                self.assertFalse(any("up" in x for x in docker.events))
        finally:
            for context in reversed(env):
                context.__exit__(None,None,None)

    def test_start_uses_only_tunnel_and_requires_health_public_identity_and_game_401(self):
        docker = FakeDocker()
        patches = self.env_gate()
        for context in patches: context.__enter__()
        try:
            m.start_tunnel(
                runner=docker,
                inspect=lambda ca: dict(LOCAL),
                get_local_key=lambda ca: KEY,
                check_public=lambda key: self.assertEqual(key,KEY),
                check_guest=lambda: None,
                sleep=lambda t: None,
            )
        finally:
            for context in reversed(patches): context.__exit__(None,None,None)
        ups = [x for x in docker.events if "up" in x]
        self.assertEqual(len(ups), 1)
        self.assertEqual(ups[0][-1], m.op.TUNNEL)
        self.assertIn("--no-deps", ups[0])
        self.assertIn("--pull", ups[0])
        self.assertIn("never", ups[0])
        self.assertNotIn(m.op.SERVICE, ups[0])
        self.assertTrue(docker.origin_running)
        self.assertTrue(docker.tunnel_running)

    def test_after_start_public_mismatch_dns_failure_game_escape_or_up_error_rolls_back_tunnel_only(self):
        for case in ("public-jwks", "id-down", "game-200", "up-error", "rogue"):
            with self.subTest(case=case):
                docker=FakeDocker()
                docker.fail_up = case == "up-error"
                docker.add_rogue = case == "rogue"
                patches=self.env_gate()
                for context in patches: context.__enter__()
                try:
                    def public_check(key):
                        if case == "public-jwks": raise m.Refused("synthetic public mismatch")
                    def check_guest():
                        # first call is before the container can start
                        if case == "game-200" and docker.tunnel_running:
                            raise m.Refused("guest suddenly sees game assets")
                    def inspect(ca):
                        if case == "id-down" and docker.tunnel_running:
                            return {**LOCAL,"ready":"no"}
                        return dict(LOCAL)
                    with self.assertRaises(m.Refused):
                        m.start_tunnel(
                            runner=docker, inspect=inspect,
                            get_local_key=lambda ca: KEY,
                            check_public=public_check, check_guest=check_guest,
                            sleep=lambda t: None)
                finally:
                    for context in reversed(patches): context.__exit__(None,None,None)
                self.assertTrue(docker.origin_running)
                self.assertFalse(docker.tunnel_running)
                self.assertEqual(len([x for x in docker.events if "stop" in x]),1)
                self.assertEqual([x for x in docker.events if "stop" in x][0][-1],m.op.TUNNEL)

    def test_manual_stop_does_not_require_public_health_or_stop_identity(self):
        docker=FakeDocker()
        docker.tunnel_running=True
        patches=self.env_gate()
        for context in patches: context.__enter__()
        try:
            m.stop_tunnel(runner=docker)
            self.assertFalse(docker.tunnel_running)
            self.assertTrue(docker.origin_running)
        finally:
            for context in reversed(patches): context.__exit__(None,None,None)

if __name__ == "__main__":
    unittest.main()
