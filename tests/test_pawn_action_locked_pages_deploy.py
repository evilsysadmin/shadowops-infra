"""Offline contract for first deny-only Pawn Action Pages deployment (no cloud)."""
from __future__ import annotations
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_locked_pages_deploy as target
import pawn_action_pages_shell as shell

class Reader:
    account = "a" * 32
    def __init__(self, owned=True, deployed=False):
        self.owned, self.deployed, self.calls = owned, deployed, []
    def get(self, path, *, allow_missing=False):
        self.calls.append(path)
        if path.startswith("/zones?"):
            return 200, [{"name": "shadowops.dpdns.org", "id": "z" * 32}]
        if "/pages/projects/pawn-action-staging/deployments?" in path:
            return 200, [{"id": "synthetic-deployment"}] if self.deployed else []
        if path.endswith("/pages/projects/pawn-action-staging"):
            if not self.owned:
                return 404, None
            return 200, {
                "name": "pawn-action-staging", "production_branch": "main",
                "source": None, "subdomain": "pawn-action-staging.pages.dev",
                "domains": ["pawn-action-staging.pages.dev"],
                "latest_deployment": {"id": "synthetic"} if self.deployed else None,
                "canonical_deployment": None,
            }
        if "/pages/projects/" in path and "/domains/" in path:
            return 404, None
        if "/dns_records?" in path:
            return 200, []
        raise AssertionError("Unexpected Cloudflare read: " + path)

class TestLockedPagesDeployment(unittest.TestCase):
    def test_preflight_accepts_only_empty_project_and_exact_three_file_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"shell"
            shell.build(root)
            r=Reader()
            result=target.preflight(r,root)
            self.assertTrue(result["locked"])
            self.assertFalse(result["publishGame"])
            self.assertEqual(result["gameFiles"],0)
            self.assertIn("/deployments?per_page=1&page=1",r.calls[-1])
            (root/"index.wasm").write_bytes(b"fake")
            with self.assertRaises((target.LockedDeploymentError,shell.ShellError)):
                target.preflight(Reader(),root)

    def test_preflight_rejects_missing_project_or_any_preview(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"shell"; shell.build(root)
            for r in (Reader(owned=False),Reader(deployed=True)):
                with self.subTest(state=r.__dict__):
                    with self.assertRaises((target.LockedDeploymentError,ValueError)):
                        target.preflight(r,root)

    def test_alias_is_only_404_on_both_methods_for_all_protected_files(self):
        calls=[]
        def probe(host,path,method):
            calls.append((host,path,method))
        r=Reader(deployed=True)
        result=target.verify_alias(r,probe)
        self.assertEqual(result["checks"],2*len(target.PATHS))
        self.assertTrue(result["locked"])
        self.assertFalse(result["gameReady"])
        self.assertEqual(len(calls), 2 * len(target.PATHS))
        self.assertGreaterEqual(len(target.PATHS), 17)
        self.assertIn(("pawn-action-staging.pages.dev", "/index.audio.worklet.js", "GET"), calls)
        self.assertIn(("pawn-action-staging.pages.dev", "/_shadowops/session.js", "HEAD"), calls)
        self.assertIn(("pawn-action-staging.pages.dev","/index.wasm","GET"),calls)
        self.assertIn(("pawn-action-staging.pages.dev","/index.wasm","HEAD"),calls)

    def test_alias_never_proves_gameplay_ready_without_deployment(self):
        with self.assertRaises(target.LockedDeploymentError):
            target.verify_alias(Reader(),lambda *_:None)

    def test_no_arbitrary_external_requests_or_writes(self):
        for host, path, method in (("evil.pages.dev","/","GET"),
                                  ("pawn-action-staging.attacker.example","/","GET"),
                                  ("pawn-action-staging.pages.dev.evil.tld","/","GET"),
                                  ("pawn-action-staging.pages.dev","/index.html?token=x","GET"),
                                  ("pawn-action-staging.pages.dev","/","POST")):
            with self.subTest(host=host,path=path,method=method):
                with self.assertRaises(target.LockedDeploymentError):
                    target.probe_alias(host,path,method)
        source=Path(target.__file__).read_text()
        self.assertNotIn('method="POST"',source)
        self.assertNotIn('method="PUT"',source)
        self.assertNotIn('method="DELETE"',source)
        self.assertNotIn("chess-studio-assets",source)

    def test_live_alias_probe_accepts_only_uncached_worker_404(self):
        class Reply:
            def __init__(self, status=404, headers=None):
                self.status = status
                self.headers = headers if headers is not None else {
                    "Cache-Control": "no-store, max-age=0",
                    "X-Content-Type-Options": "nosniff",
                }
            def __enter__(self): return self
            def __exit__(self, *args): return False
        class Opener:
            def __init__(self, reply): self.reply = reply
            def open(self, request, *, timeout):
                self_request = request
                assert self_request.full_url == "https://pawn-action-staging.pages.dev/index.wasm"
                assert self_request.get_method() == "GET"
                assert timeout == 8
                return self.reply

        valid = Reply()
        with patch.object(target.urllib.request, "build_opener", return_value=Opener(valid)):
            target.probe_alias("pawn-action-staging.pages.dev", "/index.wasm", "GET")
        for bad in (Reply(status=200), Reply(status=302),
                    Reply(headers={"Cache-Control": "public", "X-Content-Type-Options": "nosniff"}),
                    Reply(headers={"Cache-Control": "no-store"}),
                    Reply(headers={"Cache-Control": "no-store",
                                   "X-Content-Type-Options": "nosniff",
                                   "Location": "https://assets.chess-studio.shadowops.dpdns.org/"})):
            with self.subTest(status=bad.status, headers=bad.headers):
                with patch.object(target.urllib.request, "build_opener",
                                  return_value=Opener(bad)):
                    with self.assertRaises(target.LockedDeploymentError):
                        target.probe_alias("pawn-action-staging.pages.dev", "/index.wasm", "GET")

    def test_workflow_rechecks_exact_empty_project_immediately_before_wrangler(self):
        workflow=(Path(__file__).resolve().parents[1] /
                  ".github/workflows/pawn-action-locked-pages-deploy.yml").read_text()
        deploy=workflow.split("      - name: Deploy the verified deny-all Worker; NO game or custom domain",1)[1]
        admission="CLOUDFLARE_API_TOKEN=\"$CLOUDFLARE_READ_TOKEN\" python3 scripts/pawn_action_locked_pages_deploy.py preflight"
        write="npx --yes wrangler@4.127.1 pages deploy"
        self.assertIn(admission, deploy)
        self.assertIn(write, deploy)
        self.assertLess(deploy.index(admission), deploy.index(write))
        self.assertIn("inputs.confirm == 'pawn-action-staging:locked'", workflow)
        self.assertIn("github.event_name == 'workflow_dispatch'", workflow)
        self.assertIn("secrets.PAWN_ACTION_PAGES_DEPLOY_TOKEN", workflow)

    def test_main_preflight_never_calls_cloud_without_exact_confirmation(self):
        with patch.object(target,"CloudflareReadClient") as reader:
            self.assertEqual(target.main(["preflight"],{}),1)
            reader.assert_not_called()

if __name__ == "__main__":
    unittest.main()
