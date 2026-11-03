"""Offline checks that staging's Pages shell cannot accidentally expose gameplay."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import pawn_action_pages_shell as shell

class PagesShellTests(unittest.TestCase):
    def test_build_and_verify_only_holding_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "site"
            result = shell.build(root)
            self.assertTrue(result["locked"])
            self.assertEqual(result["gameFiles"], 0)
            self.assertEqual(shell.verify(root), result)
            self.assertEqual({p.name for p in root.iterdir()}, {"_worker.js", "index.html", "_headers"})
            self.assertNotIn(b"index.wasm", (root / "index.html").read_bytes())
            self.assertFalse((root / "release.json").exists())
    def test_cannot_overwrite_or_accept_extra_file_or_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "site"
            shell.build(root)
            with self.assertRaises(shell.ShellError):
                shell.build(root)
            (root / "index.wasm").write_bytes(b"secret")
            with self.assertRaises(shell.ShellError):
                shell.verify(root)
            (root / "index.wasm").unlink()
            (root / "_worker.js").write_bytes(b"export default {fetch:()=>new Response('open')}")
            with self.assertRaises(shell.ShellError):
                shell.verify(root)
    def test_missing_parent_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self.assertRaises(shell.ShellError):
                shell.build(base / "missing" / "site")
            destination = base / "target"
            destination.mkdir()
            link = base / "symlink"
            link.symlink_to(destination, target_is_directory=True)
            with self.assertRaises(shell.ShellError):
                shell.verify(link)
            with self.assertRaises(shell.ShellError):
                shell.build(link)
if __name__ == "__main__":
    unittest.main()
