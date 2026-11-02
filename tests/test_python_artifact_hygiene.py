"""Keep generated Python interpreter bytecode out of the Git repository."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PythonArtifactHygiene(unittest.TestCase):
    def test_no_tracked_python_bytecode(self):
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True)
        paths = [p.decode("utf-8") for p in result.stdout.split(b"\0") if p]
        generated = [p for p in paths if (
            "/__pycache__/" in "/" + p or p.endswith((".pyc", ".pyo")))]
        self.assertEqual(generated, [], "Generated Python bytecode must not be versioned")

    def test_bytecode_is_ignored_even_in_nested_directories(self):
        for name in (
            "scripts/__pycache__/oci_chronicles_api_release.cpython-313.pyc",
            "host/__pycache__/chronicles-api-deploy.cpython-313.pyc",
            "tests/__pycache__/test_oci_control_plane.cpython-313.pyc",
            "nested/other/sample.pyc",
            "nested/other/sample.pyo",
        ):
            with self.subTest(name=name):
                result = subprocess.run(
                    ["git", "check-ignore", "--no-index", "-q", name],
                    cwd=ROOT, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, "Not ignored: " + name)


if __name__ == "__main__":
    unittest.main()
