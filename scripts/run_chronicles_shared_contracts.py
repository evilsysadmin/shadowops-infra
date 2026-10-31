#!/usr/bin/env python3
"""Run the five shared Chronicles staging contract suites in one interpreter.

This runner is called independently by both API and Pages PR gates. Each gate
remains separately green/red; only redundant shell/Python startup and the
duplicate list of shared suites are removed.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]

SHARED_TESTS = (
    "test_chronicles_source_ci.py",
    "test_chronicles_production_admission.py",
    "test_chronicles_api_before_pages.py",
    "test_chronicles_staging_receipt.py",
    "test_chronicles_github_evidence_transport.py",
)


def load_shared_suites(loader: unittest.TestLoader | None = None) -> unittest.TestSuite:
    loader = loader or unittest.TestLoader()
    combined = unittest.TestSuite()
    for filename in SHARED_TESTS:
        suite = loader.discover(start_dir=str(ROOT / "tests"), pattern=filename)
        if not suite.countTestCases():
            raise RuntimeError(f"Missing shared staging contract suite: {filename}")
        combined.addTests(suite)
    return combined


def main() -> int:
    try:
        suite = load_shared_suites()
    except (ImportError, RuntimeError) as exc:
        print(f"CHRONICLES_SHARED_CONTRACTS_BLOCKED {exc}", file=sys.stderr)
        return 1
    outcome = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if outcome.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
