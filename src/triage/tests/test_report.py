#!/usr/bin/env python3
"""Unit tests for report.py's duplicate-issue handling.

Bug confirmation runs against the same deterministic fake target solver
test_dedup.py uses (see fake_solver_lib.py for the directive format), so
these tests are hermetic. The GitHub-touching boundary (find_existing_issue,
post_issue, and the gh CLI presence/auth checks) is mocked out at the
report module level -- these tests are about report()'s open/closed
branching, not about `gh` itself.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import report  # noqa: E402

TESTS_DIR = Path(__file__).resolve().parent
FAKE_TARGET_SOLVER = TESTS_DIR / "fake_target_solver.py"
TARGET_CMD = str(FAKE_TARGET_SOLVER)


def write_crash_fixture(dir_path):
    path = Path(dir_path) / "crash-fixture.smt2"
    path.write_text(
        "(set-logic ALL)\n"
        "(declare-const x Int)\n"
        '(set-info :fake-target-verdict "crash:Segmentation fault")\n'
        "(assert (> x 0))\n"
        "(check-sat)\n"
    )
    return path


class ReportDuplicateHandlingTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.path = write_crash_fixture(self.tmpdir.name)

        # gh CLI presence/auth gate -- not what's under test here.
        patcher = patch.object(report, "shutil", MagicMock(which=lambda _: "/usr/bin/gh"))
        patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch.object(report, "subprocess", MagicMock())
        self.mock_subprocess = patcher.start()
        self.mock_subprocess.run.return_value = MagicMock(returncode=0)
        self.addCleanup(patcher.stop)

    def _report(self, existing):
        with patch.object(report, "find_existing_issue", return_value=existing) as mock_find, \
             patch.object(report, "post_issue") as mock_post:
            report.report(self.path, TARGET_CMD, None, post=True, out=None, repo="owner/repo")
        return mock_find, mock_post

    def test_no_existing_issue_files_normally(self):
        _, mock_post = self._report(existing=None)
        mock_post.assert_called_once()
        title, body, repo = mock_post.call_args[0]
        self.assertNotIn("regression", body.lower())
        self.assertEqual(repo, "owner/repo")

    def test_open_duplicate_is_skipped(self):
        existing = {"number": 42, "title": "whatever", "url": "https://github.com/owner/repo/issues/42", "state": "OPEN"}
        _, mock_post = self._report(existing=existing)
        mock_post.assert_not_called()

    def test_closed_duplicate_is_filed_as_regression(self):
        existing = {"number": 42, "title": "whatever", "url": "https://github.com/owner/repo/issues/42", "state": "CLOSED"}
        _, mock_post = self._report(existing=existing)
        mock_post.assert_called_once()
        _, body, _ = mock_post.call_args[0]
        self.assertIn("Possible regression of #42", body)
        self.assertIn("https://github.com/owner/repo/issues/42", body)


if __name__ == "__main__":
    unittest.main()
