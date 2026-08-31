"""Tests for filesystem locations and permission hardening."""

from __future__ import annotations

import os
import stat
import unittest
from pathlib import Path

from leakscan import APP_NAME, paths

from .support import ProjectTempDir

POSIX_ONLY = unittest.skipUnless(os.name == "posix", "POSIX permissions only")


class StateDirTests(unittest.TestCase):
    def test_state_dir_is_absolute_and_named(self) -> None:
        directory = paths.app_state_dir()
        self.assertTrue(directory.is_absolute())
        self.assertEqual(directory.name, APP_NAME)

    def test_default_output_dir_is_under_cwd(self) -> None:
        self.assertEqual(paths.default_output_dir(), Path.cwd() / "output")


class PrivateWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_writes_content(self) -> None:
        target = paths.write_private_text(self.root / "sub" / "report.json", "{}")
        self.assertEqual(target.read_text(encoding="utf-8"), "{}")

    def test_creates_missing_parents(self) -> None:
        paths.write_private_text(self.root / "a" / "b" / "c.txt", "x")
        self.assertTrue((self.root / "a" / "b").is_dir())

    def test_overwrites_existing_file(self) -> None:
        target = self.root / "report.json"
        paths.write_private_text(target, "first")
        paths.write_private_text(target, "second")
        self.assertEqual(target.read_text(encoding="utf-8"), "second")

    @POSIX_ONLY
    def test_file_is_owner_only(self) -> None:
        target = paths.write_private_text(self.root / "report.json", "{}")
        mode = stat.S_IMODE(target.stat().st_mode)
        self.assertEqual(mode, 0o600, f"expected 0600, got {mode:04o}")

    @POSIX_ONLY
    def test_directory_is_owner_only(self) -> None:
        directory = paths.ensure_private_dir(self.root / "out")
        mode = stat.S_IMODE(directory.stat().st_mode)
        self.assertEqual(mode, 0o700, f"expected 0700, got {mode:04o}")

    @POSIX_ONLY
    def test_harden_reports_enforcement(self) -> None:
        target = self.root / "f.txt"
        target.write_text("x", encoding="utf-8")
        self.assertTrue(paths.harden(target))

    def test_harden_never_raises_on_missing_path(self) -> None:
        self.assertFalse(paths.harden(self.root / "does-not-exist"))


if __name__ == "__main__":
    unittest.main()
