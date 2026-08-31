"""Tests for walking a ZIP or directory of transcripts."""

from __future__ import annotations

import unittest
import zipfile
from pathlib import Path

from leakscan import ingest

from .support import REPO_ROOT, ProjectTempDir

CORPUS_ZIP = REPO_ROOT / "corpus" / "synthetic-transcripts.zip"


class CorpusZipTests(unittest.TestCase):
    """The synthetic corpus is the shape a real audit ZIP takes."""

    def setUp(self) -> None:
        self.result = ingest.walk(CORPUS_ZIP)

    def test_finds_every_transcript(self) -> None:
        # Five transcripts plus the spilled tool-result sidecar.
        self.assertEqual(len(self.result.files), 6)

    def test_nothing_is_skipped(self) -> None:
        self.assertEqual(self.result.skipped, [])

    def test_attributes_by_top_level_folder(self) -> None:
        self.assertEqual(
            self.result.employees,
            ["alice.chen", "ben.okafor", "priya.nair", "sam.doyle"],
        )

    def test_paths_are_forward_slashed_and_relative(self) -> None:
        for source in self.result.files:
            self.assertFalse(source.path.startswith("/"))
            self.assertNotIn("\\", source.path)

    def test_files_can_be_read_lazily(self) -> None:
        source = next(f for f in self.result.files if f.path.endswith(".jsonl"))
        with source.open_text() as stream:
            first = stream.readline()
        self.assertTrue(first.startswith("{"))


class DirectoryWalkTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self, relative: str, content: str = '{"type":"user"}\n') -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_walks_nested_employee_folders(self) -> None:
        self._write("alice/claude-code/a.jsonl")
        self._write("bob/claude-code/b.jsonl")
        result = ingest.walk(self.root)
        self.assertEqual(result.employees, ["alice", "bob"])
        self.assertEqual(len(result.files), 2)

    def test_root_level_file_is_unattributed(self) -> None:
        self._write("loose.jsonl")
        result = ingest.walk(self.root)
        self.assertEqual(result.files[0].employee, ingest.UNATTRIBUTED)

    def test_unsupported_type_is_skipped_with_a_reason(self) -> None:
        self._write("alice/diagram.png", "not really a png")
        result = ingest.walk(self.root)
        self.assertEqual(result.files, [])
        self.assertEqual(len(result.skipped), 1)
        self.assertIn("unsupported file type", result.skipped[0].reason)

    def test_empty_file_is_skipped_with_a_reason(self) -> None:
        self._write("alice/empty.jsonl", "")
        result = ingest.walk(self.root)
        self.assertEqual(result.files, [])
        self.assertIn("empty", result.skipped[0].reason)

    def test_os_clutter_is_ignored_quietly(self) -> None:
        self._write("alice/a.jsonl")
        self._write("alice/.DS_Store", "junk")
        self._write("__MACOSX/alice/._a.jsonl", "junk")
        result = ingest.walk(self.root)
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.skipped, [], "clutter should not appear as a skip")

    def test_missing_path_is_reported_not_raised(self) -> None:
        result = ingest.walk(self.root / "nope")
        self.assertEqual(result.files, [])
        self.assertIn("does not exist", result.skipped[0].reason)

    def test_single_transcript_file(self) -> None:
        path = self._write("one.jsonl")
        result = ingest.walk(path)
        self.assertEqual(len(result.files), 1)
        self.assertEqual(result.files[0].employee, ingest.UNATTRIBUTED)

    def test_crlf_and_bad_bytes_survive_reading(self) -> None:
        path = self.root / "alice" / "windows.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'{"a":1}\r\n{"b":2}\r\n\xff\xfe bad bytes\r\n')
        result = ingest.walk(self.root)
        with result.files[0].open_text() as stream:
            lines = stream.readlines()
        self.assertEqual(len(lines), 3)
        self.assertNotIn("\r", lines[0], "universal newlines should normalise CRLF")


class MalformedArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_corrupt_zip_is_reported_not_raised(self) -> None:
        path = self.root / "broken.zip"
        path.write_bytes(b"this is not a zip file")
        result = ingest.walk(path)
        self.assertEqual(result.files, [])
        self.assertIn("not a readable ZIP", result.skipped[0].reason)

    def test_path_traversal_entry_is_refused(self) -> None:
        path = self.root / "evil.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("../escaped.jsonl", '{"type":"user"}')
            archive.writestr("alice/fine.jsonl", '{"type":"user"}')
        result = ingest.walk(path)
        self.assertEqual([f.path for f in result.files], ["alice/fine.jsonl"])
        self.assertIn("unsafe path", result.skipped[0].reason)


if __name__ == "__main__":
    unittest.main()
