"""Tests for sidecar text files and base64 payloads embedded in transcripts."""

from __future__ import annotations

import base64
import unittest
from pathlib import Path

from leakscan import adapters, detect, embedded, ingest, rules
from leakscan.adapters import plain_text
from leakscan.records import Location, Record

from .support import REPO_ROOT, ProjectTempDir

CORPUS_ZIP = REPO_ROOT / "corpus" / "synthetic-transcripts.zip"


def _record(text: str, kind: str = "tool_result") -> Record:
    return Record(
        employee="x", session_id="s", source="claude-code", kind=kind, text=text,
        location=Location("x/s.jsonl", 3, 0),
    )


class SidecarFileTests(unittest.TestCase):
    """Claude Code spills its biggest tool outputs to files, not into the .jsonl."""

    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _parse(self, relative: str, content: str) -> list[Record]:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        problems: list[str] = []
        found: list[Record] = []
        for source in ingest.walk(self.root).files:
            found.extend(adapters.parse_file(source, problems))
        return found

    def test_text_files_are_no_longer_skipped(self) -> None:
        records = self._parse("alice/notes.txt", "AWS_ACCESS_KEY_ID=AKIA4XZQ7MNPKD3RTBWV")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].source, "plain-text")

    def test_spilled_tool_output_is_credited_as_a_tool_result(self) -> None:
        records = self._parse(
            "alice/claude-code/sess-1/tool-results/psql-out.txt", "some output"
        )
        self.assertEqual(records[0].kind, "tool_result")
        self.assertEqual(records[0].session_id, "sess-1", "session comes from the folder")

    def test_memory_and_instruction_files_are_system_prompts(self) -> None:
        self.assertEqual(self._parse("alice/CLAUDE.md", "internal notes")[0].kind, "system_prompt")
        self.assertEqual(self._parse("bob/memory/project.md", "notes")[0].kind, "system_prompt")

    def test_other_text_is_an_attachment(self) -> None:
        self.assertEqual(self._parse("alice/report.txt", "text")[0].kind, "attachment")

    def test_large_files_are_chunked_with_overlap(self) -> None:
        body = "x" * (plain_text.CHUNK_SIZE * 2)
        records = self._parse("alice/big.log", body)
        self.assertGreater(len(records), 1)
        self.assertTrue(all(len(r.text) <= plain_text.CHUNK_SIZE for r in records))

    def test_a_value_straddling_a_chunk_boundary_is_still_found(self) -> None:
        filler = "x" * (plain_text.CHUNK_SIZE - 20)
        body = filler + "AWS_ACCESS_KEY_ID=AKIA4XZQ7MNPKD3RTBWV" + "\n" + "y" * 100
        records = self._parse("alice/big.log", body)
        result = detect.Engine(rules.load_rules()).scan(records)
        self.assertIn("aws_access_key_id", {f.subtype for f in result.findings})

    def test_plain_text_never_steals_a_json_transcript(self) -> None:
        self.assertFalse(plain_text.matches("conversations.json", "[]"))
        self.assertFalse(plain_text.matches("session.jsonl", "{}"))
        self.assertTrue(plain_text.matches("output.txt", "anything"))


class EmbeddedPayloadTests(unittest.TestCase):
    """A base64'd credential matches no pattern until something decodes it."""

    def _expand(self, text: str) -> tuple[list[Record], list[str]]:
        problems: list[str] = []
        return list(embedded.expand(_record(text), problems)), problems

    def test_decodes_an_encoded_secret(self) -> None:
        blob = base64.b64encode(
            b"AWS_SECRET_ACCESS_KEY=hR7pQ2mZx9TfKd4LbN8vYcJ3sWe6UaGi5oPqRt1X\n"
        ).decode()
        records, _ = self._expand(f"restored: {blob}")
        self.assertEqual(len(records), 1)
        self.assertIn("AWS_SECRET_ACCESS_KEY", records[0].text)

    def test_decoded_content_is_scanned_by_the_engine(self) -> None:
        blob = base64.b64encode(
            b"AWS_ACCESS_KEY_ID=AKIA4XZQ7MNPKD3RTBWV\n"
            b"DEPLOY=production\nOWNER=platform-team\nREGION=eu-west-2\n"
        ).decode()
        records = [_record(f"blob: {blob}")]
        records.extend(embedded.expand(records[0], []))
        result = detect.Engine(rules.load_rules()).scan(records)
        self.assertIn("aws_access_key_id", {f.subtype for f in result.findings})

    def test_expansion_keeps_provenance(self) -> None:
        blob = base64.b64encode(
            b"TOKEN=abcdefghijklmnopqrstuvwxyz012345\nOWNER=platform\nENV=prod\n"
        ).decode()
        records, _ = self._expand(f"x {blob}")
        self.assertEqual(records[0].kind, "tool_result")
        self.assertEqual(records[0].location.record_index, 3, "same record as its parent")
        self.assertGreaterEqual(records[0].location.block_index, 800)

    def test_binary_payloads_are_reported_not_silently_skipped(self) -> None:
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200).decode()
        records, problems = self._expand(f"image: {png}")
        self.assertEqual(records, [])
        self.assertIn("PNG image", problems[0])
        self.assertIn("not scanned", problems[0])

    def test_zip_payloads_are_reported(self) -> None:
        archive = base64.b64encode(b"PK\x03\x04" + b"\x00" * 200).decode()
        _, problems = self._expand(f"file: {archive}")
        self.assertIn("ZIP archive", problems[0])

    def test_random_text_is_not_decoded_as_base64(self) -> None:
        records, _ = self._expand("here is a long sentence of ordinary prose " * 4)
        self.assertEqual(records, [])

    def test_jwt_segments_are_left_to_the_jwt_rules(self) -> None:
        payload = base64.b64encode(b'{"role":"service_role","iss":"supabase"}' * 3).decode().rstrip("=")
        records, _ = self._expand(f"eyJhbGciOiJIUzI1NiJ9.{payload}.signature")
        self.assertEqual(records, [])

    def test_oversized_payloads_are_refused(self) -> None:
        original = embedded.MAX_DECODED_BYTES
        embedded.MAX_DECODED_BYTES = 64
        try:
            records, problems = self._expand("x " + "A" * 4_000)
        finally:
            embedded.MAX_DECODED_BYTES = original
        self.assertEqual(records, [])
        self.assertIn("was not decoded", problems[0])

    def test_per_record_cap(self) -> None:
        records, problems = self._expand(" ".join(
            base64.b64encode(
                f"KEY{i}=abcdefghijklmnopqrstuvwxyz0123456789\n"
                f"OWNER=platform-team\nENV=production\n".encode()
            ).decode()
            for i in range(embedded.MAX_PER_RECORD + 5)
        ))
        self.assertEqual(len(records), embedded.MAX_PER_RECORD)
        self.assertIn("the rest were not decoded", problems[-1])


class CorpusCoverageTests(unittest.TestCase):
    """Both features, exercised through the real corpus."""

    @classmethod
    def setUpClass(cls) -> None:
        problems: list[str] = []
        records = []
        for source in ingest.walk(CORPUS_ZIP).files:
            records.extend(adapters.parse_file(source, problems))
        cls.result = detect.Engine(rules.load_rules()).scan(records)
        cls.problems = problems

    def test_sidecar_file_is_scanned(self) -> None:
        from_sidecar = [
            f for f in self.result.findings if "tool-results/" in f.location
        ]
        self.assertTrue(from_sidecar, "the spilled tool result was not scanned")
        self.assertIn(
            "database_connection_string", {f.subtype for f in from_sidecar}
        )

    def test_encoded_secret_is_found(self) -> None:
        encoded = [
            f
            for f in self.result.findings
            if f.location.split(".")[-1].isdigit() and int(f.location.split(".")[-1]) >= 800
        ]
        self.assertTrue(encoded, "the base64 payload was not decoded and scanned")
        self.assertIn("env_assignment", {f.subtype for f in encoded})

    def test_no_new_parse_problems(self) -> None:
        self.assertEqual(self.problems, [])


if __name__ == "__main__":
    unittest.main()
