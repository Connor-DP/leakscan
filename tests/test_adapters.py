"""Tests for the transcript format adapters."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from leakscan import adapters, ingest
from leakscan.adapters import claude_code, claude_desktop

from .support import REPO_ROOT, ProjectTempDir

CORPUS_ZIP = REPO_ROOT / "corpus" / "synthetic-transcripts.zip"


def _records(root: Path) -> tuple[list, list[str]]:
    problems: list[str] = []
    found = []
    for source in ingest.walk(root).files:
        found.extend(adapters.parse_file(source, problems))
    return found, problems


class SniffingTests(unittest.TestCase):
    def test_recognises_claude_code(self) -> None:
        head = '{"type":"user","message":{"role":"user","content":[]}}\n'
        self.assertTrue(claude_code.matches("session.jsonl", head))
        self.assertFalse(claude_desktop.matches("session.jsonl", head))

    def test_recognises_claude_desktop(self) -> None:
        head = '[{"uuid":"x","name":"t","chat_messages":[]}]'
        self.assertTrue(claude_desktop.matches("conversations.json", head))
        self.assertFalse(claude_code.matches("conversations.json", head))

    def test_rejects_unrelated_json(self) -> None:
        self.assertFalse(claude_code.matches("package.json", '{"name":"x"}'))
        self.assertFalse(claude_desktop.matches("data.json", '[{"a":1}]'))

    def test_extension_alone_is_not_enough(self) -> None:
        self.assertFalse(claude_code.matches("notes.jsonl", "not json at all"))


class CorpusParseTests(unittest.TestCase):
    """Parse the synthetic corpus and check what came out."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.records, cls.problems = _records(CORPUS_ZIP)

    def test_parses_without_problems(self) -> None:
        self.assertEqual(self.problems, [])

    def test_record_count(self) -> None:
        self.assertEqual(len(self.records), 39)

    def test_both_formats_are_represented(self) -> None:
        sources = {record.source for record in self.records}
        self.assertEqual(sources, {"claude-code", "claude-desktop", "plain-text"})

    def test_tool_results_are_not_mislabelled_as_user_messages(self) -> None:
        """The format detail that matters most.

        A tool result arrives as a *user-role* message. Treating role as the
        source of truth would file the richest leak location under "things the
        employee typed" and understate every finding in it.
        """
        env_dump = [
            record
            for record in self.records
            if "AWS_SECRET_ACCESS_KEY" in record.text
        ]
        self.assertEqual(len(env_dump), 1)
        self.assertEqual(env_dump[0].kind, "tool_result")

    def test_tool_calls_are_captured(self) -> None:
        calls = [record for record in self.records if record.kind == "tool_call"]
        self.assertEqual(len(calls), 6)
        self.assertTrue(any("cat .env.production" in record.text for record in calls))

    def test_system_prompt_is_captured(self) -> None:
        system = [record for record in self.records if record.kind == "system_prompt"]
        self.assertEqual(len(system), 1)
        self.assertIn("Project Kestrel", system[0].text)

    def test_desktop_export_carries_conversation_titles(self) -> None:
        desktop = [r for r in self.records if r.source == "claude-desktop"]
        self.assertEqual(len(desktop), 9)
        self.assertIn(
            "Tidy up the quarterly management report",
            {record.title for record in desktop},
        )

    def test_employee_attribution_survives_parsing(self) -> None:
        by_employee: dict[str, int] = {}
        for record in self.records:
            by_employee[record.employee] = by_employee.get(record.employee, 0) + 1
        self.assertEqual(
            by_employee,
            {"alice.chen": 16, "ben.okafor": 9, "priya.nair": 9, "sam.doyle": 5},
        )

    def test_locations_are_stable_and_unique(self) -> None:
        refs = [record.location.ref for record in self.records]
        self.assertEqual(len(refs), len(set(refs)), "location refs must be unique")
        again, _ = _records(CORPUS_ZIP)
        self.assertEqual(refs, [record.location.ref for record in again])


class ClaudeCodeEdgeCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _parse(self, lines: list[str]) -> tuple[list, list[str]]:
        path = self.root / "alice" / "session.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return _records(self.root)

    def test_malformed_line_is_reported_and_others_still_parse(self) -> None:
        good = json.dumps(
            {"type": "user", "message": {"role": "user", "content": [
                {"type": "text", "text": "hello"}]}}
        )
        records, problems = self._parse([good, "{not json", good])
        self.assertEqual(len(records), 2, "one bad line must not lose the file")
        self.assertEqual(len(problems), 1)
        self.assertIn("malformed JSON line", problems[0])

    def test_unknown_block_type_is_surfaced_not_silently_dropped(self) -> None:
        line = json.dumps(
            {"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "video", "url": "x"}]}}
        )
        records, problems = self._parse([line])
        self.assertEqual(records, [])
        self.assertIn("unrecognised block type", problems[0])

    def test_image_blocks_are_noted_as_unscanned(self) -> None:
        line = json.dumps(
            {"type": "user", "message": {"role": "user", "content": [
                {"type": "image", "source": {}}]}}
        )
        _, problems = self._parse([line])
        self.assertIn("no OCR", problems[0])

    def test_nested_tool_input_is_flattened_not_dropped(self) -> None:
        line = json.dumps(
            {"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "t1", "name": "Write",
                 "input": {"file_path": "/tmp/x", "nested": {"token": "sk-secret-value"}}}]}}
        )
        records, _ = self._parse([line])
        self.assertEqual(len(records), 1)
        self.assertIn("sk-secret-value", records[0].text)

    def test_tool_use_result_sibling_field_is_scanned(self) -> None:
        line = json.dumps(
            {"type": "user", "toolUseResult": {"stdout": "PASSWORD=hunter2"},
             "message": {"role": "user", "content": []}}
        )
        records, _ = self._parse([line])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].kind, "tool_result")
        self.assertIn("hunter2", records[0].text)

    def test_compaction_summary_is_scanned(self) -> None:
        line = json.dumps({"type": "summary", "summary": "We used key sk-ant-xyz"})
        records, _ = self._parse([line])
        self.assertEqual(len(records), 1)
        self.assertIn("sk-ant-xyz", records[0].text)

    def test_blank_text_is_not_emitted(self) -> None:
        line = json.dumps(
            {"type": "user", "message": {"role": "user", "content": [
                {"type": "text", "text": "   "}]}}
        )
        records, problems = self._parse([line])
        self.assertEqual(records, [])
        self.assertEqual(problems, [])


class ClaudeDesktopEdgeCaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _parse(self, payload) -> tuple[list, list[str]]:
        path = self.root / "ben" / "conversations.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return _records(self.root)

    def test_attachments_are_captured_as_their_own_records(self) -> None:
        records, _ = self._parse([{
            "uuid": "c1", "name": "Board pack",
            "chat_messages": [{
                "uuid": "m1", "sender": "human", "text": "Review this",
                "attachments": [{
                    "file_name": "q3-figures.csv",
                    "extracted_content": "client,value\nHalyard,180000",
                }],
            }],
        }])
        kinds = [record.kind for record in records]
        self.assertIn("attachment", kinds)
        attachment = next(r for r in records if r.kind == "attachment")
        self.assertIn("q3-figures.csv", attachment.text)
        self.assertIn("Halyard,180000", attachment.text)

    def test_content_blocks_preferred_over_flat_text(self) -> None:
        records, _ = self._parse([{
            "uuid": "c1", "name": "t",
            "chat_messages": [{
                "sender": "assistant",
                "text": "stale copy",
                "content": [{"type": "text", "text": "current text"}],
            }],
        }])
        self.assertEqual(records[0].text, "current text")

    def test_non_array_payload_is_reported(self) -> None:
        records, problems = self._parse({"conversations": []})
        self.assertEqual(records, [])
        self.assertIn("expected an array", problems[0])

    def test_conversation_without_messages_is_reported(self) -> None:
        records, problems = self._parse([{"uuid": "c1", "name": "t"}])
        self.assertEqual(records, [])
        self.assertIn("no chat_messages", problems[0])


if __name__ == "__main__":
    unittest.main()
