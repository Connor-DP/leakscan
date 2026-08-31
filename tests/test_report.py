"""Tests for the JSON and HTML reports."""

from __future__ import annotations

import json
import os
import stat
import unittest
from pathlib import Path

from leakscan import adapters, detect, ingest, report, rules
from leakscan.audit import audit_html
from leakscan.records import Location, Record

from .support import REPO_ROOT, ProjectTempDir

CORPUS_ZIP = REPO_ROOT / "corpus" / "synthetic-transcripts.zip"
POSIX_ONLY = unittest.skipUnless(os.name == "posix", "POSIX permissions only")


def _scan():
    ruleset = rules.load_rules()
    walked = ingest.walk(CORPUS_ZIP)
    problems: list[str] = []
    records = []
    for source in walked.files:
        records.extend(adapters.parse_file(source, problems))
    return detect.Engine(ruleset).scan(records), walked, ruleset, problems


class ReportStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        result, walked, ruleset, problems = _scan()
        cls.document = report.build_report(result, walked, ruleset, problems=problems)

    def test_is_json_serialisable(self) -> None:
        json.dumps(self.document)

    def test_records_the_redaction_mode(self) -> None:
        """A reader must always know whether they hold a redacted document."""
        self.assertEqual(self.document["scan"]["redaction"], "redacted")

    def test_omits_raw_values_by_default(self) -> None:
        for finding in self.document["findings"]:
            self.assertNotIn("value", finding)
            self.assertIn("value_redacted", finding)

    def test_lists_every_employee_including_the_clean_one(self) -> None:
        names = {row["employee"] for row in self.document["employees"]}
        self.assertIn("sam.doyle", names)
        clean = next(r for r in self.document["employees"] if r["employee"] == "sam.doyle")
        self.assertTrue(clean["clean"])
        self.assertEqual(clean["findings"], 0)

    def test_reports_scan_quality_alongside_findings(self) -> None:
        for key in ("suppressed", "skipped_files", "parse_problems"):
            self.assertIn(key, self.document)

    def test_carries_the_caveat(self) -> None:
        self.assertIn("not proof", self.document["caveat"])

    def test_records_the_ruleset_used(self) -> None:
        self.assertEqual(self.document["tool"]["rules"], len(rules.load_rules().rules))


class RevealModeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        result, walked, ruleset, problems = _scan()
        cls.document = report.build_report(
            result, walked, ruleset, problems=problems, reveal=True
        )

    def test_includes_raw_values(self) -> None:
        self.assertTrue(all("value" in f for f in self.document["findings"]))

    def test_records_that_reveal_was_used(self) -> None:
        self.assertEqual(self.document["scan"]["redaction"], "revealed")

    def test_html_warns_the_reader(self) -> None:
        markup = report.render_html(self.document)
        self.assertIn("Unredacted report", markup)


class HtmlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        result, walked, ruleset, problems = _scan()
        cls.document = report.build_report(result, walked, ruleset, problems=problems)
        cls.markup = report.render_html(cls.document)

    def test_page_is_self_contained(self) -> None:
        """No fonts, no CDN, no images: opening the report must not call out."""
        self.assertEqual(audit_html(self.markup), [])

    def test_has_structure(self) -> None:
        self.assertIn("<!doctype html>", self.markup)
        self.assertIn("<title>Transcript leak report</title>", self.markup)
        self.assertIn("<style>", self.markup)

    def test_shows_the_clean_employee_rather_than_omitting_them(self) -> None:
        self.assertIn("sam.doyle", self.markup)
        self.assertIn("nothing found", self.markup)

    def test_escapes_untrusted_transcript_content(self) -> None:
        """A snippet is attacker-controlled text: it may contain markup."""
        hostile = Record(
            employee="x", session_id="s", source="claude-code", kind="tool_result",
            text="AWS_ACCESS_KEY_ID=AKIA4XZQ7MNPKD3RTBWV <script>alert(1)</script>",
            location=Location("x/s.jsonl", 0, 0),
        )
        result = detect.Engine(rules.load_rules()).scan([hostile])
        walked = ingest.Ingest(root="x")
        document = report.build_report(result, walked, rules.load_rules())
        markup = report.render_html(document)
        self.assertNotIn("<script>alert(1)</script>", markup)
        self.assertIn("&lt;script&gt;", markup)

    def test_empty_scan_still_renders(self) -> None:
        document = report.build_report(
            detect.ScanResult(), ingest.Ingest(root="empty"), rules.load_rules()
        )
        markup = report.render_html(document)
        self.assertIn("No findings.", markup)
        self.assertEqual(audit_html(markup), [])


class WriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)
        result, walked, ruleset, problems = _scan()
        self.document = report.build_report(result, walked, ruleset, problems=problems)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_writes_both_files(self) -> None:
        written = report.write_reports(self.document, self.root / "out")
        self.assertEqual([p.name for p in written], ["report.json", "report.html"])
        for path in written:
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 500)

    def test_json_round_trips(self) -> None:
        written = report.write_reports(self.document, self.root / "out")
        loaded = json.loads(written[0].read_text(encoding="utf-8"))
        self.assertEqual(loaded["totals"], self.document["totals"])

    @POSIX_ONLY
    def test_files_are_owner_only(self) -> None:
        """The report lists exactly which secrets exist and where."""
        for path in report.write_reports(self.document, self.root / "out"):
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600, f"{path.name} is {mode:04o}, expected 0600")

    @POSIX_ONLY
    def test_output_directory_is_owner_only(self) -> None:
        report.write_reports(self.document, self.root / "out")
        mode = stat.S_IMODE((self.root / "out").stat().st_mode)
        self.assertEqual(mode, 0o700)

    def test_rewriting_replaces_rather_than_appends(self) -> None:
        target = self.root / "out"
        report.write_reports(self.document, target)
        first = (target / "report.json").stat().st_size
        report.write_reports(self.document, target)
        self.assertEqual((target / "report.json").stat().st_size, first)


if __name__ == "__main__":
    unittest.main()
