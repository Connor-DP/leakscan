"""Tests for the structural detectors.

These are the rules that have to work for an organisation whose vocabulary we
have never seen — a law firm, a hospital, a haulier — so the tests deliberately
use content with no keyword any pack knows.
"""

from __future__ import annotations

import unittest

from leakscan import detect, rules, structure
from leakscan.records import Location, Record


def _record(text: str, kind: str = "tool_result") -> Record:
    return Record(
        employee="x", session_id="s", source="claude-code", kind=kind, text=text,
        location=Location("x/s.jsonl", 0, 0),
    )


def _subtypes(text: str, kind: str = "tool_result") -> set[str]:
    return {signal.subtype for signal in structure.detect(_record(text, kind))}


class TabularTests(unittest.TestCase):
    def test_detects_a_table_with_no_recognisable_words(self) -> None:
        """The whole point: shape, not vocabulary."""
        table = "\n".join(
            f"ROW-{n},alpha,beta,gamma,{n * 7}" for n in range(8)
        )
        self.assertIn("bulk_data_export", _subtypes(table))

    def test_ignores_prose_that_merely_contains_commas(self) -> None:
        prose = (
            "We met on Tuesday, went through the plan, and agreed to revisit.\n"
            "It was, on balance, a good meeting with useful, practical actions.\n"
            "Nobody objected, though one person, understandably, had questions.\n"
        )
        self.assertEqual(_subtypes(prose), set())

    def test_too_few_rows_is_not_a_table(self) -> None:
        self.assertEqual(_subtypes("a,b,c\n1,2,3\n4,5,6\n"), set())

    def test_counts_delimiters_outside_quotes(self) -> None:
        """A quoted address with commas must not break the row shape.

        Without this every personal-data CSV looks ragged and slips through,
        because addresses are exactly where the extra commas live.
        """
        table = (
            "ref,who,where,when\n"
            'A1,Someone,"12 Long Road, Anytown, ZZ1 1ZZ",2026-01-01\n'
            'A2,Another,"9 Short Lane, Elsewhere, YY2 2YY",2026-02-01\n'
            'A3,A Third,"4 Mid Street, Somewhere, XX3 3XX",2026-03-01\n'
        )
        self.assertIn("bulk_data_export", _subtypes(table))

    def test_pipe_delimited_query_output(self) -> None:
        table = (
            "id | code | status | updated\n"
            "---+------+--------+--------\n"
            " 1 | AAA  | open   | 2026-01-01\n"
            " 2 | BBB  | closed | 2026-01-02\n"
            " 3 | CCC  | open   | 2026-01-03\n"
        )
        self.assertIn("bulk_data_export", _subtypes(table))

    def test_severity_rises_with_volume(self) -> None:
        small = structure.detect(_record("\n".join("a,b,c,d" for _ in range(5))))
        large = structure.detect(_record("\n".join("a,b,c,d" for _ in range(30))))
        self.assertEqual(small[0].severity, "medium")
        self.assertEqual(large[0].severity, "high")


class PersonalExportTests(unittest.TestCase):
    def test_header_naming_personal_fields_beats_any_id_format(self) -> None:
        """Catches an export whose *values* no rule pack recognises.

        These are invented identifiers in no national format at all — the header
        row is the entire signal, which is why this works outside the UK.
        """
        table = (
            "full name,date of birth,email,home address,employee id\n"
            "A Person,1990-01-01,a@x.test,1 Road,EMP-001\n"
            "B Person,1991-02-02,b@x.test,2 Road,EMP-002\n"
            "C Person,1992-03-03,c@x.test,3 Road,EMP-003\n"
        )
        self.assertIn("personal_data_export", _subtypes(table))

    def test_needs_at_least_three_personal_fields(self) -> None:
        table = "\n".join("name,widget,qty,price" for _ in range(6))
        self.assertEqual(_subtypes(table), {"bulk_data_export"})

    def test_large_export_is_critical(self) -> None:
        rows = "\n".join(
            f"P{n},1990-01-01,p{n}@x.test,{n} Road,EMP-{n}" for n in range(12)
        )
        table = "full name,date of birth,email,home address,employee id\n" + rows
        signals = structure.detect(_record(table))
        self.assertEqual(signals[0].severity, "critical")

    def test_reports_which_fields_gave_it_away(self) -> None:
        table = (
            "full name,date of birth,email,notes\n"
            "A,1990-01-01,a@x.test,ok\nB,1991-01-01,b@x.test,ok\nC,1992-01-01,c@x.test,ok\n"
        )
        summary = structure.detect(_record(table))[0].summary
        self.assertIn("full name", summary)
        self.assertIn("rows", summary)


class DocumentPasteTests(unittest.TestCase):
    def _document(self, size: int = 4_000) -> str:
        body = (
            "TERMS OF ENGAGEMENT\n\n"
            "1. Scope\n   The supplier shall provide the services described.\n\n"
            "2. Charges\n   Payable within thirty days of invoice.\n\n"
            "3. Liability\n   Liability is capped at the fees paid.\n\n"
            "- first bullet point\n- second bullet point\n\n"
        )
        return body * (size // len(body) + 1)

    def test_detects_a_pasted_document(self) -> None:
        self.assertIn("document_paste", _subtypes(self._document(), "user_message"))

    def test_attachments_count_too(self) -> None:
        self.assertIn("document_paste", _subtypes(self._document(), "attachment"))

    def test_tool_output_is_not_a_pasted_document(self) -> None:
        """A long tool result is a log, and a chunked file would trip on every chunk."""
        self.assertNotIn("document_paste", _subtypes(self._document(), "tool_result"))

    def test_short_messages_are_ignored(self) -> None:
        self.assertEqual(_subtypes("1. one\n2. two\n\n- bullet\n", "user_message"), set())

    def test_unstructured_blob_is_ignored(self) -> None:
        self.assertEqual(_subtypes("word " * 2000, "user_message"), set())

    def test_severity_rises_with_length(self) -> None:
        short = structure.detect(_record(self._document(4_000), "user_message"))
        long = structure.detect(_record(self._document(12_000), "user_message"))
        self.assertEqual(short[0].severity, "medium")
        self.assertEqual(long[0].severity, "high")


class EngineIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = detect.Engine(rules.load_rules())

    def test_structural_findings_reach_the_engine(self) -> None:
        table = "\n".join(f"REF-{n},alpha,beta,{n}" for n in range(8))
        findings = self.engine.scan([_record(table)]).findings
        self.assertIn("bulk_data_export", {f.subtype for f in findings})

    def test_structural_summaries_are_readable_not_redacted(self) -> None:
        """The summary is prose we wrote, not lifted text — masking it is wrong."""
        table = "\n".join(f"REF-{n},alpha,beta,{n}" for n in range(8))
        finding = next(
            f for f in self.engine.scan([_record(table)]).findings if f.descriptive
        )
        self.assertIn("rows", finding.snippet)
        self.assertNotIn("*", finding.snippet)

    def test_control_content_stays_clean(self) -> None:
        """The fixture block from the control employee must still find nothing."""
        fixtures = (
            "const TEST_CARD = '4242 4242 4242 4242';\n"
            "const TEST_NI = 'QQ123456C';\n"
            "const TEST_HOST = '203.0.113.45';\n"
            "// Reserved documentation values — see RFC 5737 and RFC 2606.\n"
        )
        self.assertEqual(self.engine.scan([_record(fixtures)]).findings, [])


if __name__ == "__main__":
    unittest.main()
