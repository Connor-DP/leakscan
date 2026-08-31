"""Tests for the findings store, triage and purge."""

from __future__ import annotations

import unittest
from pathlib import Path

from leakscan import adapters, detect, ingest, report, rules, store as store_module

from .support import REPO_ROOT, ProjectTempDir

CORPUS_ZIP = REPO_ROOT / "corpus" / "synthetic-transcripts.zip"


def _scan():
    ruleset = rules.load_rules()
    walked = ingest.walk(CORPUS_ZIP)
    problems: list[str] = []
    records = []
    for source in walked.files:
        records.extend(adapters.parse_file(source, problems))
    result = detect.Engine(ruleset).scan(records)
    document = report.build_report(result, walked, ruleset, problems=problems)
    return document, result


class FindingIdentityTests(unittest.TestCase):
    """Identity must survive re-scanning, or triage is worthless."""

    def test_same_leak_gets_the_same_id(self) -> None:
        first = store_module.finding_id("alice", "secret.aws.v1", "AKIA123")
        second = store_module.finding_id("alice", "secret.aws.v1", "AKIA123")
        self.assertEqual(first, second)

    def test_identity_ignores_location(self) -> None:
        """Re-exporting a transcript shifts record indices; identity must not move."""
        self.assertEqual(
            store_module.finding_id("alice", "r", "value"),
            store_module.finding_id("alice", "r", "value"),
        )

    def test_whitespace_is_normalised(self) -> None:
        self.assertEqual(
            store_module.finding_id("alice", "r", "a  b\nc"),
            store_module.finding_id("alice", "r", "a b c"),
        )

    def test_different_inputs_differ(self) -> None:
        base = store_module.finding_id("alice", "r", "v")
        self.assertNotEqual(base, store_module.finding_id("bob", "r", "v"))
        self.assertNotEqual(base, store_module.finding_id("alice", "r2", "v"))
        self.assertNotEqual(base, store_module.finding_id("alice", "r", "v2"))


class StoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document, cls.result = _scan()

    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)
        self.store = store_module.Store(self.root / "findings.sqlite3")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _record(self) -> int:
        return self.store.record_scan(self.document, self.result.findings)

    def test_records_a_scan_and_its_findings(self) -> None:
        scan_id = self._record()
        self.assertEqual(self.store.latest_scan_id(), scan_id)
        self.assertEqual(len(self.store.findings()), len(self.result.findings))

    def test_never_stores_a_raw_secret(self) -> None:
        """The database is an index of where secrets are, not a copy of them."""
        self._record()
        blob = self.store.path.read_bytes()
        raw_values = [
            f.value
            for f in self.result.findings
            if len(f.value) >= 20 and not f.descriptive
        ]
        self.assertTrue(raw_values)
        leaked = [v for v in raw_values if v.encode("utf-8") in blob]
        self.assertEqual(leaked, [], f"raw values written to the store: {leaked[:3]}")

    def test_findings_default_to_open(self) -> None:
        self._record()
        self.assertTrue(all(f["state"] == "open" for f in self.store.findings()))

    def test_triage_is_saved(self) -> None:
        self._record()
        target = self.store.findings()[0]["finding_id"]
        self.store.set_triage(target, "confirmed", "checked with the platform team")
        saved = next(f for f in self.store.findings() if f["finding_id"] == target)
        self.assertEqual(saved["state"], "confirmed")
        self.assertIn("platform team", saved["note"])

    def test_triage_survives_a_rescan(self) -> None:
        """The whole point of stable ids."""
        self._record()
        target = self.store.findings()[0]["finding_id"]
        self.store.set_triage(target, "false_positive")

        self._record()  # scan again, same transcripts
        again = next(f for f in self.store.findings() if f["finding_id"] == target)
        self.assertEqual(again["state"], "false_positive")

    def test_unknown_triage_state_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            self.store.set_triage("abc", "probably-fine")

    def test_trend_has_one_entry_per_scan(self) -> None:
        self._record()
        self._record()
        trend = self.store.trend()
        self.assertEqual(len(trend), 2)
        self.assertEqual(trend[0]["total"], len(self.result.findings))

    def test_findings_are_ordered_by_severity(self) -> None:
        self._record()
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        ranks = [order[f["severity"]] for f in self.store.findings()]
        self.assertEqual(ranks, sorted(ranks))

    def test_empty_store_is_not_an_error(self) -> None:
        self.assertIsNone(self.store.latest_scan_id())
        self.assertEqual(self.store.findings(), [])
        self.assertEqual(self.store.trend(), [])


class PurgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document, cls.result = _scan()

    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)
        self.store = store_module.Store(self.root / "findings.sqlite3")
        self.store.record_scan(self.document, self.result.findings)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_purge_all_empties_the_store(self) -> None:
        result = self.store.purge(everything=True)
        self.assertGreater(result.findings, 0)
        self.assertEqual(self.store.findings(), [])
        self.assertEqual(self.store.scans(), [])

    def test_purge_all_removes_report_files(self) -> None:
        for name in ("report.json", "report.html"):
            (self.root / name).write_text("x", encoding="utf-8")
        result = self.store.purge(everything=True, output_dir=self.root)
        self.assertEqual(len(result.files), 2)
        self.assertFalse((self.root / "report.json").exists())

    def test_purge_one_scan_keeps_the_others(self) -> None:
        second = self.store.record_scan(self.document, self.result.findings)
        self.store.purge(scan_id=second)
        self.assertEqual(len(self.store.scans()), 1)
        self.assertGreater(len(self.store.findings()), 0)

    def test_purge_one_employee(self) -> None:
        self.store.purge(employee="alice.chen")
        remaining = {f["employee"] for f in self.store.findings()}
        self.assertNotIn("alice.chen", remaining)
        self.assertIn("priya.nair", remaining)

    def test_purge_reclaims_space(self) -> None:
        """VACUUM matters: deleted rows otherwise stay readable in free pages."""
        before = self.store.path.stat().st_size
        self.store.purge(everything=True)
        self.assertLess(self.store.path.stat().st_size, before)

    def test_purged_content_is_gone_from_the_file(self) -> None:
        sample = self.store.findings()[0]["snippet"][:24]
        self.store.purge(everything=True)
        self.assertNotIn(sample.encode("utf-8"), self.store.path.read_bytes())

    def test_orphaned_triage_is_cleaned_up(self) -> None:
        target = self.store.findings()[0]["finding_id"]
        self.store.set_triage(target, "confirmed")
        result = self.store.purge(everything=True)
        self.assertEqual(result.triage, 1)

    def test_purge_needs_a_target(self) -> None:
        with self.assertRaises(ValueError):
            self.store.purge()


if __name__ == "__main__":
    unittest.main()
