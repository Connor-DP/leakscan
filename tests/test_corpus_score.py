"""Regression guard on detection quality, scored against the corpus ground truth.

This is the test that stops a rule change quietly making the product worse.
Adding a broad pattern to catch one more thing is easy; noticing that it also
started firing on the control employee is not, unless something checks.

Thresholds rather than exact numbers, so ordinary rule work does not fail the
build — but the control is absolute. Any finding there is a false positive.
"""

from __future__ import annotations

import importlib.util
import unittest

from .support import REPO_ROOT

SCORE_PATH = REPO_ROOT / "corpus" / "score.py"


def _load_scorer():
    spec = importlib.util.spec_from_file_location("corpus_score", SCORE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CorpusScoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        scorer = _load_scorer()
        import json

        from leakscan import adapters, detect, ingest, rules

        records = []
        problems: list[str] = []
        for source in ingest.walk(scorer.CORPUS_ZIP).files:
            records.extend(adapters.parse_file(source, problems))

        cls.scorer = scorer
        cls.result = detect.Engine(rules.load_rules()).scan(records)
        cls.plants = json.loads(scorer.EXPECTED.read_text(encoding="utf-8"))["findings"]

        cls.matched = []
        cls.missed = []
        used: set[int] = set()
        for plant in cls.plants:
            hit = next(
                (
                    index
                    for index, finding in enumerate(cls.result.findings)
                    if index not in used and scorer._matches(plant, finding)
                ),
                None,
            )
            if hit is None:
                cls.missed.append(plant)
            else:
                used.add(hit)
                cls.matched.append(plant)

    def test_control_employee_has_zero_findings(self) -> None:
        """Absolute. Not a threshold."""
        noise = [
            f for f in self.result.findings if f.employee == self.scorer.CONTROL_EMPLOYEE
        ]
        self.assertEqual(
            noise,
            [],
            "false positives on the control employee: "
            + ", ".join(f"{f.rule_id} ({f.snippet[:50]})" for f in noise),
        )

    def test_recall_stays_high(self) -> None:
        recall = len(self.matched) / len(self.plants)
        self.assertGreaterEqual(
            recall,
            0.90,
            f"recall dropped to {recall:.0%}; missed: "
            + ", ".join(f"{p['category']}/{p['subtype']}" for p in self.missed),
        )

    def test_every_category_is_detected(self) -> None:
        """A whole family going dark is the failure a single recall number hides."""
        expected = {plant["category"] for plant in self.plants}
        detected = {plant["category"] for plant in self.matched}
        self.assertEqual(expected, detected)

    def test_every_critical_plant_is_found(self) -> None:
        missed_critical = [p for p in self.missed if p["severity"] == "critical"]
        self.assertEqual(
            missed_critical,
            [],
            "missed critical findings: "
            + ", ".join(p["subtype"] for p in missed_critical),
        )

    def test_ground_truth_matches_the_corpus(self) -> None:
        """expected.json and the ZIP are generated together; drift means one was hand-edited."""
        files = {plant["file"] for plant in self.plants}
        from leakscan import ingest

        actual = {source.path for source in ingest.walk(self.scorer.CORPUS_ZIP).files}
        self.assertTrue(files <= actual, f"ground truth names files not in the ZIP: {files - actual}")


if __name__ == "__main__":
    unittest.main()
