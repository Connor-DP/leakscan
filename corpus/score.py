#!/usr/bin/env python3
"""Score the detection engine against the corpus ground truth.

Answers three questions, in order of how much they matter:

1. **Did the control stay clean?** Any finding on ``sam.doyle`` is a real false
   positive — that employee's transcript contains nothing but placeholders,
   documentation examples and reserved test data. This is pass/fail.
2. **What did we miss?** Planted findings with no match are recall gaps, listed
   individually so they can be fixed rather than averaged away.
3. **What did we find that wasn't labelled?** Reported as *unlabelled*, not as
   false positives — the corpus labels the items worth planting, not every true
   finding in it. An email address in a row of employee data is a real finding
   even though nobody planted it.

Usage::

    python3 corpus/score.py           # summary
    python3 corpus/score.py --detail  # list every miss and unlabelled finding
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from leakscan import adapters, detect, ingest, rules  # noqa: E402

CORPUS_ZIP = REPO_ROOT / "corpus" / "synthetic-transcripts.zip"
EXPECTED = REPO_ROOT / "corpus" / "expected.json"
CONTROL_EMPLOYEE = "sam.doyle"


def _split_ref(ref: str) -> tuple[str, int]:
    """``file#record.block`` -> ``(file, record_index)``."""
    path, _, tail = ref.partition("#")
    record = tail.split(".", 1)[0]
    return path, int(record) if record.isdigit() else -1


def _matches(expected: dict, finding: detect.Finding) -> bool:
    path, record_index = _split_ref(finding.location)
    if path != expected["file"] or record_index != expected["record_index"]:
        return False
    if finding.subtype == expected["subtype"]:
        return True
    # Several plants are described rather than quoted ("multi-row employee
    # export"), so fall back to overlap in either direction.
    wanted = expected["value"].lower()
    got = " ".join(finding.value.lower().split())
    return wanted in got or got in wanted


def run(detail: bool) -> int:
    ruleset = rules.load_rules()

    records = []
    problems: list[str] = []
    for source in ingest.walk(CORPUS_ZIP).files:
        records.extend(adapters.parse_file(source, problems))

    result = detect.Engine(ruleset).scan(records)
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    plants = expected["findings"]

    matched_plants = []
    missed_plants = []
    used: set[int] = set()
    for plant in plants:
        hit = next(
            (
                index
                for index, finding in enumerate(result.findings)
                if index not in used and _matches(plant, finding)
            ),
            None,
        )
        if hit is None:
            missed_plants.append(plant)
        else:
            used.add(hit)
            matched_plants.append(plant)

    unlabelled = [f for index, f in enumerate(result.findings) if index not in used]
    control = [f for f in result.findings if f.employee == CONTROL_EMPLOYEE]

    recall = len(matched_plants) / len(plants) * 100 if plants else 0.0

    print(f"Rules:      {len(ruleset.rules)} across {len(ruleset.packs)} packs")
    print(f"Records:    {result.records_scanned} ({result.characters_scanned:,} characters)")
    print(f"Findings:   {len(result.findings)}  (suppressed {result.suppressed_total})")
    print()
    print(f"Recall:     {len(matched_plants)}/{len(plants)} planted findings  ({recall:.0f}%)")
    print(f"Unlabelled: {len(unlabelled)} findings not in the ground truth")
    print()

    verdict = "PASS" if not control else "FAIL"
    print(f"Control ({CONTROL_EMPLOYEE}): {len(control)} findings — {verdict}")
    if control:
        for finding in control:
            print(f"    ! {finding.rule_id}  {finding.snippet[:90]}")
    print()

    by_category: dict[str, list[int]] = {}
    for plant in plants:
        by_category.setdefault(plant["category"], [0, 0])[1] += 1
    for plant in matched_plants:
        by_category[plant["category"]][0] += 1

    print("Recall by category:")
    width = max(len(name) for name in by_category)
    for name in sorted(by_category):
        hit, total = by_category[name]
        print(f"  {name.ljust(width)}  {hit:>2}/{total:<3} {hit / total * 100:>3.0f}%")

    if detail:
        if missed_plants:
            print(f"\nMissed ({len(missed_plants)}):")
            for plant in sorted(missed_plants, key=lambda p: (p["category"], p["subtype"])):
                print(f"  [{plant['severity']:<8}] {plant['category']}/{plant['subtype']}")
                print(f"            {plant['value'][:88]}")
                print(f"            {plant['file']}#{plant['record_index']}")
        if unlabelled:
            print(f"\nUnlabelled ({len(unlabelled)}):")
            for finding in unlabelled:
                print(f"  [{finding.severity:<8}] {finding.rule_id}")
                print(f"            {finding.snippet[:88]}")

    return 1 if control else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Score detection against the corpus")
    parser.add_argument("--detail", action="store_true", help="list misses and unlabelled findings")
    return run(parser.parse_args().detail)


if __name__ == "__main__":
    raise SystemExit(main())
