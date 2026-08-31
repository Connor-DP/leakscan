"""The detection engine: records in, findings out.

Order of work per match, and why:

1. **Match** a rule's pattern against a record's text.
2. **Validate** — Luhn for card numbers, a Shannon-entropy floor for catch-all
   secret rules. Cheap arithmetic that removes whole classes of false positive.
3. **Require context** where the pattern alone is too loose. A bare 40-character
   string is not a secret; one sitting next to ``AWS_SECRET_ACCESS_KEY`` is.
4. **Suppress** — placeholders, provider documentation examples, reserved test
   data. Counted, never silent, so a tuned-out category stays visible.
5. **Aggregate** — the same secret found forty times is one finding with a count,
   not forty rows a reader has to scroll past.

Everything is redacted on the way out. The engine never returns a raw value
unless explicitly asked, because the report is otherwise a second copy of the leak.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace

from . import structure
from .records import Record
from .rules import Rule, RuleSet, Suppressor

__all__ = ["Finding", "ScanResult", "Engine", "entropy", "luhn_valid", "redact"]

#: A record yielding at least this many distinct personal-data subtypes is a
#: bulk export, not an incidental mention — a materially different problem.
BULK_PII_THRESHOLD = 6

_WHITESPACE = re.compile(r"\s+")


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def luhn_valid(value: str) -> bool:
    """True if *value*'s digits satisfy the Luhn checksum."""
    digits = [int(char) for char in value if char.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def redact(value: str) -> str:
    """Mask a value, keeping just enough to recognise it."""
    compact = _WHITESPACE.sub(" ", value).strip()
    if len(compact) <= 6:
        return "*" * len(compact)
    keep = 4 if len(compact) > 16 else 2
    return f"{compact[:keep]}{'*' * 6}{compact[-2:]}"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    category: str
    subtype: str
    severity: str
    confidence: int
    employee: str
    session_id: str
    source: str
    kind: str
    location: str
    start: int
    end: int
    value: str  # raw; only written out under --reveal
    snippet: str  # redacted, safe to print
    occurrences: int = 1
    also_at: tuple[str, ...] = ()
    #: True when ``value`` is a description we wrote ("7 rows of tabular
    #: data"), not text lifted from the transcript. Descriptions must not
    #: be redacted, and must never be treated as secrets to mask elsewhere.
    descriptive: bool = False

    @property
    def redacted(self) -> str:
        return redact(self.value)


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    records_scanned: int = 0
    characters_scanned: int = 0
    #: suppressor id -> how many matches it removed. Belongs in the report.
    suppressed: dict[str, int] = field(default_factory=dict)

    @property
    def suppressed_total(self) -> int:
        return sum(self.suppressed.values())

    def by_employee(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.employee] = counts.get(finding.employee, 0) + 1
        return counts

    def by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return counts

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts


_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Engine:
    """Applies a :class:`~leakscan.rules.RuleSet` to records."""

    def __init__(self, ruleset: RuleSet) -> None:
        self.ruleset = ruleset

    # -- individual checks -------------------------------------------------

    def _suppressor_for(
        self, category: str, value: str, window: str
    ) -> Suppressor | None:
        for suppressor in self.ruleset.suppressors:
            if not suppressor.covers(category):
                continue
            subject = value if suppressor.scope == "value" else window
            if suppressor.pattern.search(subject):
                return suppressor
        return None

    @staticmethod
    def _has_context(rule: Rule, text: str, start: int, end: int) -> bool:
        if not rule.requires_context:
            return True
        window = text[
            max(0, start - rule.context_window) : end + rule.context_window
        ].lower()
        return any(term.lower() in window for term in rule.requires_context)

    @staticmethod
    def _merge_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    @staticmethod
    def _snippet(text: str, spans: list[tuple[int, int]], start: int, end: int) -> str:
        """Render the window around a match with *every* detected value masked.

        Masking is done by character offset, not by replacing known strings.
        The window routinely cuts through a neighbouring secret — an ``.env``
        dump is wall-to-wall credentials — and a string-replacement pass leaves
        that fragment in clear because a partial value matches nothing. Half an
        API key in a report a customer forwards is still half an API key.
        """
        left = max(0, start - 50)
        right = min(len(text), end + 50)

        pieces: list[str] = []
        cursor = left
        for span_start, span_end in spans:
            if span_end <= left or span_start >= right:
                continue
            visible_start = max(span_start, left)
            if visible_start > cursor:
                pieces.append(text[cursor:visible_start])
            if span_start >= left and span_end <= right:
                pieces.append(redact(text[span_start:span_end]))
            else:
                # Clipped by the window: show none of it, since even the shape
                # of a partial key is more than the reader needs.
                pieces.append("***")
            cursor = max(cursor, min(span_end, right))
        if cursor < right:
            pieces.append(text[cursor:right])

        fragment = _WHITESPACE.sub(" ", "".join(pieces)).strip()
        prefix = "…" if left > 0 else ""
        suffix = "…" if right < len(text) else ""
        return f"{prefix}{fragment}{suffix}"

    # -- scanning ----------------------------------------------------------

    def scan_record(self, record: Record, result: ScanResult) -> list[Finding]:
        text = record.text
        # Two passes. Every match in the record is collected first, so that the
        # snippets built in the second pass can mask *all* of them — including
        # the neighbouring secret that the window happens to cut through.
        hits: list[tuple[Rule, int, int, str]] = []

        for rule in self.ruleset.rules:
            if not rule.applies_to(record.kind):
                continue

            for match in rule.pattern.finditer(text):
                try:
                    value = match.group(rule.group)
                except IndexError:  # a rule naming a group its pattern lacks
                    continue
                if not value or not value.strip():
                    continue

                if any(pattern.search(value) for pattern in rule.ignore):
                    key = f"{rule.id}:ignore"
                    result.suppressed[key] = result.suppressed.get(key, 0) + 1
                    continue

                if rule.validate == "luhn" and not luhn_valid(value):
                    continue
                if rule.min_entropy and entropy(value) < rule.min_entropy:
                    continue
                if not self._has_context(rule, text, match.start(), match.end()):
                    continue

                window = text[max(0, match.start() - 200) : match.end() + 200]
                suppressor = self._suppressor_for(rule.category, value, window)
                if suppressor is not None:
                    result.suppressed[suppressor.id] = (
                        result.suppressed.get(suppressor.id, 0) + 1
                    )
                    continue

                start, end = match.span(rule.group)
                hits.append((rule, start, end, value))

        spans = self._merge_spans([(start, end) for _, start, end, _ in hits])
        found = [
            Finding(
                rule_id=rule.id,
                category=rule.category,
                subtype=rule.subtype,
                severity=rule.severity,
                confidence=rule.confidence,
                employee=record.employee,
                session_id=record.session_id,
                source=record.source,
                kind=record.kind,
                location=record.location.ref,
                start=start,
                end=end,
                value=value,
                snippet=self._snippet(text, spans, start, end),
            )
            for rule, start, end, value in hits
        ]

        found.extend(self._bulk_finding(record, found))
        found.extend(self._structural_findings(record))
        return found

    @staticmethod
    def _structural_findings(record: Record) -> list[Finding]:
        """Findings from the shape of the content, independent of vocabulary.

        These are what let the scanner say something useful about an
        organisation whose words no rule pack knows — a table of people is a
        table of people whether the columns hold NI numbers or Social Security
        numbers or neither.
        """
        return [
            Finding(
                rule_id=signal.rule_id,
                category=signal.category,
                subtype=signal.subtype,
                severity=signal.severity,
                confidence=signal.confidence,
                employee=record.employee,
                session_id=record.session_id,
                source=record.source,
                kind=record.kind,
                location=record.location.ref,
                start=0,
                end=len(record.text),
                value=signal.summary,
                snippet=signal.summary,
                descriptive=True,
            )
            for signal in structure.detect(record)
        ]

    @staticmethod
    def _bulk_finding(record: Record, found: list[Finding]) -> list[Finding]:
        """Flag a record that is a personal-data export rather than a mention.

        Volume changes what a finding means. One employee's address is a Medium;
        two hundred rows of them is a different conversation entirely, and a
        reader should not have to infer that from a long list.
        """
        subtypes = {f.subtype for f in found if f.category in ("pii", "special-category")}
        if len(subtypes) < BULK_PII_THRESHOLD:
            return []
        return [
            Finding(
                rule_id="pii.bulk_personal_records.v1",
                category="pii",
                subtype="bulk_personal_records",
                severity="critical",
                confidence=90,
                employee=record.employee,
                session_id=record.session_id,
                source=record.source,
                kind=record.kind,
                location=record.location.ref,
                start=0,
                end=len(record.text),
                value=f"{len(subtypes)} kinds of personal data in one record",
                snippet=(
                    f"Bulk personal data: {len(subtypes)} distinct kinds "
                    f"({', '.join(sorted(subtypes))}) in a single "
                    f"{record.kind.replace('_', ' ')}."
                ),
                descriptive=True,
            )
        ]

    def scan(self, records: Iterable[Record]) -> ScanResult:
        result = ScanResult()
        raw: list[Finding] = []

        for record in records:
            result.records_scanned += 1
            result.characters_scanned += len(record.text)
            raw.extend(self.scan_record(record, result))

        result.findings = self._sanitise(self._aggregate(raw))
        return result

    @staticmethod
    def _sanitise(findings: list[Finding]) -> list[Finding]:
        """Mask every known secret appearing in any snippet, not just its own.

        A snippet is a window of surrounding text, and in an ``.env`` dump the
        surroundings are other credentials. Redacting only the matched value
        would print the AWS key in clear as context for the database URL — the
        report leaking exactly what it is reporting.
        """
        needles: list[tuple[str, str]] = []
        for finding in findings:
            if finding.descriptive:
                continue
            for form in {finding.value, _WHITESPACE.sub(" ", finding.value).strip()}:
                if len(form) >= 8:
                    needles.append((form, redact(form)))
        needles.sort(key=lambda pair: len(pair[0]), reverse=True)

        cleaned: list[Finding] = []
        for finding in findings:
            snippet = finding.snippet
            for needle, masked in needles:
                if needle in snippet:
                    snippet = snippet.replace(needle, masked)
            cleaned.append(replace(finding, snippet=snippet))
        return cleaned

    @staticmethod
    def _aggregate(findings: list[Finding]) -> list[Finding]:
        """Collapse repeats of the same value into one finding with a count."""
        grouped: dict[tuple[str, str, str], list[Finding]] = {}
        for finding in findings:
            key = (finding.employee, finding.rule_id, _WHITESPACE.sub(" ", finding.value))
            grouped.setdefault(key, []).append(finding)

        collapsed: list[Finding] = []
        for group in grouped.values():
            first = group[0]
            others = tuple(dict.fromkeys(f.location for f in group[1:]))
            collapsed.append(replace(first, occurrences=len(group), also_at=others))

        collapsed.sort(
            key=lambda f: (
                _SEVERITY_ORDER.get(f.severity, 9),
                -f.confidence,
                f.employee,
                f.location,
                f.rule_id,
            )
        )
        return collapsed
