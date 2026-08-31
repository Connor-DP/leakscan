"""Structural detectors: findings from the *shape* of what was pasted.

Every rule in the YAML packs depends on vocabulary — a provider's key prefix, a
UK identifier format, the word "ARR". Vocabulary does not travel. A law firm has
matters, a hospital has patients, a factory has bills of materials, and none of
them have monthly recurring revenue.

Shape does travel. A two-hundred-row table pasted into a chat is alarming in
every industry and every country, and recognising it needs no keyword at all.
These detectors are what make the scanner useful to an organisation whose words
we have never seen — including one whose national ID format no rule pack covers,
because a header row saying ``name, dob, address`` gives the game away by itself.

They emit :class:`Signal`, not ``Finding``, so this module stays independent of
the detection engine that consumes it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .records import Record

__all__ = ["Signal", "detect", "MIN_TABLE_ROWS", "MIN_DOCUMENT_CHARS"]

#: Rows sharing a shape before it counts as a table rather than coincidence.
MIN_TABLE_ROWS = 4

#: Characters in one message before it reads as a pasted document.
MIN_DOCUMENT_CHARS = 3_000

#: Delimiters worth testing, in the order they are tried.
_DELIMITERS = ("|", ",", "\t", ";")

#: Field names that mean "this row is about a person", in any sector and any
#: country. Deliberately not values — the point is to catch a personal-data
#: export whose *contents* no rule pack recognises.
_PERSONAL_FIELDS = frozenset(
    {
        "name", "first name", "firstname", "first_name", "last name", "lastname",
        "last_name", "surname", "full name", "fullname", "full_name",
        "dob", "date of birth", "date_of_birth", "birth date", "birthdate",
        "email", "e-mail", "email address", "email_address",
        "phone", "telephone", "mobile", "phone number", "phone_number",
        "address", "home address", "street", "postcode", "post code", "zip",
        "zipcode", "zip code", "city", "town", "county", "state", "country",
        "salary", "pay", "wage", "gross pay", "net pay", "annual salary",
        "national insurance", "ni number", "ni_number", "nino", "ssn",
        "social security", "nhs number", "nhs_number", "passport",
        "national id", "id number", "employee id", "employee_id", "staff id",
        "customer id", "patient id", "student id", "account number", "iban",
        "sort code", "sort_code", "bank account", "card number",
        "gender", "sex", "ethnicity", "nationality", "marital status",
        "next of kin", "emergency contact", "job title", "department",
        "start date", "end date", "manager",
    }
)

#: Markers that a long paste has document structure rather than being one blob.
_DOCUMENT_MARKERS = (
    re.compile(r"(?m)^\s*\d+(?:\.\d+)*[.)]\s+\S"),        # numbered clauses
    re.compile(r"(?m)^\s*[-*•]\s+\S"),               # bullets
    re.compile(r"(?m)^[A-Z][A-Z \t&/'-]{6,}$"),           # shouted headings
    re.compile(r"(?m)^\s*(?:[A-Z][\w '-]{2,40}):\s*$"),   # title-case headings
    re.compile(r"\n\s*\n"),                               # paragraph breaks
)


@dataclass(frozen=True, slots=True)
class Signal:
    """A structural observation, ready to become a finding."""

    rule_id: str
    category: str
    subtype: str
    severity: str
    confidence: int
    summary: str


def _count_outside_quotes(line: str, delimiter: str) -> int:
    """Count *delimiter* in *line*, ignoring anything inside quotes.

    Necessary, not fussy: a CSV of people almost always has a quoted address
    with commas in it, so a naive count makes every data row disagree with its
    own header and the table stops looking like a table.
    """
    count = 0
    quote: str | None = None
    for char in line:
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == delimiter:
            count += 1
    return count


def _split_outside_quotes(line: str, delimiter: str) -> list[str]:
    cells: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in line:
        if quote:
            if char == quote:
                quote = None
            else:
                current.append(char)
        elif char in "\"'":
            quote = char
        elif char == delimiter:
            cells.append("".join(current))
            current = []
        else:
            current.append(char)
    cells.append("".join(current))
    return cells


def _rows_by_shape(text: str) -> tuple[str, int, int] | None:
    """Find repeated delimiter-separated rows.

    Returns ``(delimiter, rows, columns)`` for the strongest candidate, or None.
    A table is lines that agree on how many separators they contain — which is
    what distinguishes data from prose that happens to have commas in it.
    """
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) < MIN_TABLE_ROWS:
        return None

    best: tuple[str, int, int] | None = None
    for delimiter in _DELIMITERS:
        counts: dict[int, int] = {}
        for line in lines:
            separators = _count_outside_quotes(line, delimiter)
            if separators >= 2:  # three or more columns
                counts[separators] = counts.get(separators, 0) + 1
        if not counts:
            continue
        separators, rows = max(counts.items(), key=lambda item: item[1])
        if rows >= MIN_TABLE_ROWS and (best is None or rows > best[1]):
            best = (delimiter, rows, separators + 1)
    return best


def _personal_fields_in(line: str, delimiter: str) -> set[str]:
    cells = {cell.strip().lower() for cell in _split_outside_quotes(line, delimiter)}
    return {cell for cell in cells if cell in _PERSONAL_FIELDS}


def _tabular(record: Record) -> list[Signal]:
    shape = _rows_by_shape(record.text)
    if shape is None:
        return []
    delimiter, rows, columns = shape

    # Does any line name personal fields? That turns "a table" into "a table
    # about people", which is a different severity of problem.
    personal: set[str] = set()
    for line in record.text.splitlines():
        found = _personal_fields_in(line, delimiter)
        if len(found) >= 3:
            personal = found
            break

    if personal:
        # Volume changes the conversation, but any export of people is serious.
        severity = "critical" if rows >= 10 else "high"
        return [
            Signal(
                rule_id="structure.personal_data_export.v1",
                category="pii",
                subtype="personal_data_export",
                severity=severity,
                confidence=88,
                summary=(
                    f"{rows} rows x {columns} columns naming personal fields "
                    f"({', '.join(sorted(personal)[:5])}) in a "
                    f"{record.kind.replace('_', ' ')}"
                ),
            )
        ]

    severity = "high" if rows >= 25 else "medium"
    return [
        Signal(
            rule_id="structure.bulk_data_export.v1",
            category="internal",
            subtype="bulk_data_export",
            severity=severity,
            confidence=75,
            summary=(
                f"{rows} rows x {columns} columns of tabular data in a "
                f"{record.kind.replace('_', ' ')}"
            ),
        )
    ]


def _document(record: Record) -> list[Signal]:
    # Only what a person pasted or attached. A long tool result is a log, and a
    # chunked file would otherwise trip this on every chunk.
    if record.kind not in ("user_message", "attachment"):
        return []
    if len(record.text) < MIN_DOCUMENT_CHARS:
        return []

    structure = sum(1 for marker in _DOCUMENT_MARKERS if marker.search(record.text))
    if structure < 3:
        return []

    words = len(record.text.split())
    severity = "high" if len(record.text) >= 10_000 else "medium"
    return [
        Signal(
            rule_id="structure.document_paste.v1",
            category="internal",
            subtype="document_paste",
            severity=severity,
            confidence=70,
            summary=(
                f"a structured document of roughly {words:,} words was pasted "
                f"into a {record.kind.replace('_', ' ')}"
            ),
        )
    ]


#: Every structural detector, run against each record.
DETECTORS = (_tabular, _document)


def detect(record: Record) -> list[Signal]:
    """Run every structural detector over one record."""
    signals: list[Signal] = []
    for detector in DETECTORS:
        signals.extend(detector(record))
    return signals
