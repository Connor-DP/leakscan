"""The findings store: SQLite, local, and deletable on demand.

Three decisions shape this file.

**Raw values are never stored.** The store holds the redacted value and the
redacted snippet, nothing else. A findings database is already a ranked,
deduplicated index of every credential in the company — more useful to an
attacker than the transcripts it came from. Keeping the plaintext out means the
worst case is a map of where to look, not the keys themselves.

**Finding identity is stable across scans.** ``finding_id`` is a hash of
employee, rule and value — deliberately *not* location. Re-export a transcript
and record indices shift; if identity depended on them, every "we checked this,
it's a false positive" would be lost on the next scan, and triage nobody trusts
gets abandoned.

**Deletion is real.** :func:`purge` drops rows and then ``VACUUM``s, so freed
pages are rewritten rather than left in the file. It cannot defeat a backup or
a filesystem snapshot that already ran, and the docs say so.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path

from .detect import Finding, redact
from .paths import ensure_private_dir, harden

__all__ = [
    "STATES",
    "DEFAULT_DB_NAME",
    "finding_id",
    "Store",
    "PurgeResult",
]

#: Triage states. ``open`` is the implicit default for anything untouched.
STATES = ("open", "confirmed", "false_positive", "remediated")

DEFAULT_DB_NAME = "findings.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT NOT NULL,
    root         TEXT NOT NULL,
    files        INTEGER NOT NULL DEFAULT 0,
    records      INTEGER NOT NULL DEFAULT 0,
    characters   INTEGER NOT NULL DEFAULT 0,
    rules        INTEGER NOT NULL DEFAULT 0,
    suppressed   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    scan_id        INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_id     TEXT NOT NULL,
    employee       TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    category       TEXT NOT NULL,
    subtype        TEXT NOT NULL,
    severity       TEXT NOT NULL,
    confidence     INTEGER NOT NULL,
    session_id     TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT '',
    location       TEXT NOT NULL,
    location_kind  TEXT NOT NULL,
    occurrences    INTEGER NOT NULL DEFAULT 1,
    value_redacted TEXT NOT NULL,
    snippet        TEXT NOT NULL,
    PRIMARY KEY (scan_id, finding_id)
);

CREATE INDEX IF NOT EXISTS findings_by_employee ON findings(employee);
CREATE INDEX IF NOT EXISTS findings_by_finding ON findings(finding_id);

-- Keyed on finding_id alone, with no scan_id: triage is a judgement about a
-- leak, not about one scan of it, and must survive re-scanning.
CREATE TABLE IF NOT EXISTS triage (
    finding_id TEXT PRIMARY KEY,
    state      TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
"""


def finding_id(employee: str, rule_id: str, value: str) -> str:
    """A stable identity for a finding, independent of where it was seen."""
    digest = hashlib.sha256(
        "\x1f".join((employee, rule_id, " ".join(value.split()))).encode("utf-8")
    )
    return digest.hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class PurgeResult:
    scans: int = 0
    findings: int = 0
    triage: int = 0
    files: tuple[str, ...] = ()

    @property
    def anything(self) -> bool:
        return bool(self.scans or self.findings or self.triage or self.files)


class Store:
    """A local SQLite findings store."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        ensure_private_dir(self.path.parent)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
        harden(self.path)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
            connection.commit()
        finally:
            connection.close()

    # -- writing -----------------------------------------------------------

    def record_scan(self, report: dict, findings: Iterable[Finding]) -> int:
        """Store one scan and its findings. Returns the new scan id."""
        scan = report["scan"]
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scans (started_at, finished_at, root, files, records,"
                " characters, rules, suppressed) VALUES (?,?,?,?,?,?,?,?)",
                (
                    scan["started_at"],
                    scan["finished_at"],
                    scan["root"],
                    scan["files_parsed"],
                    scan["records"],
                    scan["characters"],
                    report["tool"]["rules"],
                    report["totals"]["suppressed_as_noise"],
                ),
            )
            scan_id = int(cursor.lastrowid)

            connection.executemany(
                "INSERT OR REPLACE INTO findings (scan_id, finding_id, employee,"
                " rule_id, category, subtype, severity, confidence, session_id,"
                " source, location, location_kind, occurrences, value_redacted,"
                " snippet) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        scan_id,
                        finding_id(f.employee, f.rule_id, f.value),
                        f.employee,
                        f.rule_id,
                        f.category,
                        f.subtype,
                        f.severity,
                        f.confidence,
                        f.session_id,
                        f.source,
                        f.location,
                        f.kind,
                        f.occurrences,
                        redact(f.value),  # never the raw value
                        f.snippet,
                    )
                    for f in findings
                ],
            )
        return scan_id

    def set_triage(self, identifier: str, state: str, note: str = "") -> None:
        if state not in STATES:
            raise ValueError(f"unknown triage state: {state!r}")
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO triage (finding_id, state, note, updated_at)"
                " VALUES (?,?,?,datetime('now'))"
                " ON CONFLICT(finding_id) DO UPDATE SET"
                " state=excluded.state, note=excluded.note, updated_at=excluded.updated_at",
                (identifier, state, note),
            )

    # -- reading -----------------------------------------------------------

    def latest_scan_id(self) -> int | None:
        with self._connect() as connection:
            row = connection.execute("SELECT MAX(id) AS id FROM scans").fetchone()
        return row["id"] if row and row["id"] is not None else None

    def scans(self) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id)"
                " AS findings FROM scans s ORDER BY s.id"
            ).fetchall()
        return [dict(row) for row in rows]

    def findings(self, scan_id: int | None = None) -> list[dict]:
        """Findings for a scan (latest by default), with triage state attached."""
        scan_id = scan_id if scan_id is not None else self.latest_scan_id()
        if scan_id is None:
            return []
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT f.*, COALESCE(t.state, 'open') AS state,"
                " COALESCE(t.note, '') AS note"
                " FROM findings f LEFT JOIN triage t ON t.finding_id = f.finding_id"
                " WHERE f.scan_id = ?"
                " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
                " WHEN 'medium' THEN 2 ELSE 3 END, f.confidence DESC, f.employee",
                (scan_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def trend(self) -> list[dict]:
        """Findings per scan, by severity — the shape of the problem over time."""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT s.id, s.finished_at, f.severity, COUNT(*) AS n"
                " FROM scans s LEFT JOIN findings f ON f.scan_id = s.id"
                " GROUP BY s.id, f.severity ORDER BY s.id"
            ).fetchall()

        by_scan: dict[int, dict] = {}
        for row in rows:
            entry = by_scan.setdefault(
                row["id"],
                {"scan_id": row["id"], "finished_at": row["finished_at"], "total": 0},
            )
            if row["severity"]:
                entry[row["severity"]] = row["n"]
                entry["total"] += row["n"]
        return list(by_scan.values())

    # -- deletion ----------------------------------------------------------

    def purge(
        self,
        *,
        everything: bool = False,
        scan_id: int | None = None,
        employee: str | None = None,
        output_dir: Path | None = None,
    ) -> PurgeResult:
        """Hard-delete stored findings, then rewrite the freed pages.

        ``VACUUM`` matters: without it SQLite leaves deleted rows readable in
        free pages, so a "deleted" secret would still be recoverable from the
        file with a hex editor.
        """
        removed_files: list[str] = []
        with self._connect() as connection:
            if everything:
                findings = connection.execute("DELETE FROM findings").rowcount
                scans = connection.execute("DELETE FROM scans").rowcount
                triage = connection.execute("DELETE FROM triage").rowcount
            elif scan_id is not None:
                findings = connection.execute(
                    "DELETE FROM findings WHERE scan_id = ?", (scan_id,)
                ).rowcount
                scans = connection.execute(
                    "DELETE FROM scans WHERE id = ?", (scan_id,)
                ).rowcount
                triage = connection.execute(
                    "DELETE FROM triage WHERE finding_id NOT IN"
                    " (SELECT finding_id FROM findings)"
                ).rowcount
            elif employee is not None:
                findings = connection.execute(
                    "DELETE FROM findings WHERE employee = ?", (employee,)
                ).rowcount
                scans = 0
                triage = connection.execute(
                    "DELETE FROM triage WHERE finding_id NOT IN"
                    " (SELECT finding_id FROM findings)"
                ).rowcount
            else:
                raise ValueError("purge needs everything=True, a scan_id, or an employee")

        # VACUUM cannot run inside a transaction.
        with closing(sqlite3.connect(self.path)) as connection:
            connection.isolation_level = None
            connection.execute("VACUUM")
        harden(self.path)

        if everything and output_dir:
            for name in ("report.json", "report.html"):
                target = Path(output_dir) / name
                if target.exists():
                    target.unlink()
                    removed_files.append(str(target))

        return PurgeResult(
            scans=max(scans, 0),
            findings=max(findings, 0),
            triage=max(triage, 0),
            files=tuple(removed_files),
        )
