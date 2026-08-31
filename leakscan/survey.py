"""Parse a scan root and describe what was found, without detecting anything.

This is what ``leakscan inspect`` runs. It answers the question you need settled
before you trust any scan: *did the parser actually understand my transcripts?*
A report saying "no findings" means nothing if the files were never read, so the
counts here — records by kind, files skipped, lines that failed to parse — are
the honest precondition for everything downstream.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import adapters, ingest

__all__ = ["Survey", "survey", "format_survey"]


@dataclass(slots=True)
class Survey:
    root: str
    files: int = 0
    records: int = 0
    characters: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    by_employee: dict[str, int] = field(default_factory=dict)
    by_source: dict[str, int] = field(default_factory=dict)
    skipped: list[ingest.Skipped] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def survey(root: Path) -> Survey:
    """Walk and parse *root*, counting what comes out."""
    walked = ingest.walk(root)
    result = Survey(root=walked.root, files=len(walked.files), skipped=list(walked.skipped))

    for source in walked.files:
        result.by_employee.setdefault(source.employee, 0)
        for record in adapters.parse_file(source, result.problems):
            result.records += 1
            result.characters += len(record.text)
            result.by_kind[record.kind] = result.by_kind.get(record.kind, 0) + 1
            result.by_employee[record.employee] = result.by_employee.get(record.employee, 0) + 1
            result.by_source[record.source] = result.by_source.get(record.source, 0) + 1

    return result


def _table(title: str, counts: dict[str, int], order: tuple[str, ...] | None = None) -> list[str]:
    if not counts:
        return []
    keys = [key for key in order if key in counts] if order else sorted(counts)
    keys += [key for key in sorted(counts) if key not in keys]
    width = max(len(key) for key in keys)
    lines = [f"{title}:"]
    for key in keys:
        lines.append(f"  {key.ljust(width)}  {counts[key]:>7,}")
    return lines


def format_survey(result: Survey, *, max_listed: int = 20) -> str:
    """Render a survey for the terminal."""
    from .records import KINDS

    lines = [
        f"Scanned:  {result.root}",
        f"Files:    {result.files} parsed, {len(result.skipped)} skipped",
        f"Records:  {result.records:,} ({result.characters:,} characters of text)",
        "",
    ]
    lines += _table("By location", result.by_kind, KINDS) + [""]
    lines += _table("By employee", result.by_employee) + [""]
    lines += _table("By format", result.by_source)

    if result.skipped:
        lines += ["", f"Skipped files ({len(result.skipped)}):"]
        for item in result.skipped[:max_listed]:
            lines.append(f"  {item.path} — {item.reason}")
        if len(result.skipped) > max_listed:
            lines.append(f"  … and {len(result.skipped) - max_listed} more")

    if result.problems:
        lines += ["", f"Parse problems ({len(result.problems)}):"]
        for problem in result.problems[:max_listed]:
            lines.append(f"  {problem}")
        if len(result.problems) > max_listed:
            lines.append(f"  … and {len(result.problems) - max_listed} more")
    else:
        lines += ["", "No parse problems: every record in every file was understood."]

    return "\n".join(lines)
