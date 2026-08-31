"""Adapter for the plain-text files that live *beside* transcripts.

A transcript store is not only ``.jsonl``. Claude Code spills large tool outputs
to sidecar files under ``tool-results/`` rather than inlining them — which means
the biggest tool results, the ones most likely to be a schema dump or a query
result, are precisely the ones that end up here. Persistent memory files and
project instructions sit alongside them.

Kind is inferred from the path, because it changes what a finding means: a
credential in a spilled tool result arrived as a side effect of a command, while
one in a project-instructions file was written there deliberately.

Large files are chunked rather than held whole, with a small overlap so a value
straddling a boundary is still seen. Aggregation collapses the duplicate that
overlap can produce.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TextIO

from ..ingest import SourceFile
from ..records import Location, Record

__all__ = ["matches", "parse", "CHUNK_SIZE", "CHUNK_OVERLAP"]

SUFFIXES = (".txt", ".md", ".log", ".text")

CHUNK_SIZE = 8_000
CHUNK_OVERLAP = 200


def matches(name: str, head: str) -> bool:
    """True for plain-text files. Tried last, so it never steals a JSON format."""
    return name.lower().endswith(SUFFIXES)


def _kind_for(path: str) -> str:
    lowered = path.lower()
    if "tool-results/" in lowered or "tool_results/" in lowered:
        return "tool_result"
    if (
        lowered.endswith("claude.md")
        or "/memory/" in lowered
        or "instruction" in lowered
        or "agents.md" in lowered
    ):
        return "system_prompt"
    return "attachment"


def _session_for(path: str, name: str) -> str:
    """A spilled tool result lives at ``<session-id>/tool-results/<file>``."""
    parts = path.split("/")
    if len(parts) >= 3 and parts[-2] in ("tool-results", "tool_results"):
        return parts[-3]
    return name.rsplit(".", 1)[0]


def parse(source: SourceFile, stream: TextIO, problems: list[str]) -> Iterator[Record]:
    kind = _kind_for(source.path)
    session_id = _session_for(source.path, source.name)

    text = stream.read()
    if not text.strip():
        return

    step = CHUNK_SIZE - CHUNK_OVERLAP
    for index, start in enumerate(range(0, len(text), step)):
        chunk = text[start : start + CHUNK_SIZE]
        if not chunk.strip():
            continue
        yield Record(
            employee=source.employee,
            session_id=session_id,
            source="plain-text",
            kind=kind,
            text=chunk,
            location=Location(source.path, 0, index),
            title=source.name,
        )
        if start + CHUNK_SIZE >= len(text):
            break
