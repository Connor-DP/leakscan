"""The normalised record — the one shape everything downstream sees.

Adapters turn each transcript format into a stream of :class:`Record`. The
detection engine, the reporter and the findings store all work from this and
never touch a format-specific structure again, so adding ChatGPT or Copilot
later means writing one adapter, not touching the engine.

Two fields carry most of the weight:

``kind``
    Where in the conversation the text came from. A key found in a *tool result*
    is a different story from one a person typed — nobody chose to expose it, it
    arrived as a side effect of a command. The report is far more useful when it
    can say which happened.

``location``
    Enough to find the text again, and stable across re-scans. That stability is
    what lets slice 6 keep triage state ("we checked this, it's a false
    positive") attached to a finding when the same transcripts are scanned again.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["KINDS", "Location", "Record"]

#: Every place text can come from. Ordered roughly by how much leaked data each
#: carries in practice — see docs/detection-scope.md.
KINDS = (
    "tool_result",
    "tool_call",
    "user_message",
    "attachment",
    "assistant_message",
    "system_prompt",
)


@dataclass(frozen=True, slots=True)
class Location:
    """Where a record sits, precisely enough to go back to it."""

    #: Path within the ZIP or scan root, always forward-slashed.
    file: str
    #: Position of the record in the file. Line number for ``.jsonl`` (0-based);
    #: message position for a Claude Desktop export.
    record_index: int
    #: Position of the content block within that record.
    block_index: int = 0

    @property
    def ref(self) -> str:
        """A short, stable, human-pasteable address."""
        return f"{self.file}#{self.record_index}.{self.block_index}"

    def __str__(self) -> str:
        return self.ref


@dataclass(frozen=True, slots=True)
class Record:
    """One piece of text from a transcript, with its provenance."""

    employee: str
    session_id: str
    source: str  # claude-code | claude-desktop
    kind: str
    text: str
    location: Location
    title: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown record kind: {self.kind!r}")
