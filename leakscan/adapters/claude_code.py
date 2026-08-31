"""Adapter for Claude Code ``.jsonl`` session transcripts.

One JSON object per line. Each carries a ``message`` whose ``content`` is a list
of blocks — ``text``, ``tool_use``, ``tool_result`` — and it is the blocks, not
the line, that we want as separate records.

The detail that catches people out: **a tool result arrives as a user-role
message.** Anything that treats ``role == "user"`` as "what the human typed"
mislabels the single richest source of leaked data in the file. Here the block
type decides the kind, and the role only breaks the tie for plain text.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, TextIO

from ..ingest import SourceFile
from ..records import Location, Record

__all__ = ["matches", "parse"]

#: Blocks we deliberately do not scan, and why. Counted, never silent.
UNSCANNED_BLOCKS = {
    "image": "image content (no OCR in v1)",
    "redacted_thinking": "redacted content",
}


def matches(name: str, head: str) -> bool:
    """True if *head* looks like a Claude Code JSONL transcript."""
    if not name.lower().endswith(".jsonl"):
        return False
    first = head.lstrip().split("\n", 1)[0]
    try:
        record = json.loads(first)
    except (ValueError, TypeError):
        return False
    return isinstance(record, dict) and ("message" in record or "type" in record)


def _flatten(value: Any) -> str:
    """Render a tool input or result as scannable text.

    Structure is flattened rather than dropped: a credential sitting in a nested
    field is still a credential, and ``json.dumps`` would bury it in escaping.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            rendered = _flatten(item)
            if rendered:
                parts.append(f"{key}: {rendered}")
        return "\n".join(parts)
    if isinstance(value, list):
        return "\n".join(part for part in (_flatten(item) for item in value) if part)
    return str(value)


def _blocks(content: Any) -> list[dict]:
    """Normalise a ``content`` field to a list of blocks."""
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        return [block for block in content if isinstance(block, dict)]
    return []


def parse(source: SourceFile, stream: TextIO, problems: list[str]) -> Iterator[Record]:
    session_fallback = source.name.removesuffix(".jsonl")

    for line_index, line in enumerate(stream):
        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
        except ValueError as exc:
            problems.append(f"{source.path}:{line_index + 1}: malformed JSON line ({exc.args[0]})")
            continue
        if not isinstance(entry, dict):
            problems.append(f"{source.path}:{line_index + 1}: line is not a JSON object")
            continue

        session_id = str(entry.get("sessionId") or session_fallback)
        timestamp = str(entry.get("timestamp") or "")
        entry_type = entry.get("type")

        def emit(kind: str, text: str, block_index: int) -> Record | None:
            if not text or not text.strip():
                return None
            return Record(
                employee=source.employee,
                session_id=session_id,
                source="claude-code",
                kind=kind,
                text=text,
                location=Location(source.path, line_index, block_index),
                timestamp=timestamp,
            )

        # Project instructions / system records: CLAUDE.md content lands here,
        # and routinely carries internal architecture and client names.
        if entry_type == "system":
            record = emit("system_prompt", _flatten(entry.get("content")), 0)
            if record:
                yield record
            continue

        if entry_type == "summary":
            # A compaction summary restates the conversation, leaked data included.
            record = emit("assistant_message", _flatten(entry.get("summary")), 0)
            if record:
                yield record
            continue

        message = entry.get("message")
        role = ""
        if isinstance(message, dict):
            role = str(message.get("role") or entry_type or "")
            for block_index, block in enumerate(_blocks(message.get("content"))):
                block_type = block.get("type")

                if block_type == "text":
                    kind = "assistant_message" if role == "assistant" else "user_message"
                    record = emit(kind, str(block.get("text") or ""), block_index)
                elif block_type == "thinking":
                    record = emit("assistant_message", _flatten(block.get("thinking")), block_index)
                elif block_type == "tool_use":
                    record = emit("tool_call", _flatten(block.get("input")), block_index)
                elif block_type == "tool_result":
                    record = emit("tool_result", _flatten(block.get("content")), block_index)
                elif block_type in UNSCANNED_BLOCKS:
                    problems.append(
                        f"{source.path}:{line_index + 1}: skipped "
                        f"{UNSCANNED_BLOCKS[block_type]}"
                    )
                    continue
                else:
                    problems.append(
                        f"{source.path}:{line_index + 1}: unrecognised block type "
                        f"{block_type!r} — not scanned"
                    )
                    continue

                if record:
                    yield record

        # Claude Code also stores the raw result alongside the message. It can
        # hold more than the block does, so scan it too.
        if "toolUseResult" in entry:
            record = emit("tool_result", _flatten(entry.get("toolUseResult")), 900)
            if record:
                yield record
