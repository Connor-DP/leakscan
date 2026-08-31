"""Adapter for the Claude Desktop / claude.ai account data export.

A single ``conversations.json``: an array of conversations, each with
``chat_messages``. A message carries ``text``, and newer exports also carry a
``content`` block list; attachments arrive with their extracted text inline.

Unlike Claude Code there are no tool calls or tool results — this format is
plain conversation plus attachments. Attachments are where the bulk material
sits: someone drags in a board pack or a customer CSV and the whole thing is in
the export.

The file is read whole rather than streamed, because JSON gives no honest way to
parse an array incrementally without a custom tokeniser. Exports run to tens of
megabytes, which is fine; if that ever stops being true it is worth revisiting.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any, TextIO

from ..ingest import SourceFile
from ..records import Location, Record

__all__ = ["matches", "parse"]


def matches(name: str, head: str) -> bool:
    """True if this looks like a Claude account export.

    A file actually named ``conversations.json`` is claimed on the name alone,
    even when its contents are wrong. That is deliberate: the alternative is
    telling someone their export is an "unrecognised format" when the useful
    answer is "this is the right file, but it is not an array of conversations".
    Recognising it here lets :func:`parse` say which.
    """
    lowered = name.lower()
    if not lowered.endswith(".json"):
        return False
    if "conversations" in lowered:
        return True
    # Otherwise require the structural tell, which survives a truncated head.
    return head.lstrip().startswith("[") and "chat_messages" in head


def _text_of(message: dict) -> str:
    """Pull the message text, preferring content blocks over the flat field."""
    parts: list[str] = []
    content = message.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = str(block.get("text") or "")
                if text.strip():
                    parts.append(text)
    if parts:
        return "\n".join(parts)

    text = message.get("text")
    return str(text) if isinstance(text, str) else ""


def _attachments_of(message: dict) -> list[tuple[str, str]]:
    """Return ``(filename, extracted text)`` for each attachment carrying text."""
    found: list[tuple[str, str]] = []
    for key in ("attachments", "files"):
        items = message.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("file_name") or item.get("name") or "attachment")
            extracted = item.get("extracted_content") or item.get("content")
            if isinstance(extracted, str) and extracted.strip():
                found.append((name, extracted))
    return found


def parse(source: SourceFile, stream: TextIO, problems: list[str]) -> Iterator[Record]:
    try:
        payload: Any = json.load(stream)
    except ValueError as exc:
        problems.append(f"{source.path}: malformed JSON ({exc.args[0]})")
        return

    if not isinstance(payload, list):
        problems.append(f"{source.path}: expected an array of conversations")
        return

    position = 0
    for conversation_index, conversation in enumerate(payload):
        if not isinstance(conversation, dict):
            problems.append(
                f"{source.path}: conversation {conversation_index} is not an object"
            )
            continue

        session_id = str(conversation.get("uuid") or f"conversation-{conversation_index}")
        title = str(conversation.get("name") or "")
        messages = conversation.get("chat_messages")
        if not isinstance(messages, list):
            problems.append(f"{source.path}: conversation {session_id!r} has no chat_messages")
            continue

        for message in messages:
            if not isinstance(message, dict):
                problems.append(f"{source.path}: malformed message in {session_id!r}")
                position += 1
                continue

            sender = str(message.get("sender") or message.get("role") or "")
            kind = "user_message" if sender in ("human", "user") else "assistant_message"
            timestamp = str(message.get("created_at") or "")

            text = _text_of(message)
            if text.strip():
                yield Record(
                    employee=source.employee,
                    session_id=session_id,
                    source="claude-desktop",
                    kind=kind,
                    text=text,
                    location=Location(source.path, position, 0),
                    title=title,
                    timestamp=timestamp,
                )

            for attachment_index, (name, extracted) in enumerate(_attachments_of(message), 1):
                yield Record(
                    employee=source.employee,
                    session_id=session_id,
                    source="claude-desktop",
                    kind="attachment",
                    text=f"{name}\n{extracted}",
                    location=Location(source.path, position, attachment_index),
                    title=title,
                    timestamp=timestamp,
                )

            position += 1
