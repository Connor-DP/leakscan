"""Format adapters: transcript file in, :class:`~leakscan.records.Record` out.

Adding a source later — ChatGPT export, Copilot, Cursor — means writing one
module here and registering it. Nothing downstream changes.

Format is decided by **looking at the content**, not by trusting the file
extension, because both v1 formats are just `.json`/`.jsonl` and a customer's
export may be named anything.
"""

from __future__ import annotations

from collections.abc import Iterator

from .. import embedded
from ..ingest import SourceFile
from ..records import Record
from . import claude_code, claude_desktop, plain_text

__all__ = ["ADAPTERS", "sniff", "parse_file"]

#: Tried in order, so the structured formats get first refusal and the
#: plain-text catch-all never steals a JSON file.
ADAPTERS = (claude_code, claude_desktop, plain_text)


def sniff(source: SourceFile, head: str):
    """Return the adapter that recognises *head*, or None."""
    for adapter in ADAPTERS:
        if adapter.matches(source.name, head):
            return adapter
    return None


def parse_file(source: SourceFile, problems: list[str]) -> Iterator[Record]:
    """Parse one file, appending any problems encountered to *problems*.

    Yields nothing if the format is unrecognised — that is recorded as a problem
    rather than raised, so one odd file cannot abort a scan of ten thousand.
    """
    try:
        with source.open_text() as stream:
            head = stream.read(4096)
    except OSError as exc:
        problems.append(f"{source.path}: unreadable ({exc})")
        return

    if not head.strip():
        problems.append(f"{source.path}: file is empty")
        return

    adapter = sniff(source, head)
    if adapter is None:
        problems.append(f"{source.path}: unrecognised transcript format — not scanned")
        return

    with source.open_text() as stream:
        for record in adapter.parse(source, stream, problems):
            yield record
            # A base64'd credential is still a credential, and matches no
            # pattern until it is decoded.
            yield from embedded.expand(record, problems)
