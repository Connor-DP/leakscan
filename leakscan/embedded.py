"""Decode base64 payloads embedded in transcripts, so encoding is not a hiding place.

A credential that has been base64'd is still a credential, and it is invisible
to every pattern in the rule packs. This closes that gap: long base64 runs are
decoded, sniffed, and re-emitted as their own records for the engine to scan.

Deliberately conservative. Decoded content is only scanned when it is plainly
text; anything that sniffs as an image, PDF or archive is **reported as
unscanned** rather than skipped in silence, because "we could not read this" and
"there was nothing here" must never look the same to a reader.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator

from .records import Location, Record

__all__ = ["expand", "MAX_DECODED_BYTES", "MAX_PER_RECORD"]

#: Runs shorter than this are noise — hashes, IDs, short tokens. 64 characters
#: decodes to 48 bytes, which is about the smallest encoded ``.env`` line worth
#: chasing; the printable-text check below does the rest of the filtering.
_MIN_RUN = 64

#: A single blob larger than this is not decoded. Guards memory on hostile input.
MAX_DECODED_BYTES = 1_000_000

#: Cap per record, so one pathological file cannot dominate a scan.
MAX_PER_RECORD = 20

#: Block indices for expansions start here, keeping them distinct from the
#: parent record's own blocks in a location ref.
_BLOCK_BASE = 800

_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{%d,}={0,2}(?![A-Za-z0-9+/=])" % _MIN_RUN)

#: Magic bytes we can identify but not read.
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF8", "GIF image"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x1f\x8b", "gzip data"),
    (b"BM", "bitmap image"),
    (b"\x00\x00\x01\x00", "icon"),
    (b"OggS", "Ogg media"),
    (b"\x1aE\xdf\xa3", "Matroska media"),
)


def _sniff(payload: bytes) -> str | None:
    for signature, label in _SIGNATURES:
        if payload.startswith(signature):
            return label
    return None


def _as_text(payload: bytes) -> str | None:
    """Return decoded text if the payload is plainly textual, else None."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    printable = sum(1 for char in text if char.isprintable() or char in "\n\r\t ")
    return text if printable / len(text) >= 0.90 else None


def _is_jwt_segment(text: str, start: int, end: int) -> bool:
    """A JWT's middle segment is base64 between dots; the JWT rules own it."""
    before = text[start - 1] if start else ""
    after = text[end] if end < len(text) else ""
    return before == "." or after == "."


def expand(record: Record, problems: list[str]) -> Iterator[Record]:
    """Yield a record for each decodable base64 payload inside *record*."""
    text = record.text
    emitted = 0

    for match in _CANDIDATE.finditer(text):
        if emitted >= MAX_PER_RECORD:
            problems.append(
                f"{record.location.ref}: more than {MAX_PER_RECORD} embedded "
                f"payloads; the rest were not decoded"
            )
            return

        blob = match.group(0)
        if _is_jwt_segment(text, match.start(), match.end()):
            continue
        if len(blob) * 3 // 4 > MAX_DECODED_BYTES:
            problems.append(
                f"{record.location.ref}: embedded payload over "
                f"{MAX_DECODED_BYTES:,} bytes was not decoded"
            )
            continue

        try:
            payload = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(payload) < 16:
            continue

        label = _sniff(payload)
        if label:
            problems.append(
                f"{record.location.ref}: embedded {label} not scanned "
                f"({len(payload):,} bytes)"
            )
            continue

        decoded = _as_text(payload)
        if decoded is None:
            problems.append(
                f"{record.location.ref}: embedded binary payload not scanned "
                f"({len(payload):,} bytes)"
            )
            continue

        yield Record(
            employee=record.employee,
            session_id=record.session_id,
            source=record.source,
            kind=record.kind,
            text=decoded,
            location=Location(
                record.location.file, record.location.record_index, _BLOCK_BASE + emitted
            ),
            title=record.title,
            timestamp=record.timestamp,
        )
        emitted += 1
