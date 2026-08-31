"""Walk a ZIP or a directory and hand back the transcript files inside it.

Two things here matter more than they look.

**Nothing is skipped silently.** A file that cannot be read or recognised goes
on :attr:`Ingest.skipped` *with a reason*, and that list belongs in the report. A
quietly dropped file looks exactly like a clean result, which is the worst
failure mode a scanner has.

**Files are opened lazily and read as streams.** A transcript can be hundreds of
megabytes; the engine works line by line and never holds a whole file.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

__all__ = ["UNATTRIBUTED", "SourceFile", "Skipped", "Ingest", "walk"]

#: Employee name used when a file sits at the root with no folder above it.
UNATTRIBUTED = "(unattributed)"

#: Only these are worth opening. Everything else is skipped, with a reason.
#:
#: The text suffixes matter more than they look: Claude Code spills large tool
#: outputs to sidecar ``.txt`` files under ``tool-results/`` instead of inlining
#: them, so the biggest tool results — schema dumps, query output — live there
#: rather than in the ``.jsonl``. Memory files and project instructions are ``.md``.
SUPPORTED_SUFFIXES = frozenset({".jsonl", ".json", ".txt", ".md", ".log", ".text"})

#: Archive and OS clutter — skipped quietly, since reporting them is noise.
IGNORED_NAMES = frozenset({".DS_Store", "Thumbs.db", "desktop.ini"})
IGNORED_DIRS = frozenset({"__MACOSX", ".git", "node_modules", "__pycache__", ".tmp"})


@dataclass(frozen=True, slots=True)
class SourceFile:
    """A transcript file we intend to parse, not yet read."""

    #: Path relative to the scan root, forward-slashed, used in locations.
    path: str
    #: Derived from the top-level folder — see decision 5, folder per employee.
    employee: str
    size: int
    _origin: Path
    _archive_member: str | None = None

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @contextmanager
    def open_text(self) -> Iterator[TextIO]:
        """Open the file as UTF-8 text.

        Undecodable bytes are replaced rather than raising: a transcript with
        one bad byte is still worth scanning, and refusing to read it would
        create exactly the silent gap this module exists to prevent. Universal
        newlines means a ZIP assembled on Windows parses the same as one from a Mac.
        """
        if self._archive_member is None:
            binary = self._origin.open("rb")
            try:
                yield io.TextIOWrapper(binary, encoding="utf-8", errors="replace", newline=None)
            finally:
                binary.close()
        else:
            with zipfile.ZipFile(self._origin) as archive:
                with archive.open(self._archive_member) as binary:
                    yield io.TextIOWrapper(
                        binary, encoding="utf-8", errors="replace", newline=None
                    )


@dataclass(frozen=True, slots=True)
class Skipped:
    """A file we did not parse, and why. This belongs in the report."""

    path: str
    reason: str


@dataclass(slots=True)
class Ingest:
    """The result of walking a scan root."""

    root: str
    files: list[SourceFile] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)

    @property
    def employees(self) -> list[str]:
        return sorted({source.employee for source in self.files})


def _employee_for(relative_path: str) -> str:
    """Folder per employee: the first path component names the person."""
    parts = relative_path.split("/")
    return parts[0] if len(parts) > 1 else UNATTRIBUTED


def _is_ignored(relative_path: str) -> bool:
    parts = relative_path.split("/")
    if parts[-1] in IGNORED_NAMES or parts[-1].startswith("._"):
        return True
    return any(part in IGNORED_DIRS for part in parts[:-1])


def _classify(relative_path: str, size: int) -> str | None:
    """Return a skip reason, or None if the file should be parsed."""
    suffix = "." + relative_path.rsplit(".", 1)[-1].lower() if "." in relative_path else ""
    if suffix not in SUPPORTED_SUFFIXES:
        return f"unsupported file type ({suffix or 'no extension'})"
    if size == 0:
        return "empty file"
    return None


def _walk_directory(root: Path) -> Ingest:
    ingest = Ingest(root=str(root))
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if _is_ignored(relative):
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            ingest.skipped.append(Skipped(relative, f"unreadable ({exc.strerror or exc})"))
            continue

        reason = _classify(relative, size)
        if reason:
            ingest.skipped.append(Skipped(relative, reason))
            continue

        ingest.files.append(
            SourceFile(
                path=relative,
                employee=_employee_for(relative),
                size=size,
                _origin=path,
            )
        )
    return ingest


def _walk_zip(archive_path: Path) -> Ingest:
    ingest = Ingest(root=str(archive_path))
    try:
        archive = zipfile.ZipFile(archive_path)
    except (zipfile.BadZipFile, OSError) as exc:
        ingest.skipped.append(Skipped(archive_path.name, f"not a readable ZIP ({exc})"))
        return ingest

    with archive:
        for info in sorted(archive.infolist(), key=lambda i: i.filename):
            if info.is_dir():
                continue
            relative = info.filename.replace("\\", "/")

            # Zip-slip: we never extract, but a path escaping the root means the
            # archive is malformed or hostile, and its attribution is meaningless.
            if relative.startswith("/") or ".." in relative.split("/"):
                ingest.skipped.append(Skipped(relative, "unsafe path in archive"))
                continue
            if _is_ignored(relative):
                continue

            reason = _classify(relative, info.file_size)
            if reason:
                ingest.skipped.append(Skipped(relative, reason))
                continue

            ingest.files.append(
                SourceFile(
                    path=relative,
                    employee=_employee_for(relative),
                    size=info.file_size,
                    _origin=archive_path,
                    _archive_member=info.filename,
                )
            )
    return ingest


def walk(root: Path) -> Ingest:
    """Collect the transcript files under *root*, a ZIP or a directory."""
    root = Path(root)
    if root.is_dir():
        return _walk_directory(root)
    if root.is_file() and root.suffix.lower() == ".zip":
        return _walk_zip(root)
    if root.is_file():
        # A single transcript is a legitimate thing to scan.
        reason = _classify(root.name, root.stat().st_size)
        ingest = Ingest(root=str(root))
        if reason:
            ingest.skipped.append(Skipped(root.name, reason))
        else:
            ingest.files.append(
                SourceFile(
                    path=root.name,
                    employee=UNATTRIBUTED,
                    size=root.stat().st_size,
                    _origin=root,
                )
            )
        return ingest

    ingest = Ingest(root=str(root))
    ingest.skipped.append(Skipped(str(root), "path does not exist"))
    return ingest
