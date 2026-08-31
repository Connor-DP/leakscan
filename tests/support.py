"""Shared test helpers.

Temporary files stay inside the project, under ``.tmp/``, rather than the OS
temp area. Nothing the suite touches then lives outside this one folder, which
makes it easy to see exactly what a test run wrote — and to delete it.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

__all__ = ["REPO_ROOT", "TMP_ROOT", "ProjectTempDir"]

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Gitignored. Safe to delete at any time; each test cleans up after itself.
TMP_ROOT = REPO_ROOT / ".tmp"


class ProjectTempDir(tempfile.TemporaryDirectory):
    """A :class:`tempfile.TemporaryDirectory` rooted at ``<repo>/.tmp``.

    Same interface as the standard class — use it as a context manager, or hold
    the instance and call ``cleanup()``.
    """

    def __init__(self, prefix: str = "test-") -> None:
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        super().__init__(prefix=prefix, dir=TMP_ROOT)
