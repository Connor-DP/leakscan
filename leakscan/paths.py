"""Filesystem locations and permission hardening, per OS.

The report is a second copy of whatever leaked, so it is written with the
tightest permissions the platform will give us without leaving the standard
library. See :func:`harden` for the honest Windows caveat.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from . import APP_NAME

__all__ = [
    "app_state_dir",
    "default_output_dir",
    "harden",
    "ensure_private_dir",
    "write_private_text",
]


def app_state_dir(app: str = APP_NAME) -> Path:
    """Per-user state directory, following each platform's convention."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        base = os.environ.get("XDG_DATA_HOME")
        root = Path(base) if base else Path.home() / ".local" / "share"
    return root / app


def default_output_dir() -> Path:
    """Where reports go by default: ``./output`` beside the working directory."""
    return Path.cwd() / "output"


def harden(path: Path) -> bool:
    """Restrict *path* to the current user.

    Returns True if the platform actually enforced it.

    On POSIX this is ``chmod 0600`` for files and ``0700`` for directories.
    On Windows it is a no-op and returns False: setting a real DACL needs
    ``icacls`` (a subprocess) or ``pywin32`` (a dependency), and both are
    barred by design. Windows deployments should keep output under the user
    profile, which the profile's own ACL already restricts — the caller is
    told which happened rather than being given a false guarantee.
    """
    if os.name != "posix":
        return False
    try:
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    except OSError:
        return False
    return True


def ensure_private_dir(path: Path) -> Path:
    """Create *path* (and parents) and harden it. Returns the path."""
    path.mkdir(parents=True, exist_ok=True)
    harden(path)
    return path


def write_private_text(path: Path, text: str) -> Path:
    """Write *text* to *path*, creating it unreadable by anyone else.

    The file is created with mode 0600 from the outset rather than being
    chmod'ed afterwards, so there is no window in which a fresh report sits
    world-readable.
    """
    ensure_private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    harden(path)
    return path
