"""Transcript Leak Scanner — an offline scanner for AI-assistant transcripts.

Scans exported AI-assistant session transcripts for leaked PII, secrets and
confidential data, and produces a ranked report.

The product's core promise is that transcript content never leaves the host on
which it already lives. That is enforced at runtime by :mod:`leakscan.netguard`
and checked statically by :mod:`leakscan.audit`; it is an invariant, not a
setting, so there is deliberately no flag to turn it off.

Requires Python 3.11+ and the standard library only.
"""

from __future__ import annotations

__all__ = ["__version__", "APP_NAME", "PACKAGE_ROOT"]

__version__ = "0.1.0"

#: Used for per-OS state directories.
APP_NAME = "transcript-leak-scanner"

from pathlib import Path as _Path

#: Directory containing this package, for source auditing and asset lookup.
PACKAGE_ROOT = _Path(__file__).resolve().parent
