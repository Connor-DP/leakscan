"""Static source audit: prove the package cannot phone home.

:mod:`leakscan.netguard` blocks egress at runtime. This module closes the same
gap from the other side, at review time: it parses every source file in the
package and rejects imports that could move data off the host or run another
program. A reviewer who wants to verify the privacy claim can read
``netguard.py`` and this list, rather than the whole codebase.

``subprocess`` is on the list for the same reason as ``requests``: shelling out
is both an exfiltration channel and the thing that would break Windows support.

:func:`audit_html` covers the other half of the promise. The runtime guard
protects *this* process; it cannot protect the browser that opens the report.
A single ``<link>`` to a web font or a CDN ``<script>`` would make the viewer's
machine call out the instant the report is opened — revealing that an audit
report exists, when it was read and from where. So generated markup must be
entirely self-contained: inline CSS and JS, inline SVG, no remote anything.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

__all__ = [
    "FORBIDDEN_MODULES",
    "FORBIDDEN_PREFIXES",
    "audit_source",
    "audit_html",
]

#: Modules that can move data off the host, execute other programs, or open a
#: browser. None of them have a legitimate use in an offline scanner.
FORBIDDEN_MODULES = frozenset(
    {
        "subprocess",
        "requests",
        "httpx",
        "aiohttp",
        "urllib3",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "telnetlib",
        "webbrowser",
        "ssl",
        "asyncio",
    }
)

#: Forbidden by dotted prefix. ``urllib.parse`` stays allowed; the client
#: halves of urllib and http do not. ``http.server`` is absent deliberately —
#: the dashboard serves inbound requests on loopback, which is not egress.
FORBIDDEN_PREFIXES = ("urllib.request", "urllib.error", "http.client", "xmlrpc")

#: ``socket`` is the mechanism the guard itself is built from, so exactly one
#: file may import it. Anywhere else it would be an unguarded path to the network.
SOCKET_ALLOWED_FILES = frozenset({"netguard.py"})


def _iter_imports(tree: ast.AST):
    """Yield ``(module_name, lineno)`` for every import in *tree*."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            # node.module is None for a bare relative import ("from . import x").
            if node.module and node.level == 0:
                yield node.module, node.lineno


def _forbidden_reason(name: str) -> str | None:
    top = name.split(".", 1)[0]
    if top in FORBIDDEN_MODULES:
        return top
    for prefix in FORBIDDEN_PREFIXES:
        if name == prefix or name.startswith(prefix + "."):
            return prefix
    return None


def audit_source(root: Path) -> list[str]:
    """Audit every ``.py`` file under *root*. Returns human-readable violations."""
    violations: list[str] = []

    for path in sorted(root.rglob("*.py")):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            violations.append(f"{path.name}: unreadable ({exc})")
            continue

        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            violations.append(f"{path.name}:{exc.lineno}: syntax error ({exc.msg})")
            continue

        for name, lineno in _iter_imports(tree):
            reason = _forbidden_reason(name)
            if reason:
                violations.append(
                    f"{path.name}:{lineno}: imports {name!r} "
                    f"(forbidden: {reason})"
                )
            elif name.split(".", 1)[0] == "socket" and path.name not in SOCKET_ALLOWED_FILES:
                violations.append(
                    f"{path.name}:{lineno}: imports 'socket' outside "
                    f"{sorted(SOCKET_ALLOWED_FILES)} — route it through netguard"
                )

    return violations


# Contexts in which a URL causes the *browser* to fetch something. A URL that
# merely appears as escaped text — a Sentry DSN quoted inside a finding, say —
# is inert and must not be flagged, so matching is deliberately anchored to
# loading contexts rather than to URLs in general.
_REMOTE = r"""(?P<url>(?:https?:)?//[^"'\s>)]+)"""

_HTML_REMOTE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "remote asset",
        re.compile(
            r"""\b(?:src|href|action|formaction|poster|srcset|manifest|data)\s*=\s*["']?\s*"""
            + _REMOTE,
            re.IGNORECASE,
        ),
    ),
    (
        "remote stylesheet",
        re.compile(r"""@import\s+(?:url\()?\s*["']?\s*""" + _REMOTE, re.IGNORECASE),
    ),
    (
        "remote CSS resource",
        re.compile(r"""\burl\(\s*["']?\s*""" + _REMOTE, re.IGNORECASE),
    ),
    (
        "runtime network call",
        re.compile(
            r"""\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|importScripts"""
            r"""|sendBeacon)\b[^;\n]{0,120}?["']\s*"""
            + _REMOTE,
            re.IGNORECASE,
        ),
    ),
)


def audit_html(markup: str) -> list[str]:
    """Audit generated markup for anything the browser would fetch remotely.

    Returns human-readable violations. Relative paths, ``data:`` URIs and inline
    ``<style>``/``<script>`` blocks are all fine — the report is meant to be a
    single self-contained file that works with the network cable unplugged.
    """
    # One offending URL, one violation. The patterns deliberately overlap —
    # `@import url(…)` is both a stylesheet and a CSS resource — so the first
    # (most specific) pattern to match a given line and URL names it.
    found: dict[tuple[int, str], str] = {}
    for kind, pattern in _HTML_REMOTE_PATTERNS:
        for match in pattern.finditer(markup):
            line = markup.count("\n", 0, match.start()) + 1
            found.setdefault((line, match.group("url")), kind)

    return [
        f"line {line}: {kind} {url!r}" for (line, url), kind in sorted(found.items())
    ]
