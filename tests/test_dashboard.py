"""Tests for the local triage dashboard."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from leakscan import adapters, dashboard, detect, ingest, report, rules, store as store_module
from leakscan.audit import audit_html
from leakscan.records import Location, Record

from .support import REPO_ROOT, ProjectTempDir

CORPUS_ZIP = REPO_ROOT / "corpus" / "synthetic-transcripts.zip"


def _populate(store: store_module.Store) -> None:
    ruleset = rules.load_rules()
    walked = ingest.walk(CORPUS_ZIP)
    problems: list[str] = []
    records = []
    for source in walked.files:
        records.extend(adapters.parse_file(source, problems))
    result = detect.Engine(ruleset).scan(records)
    document = report.build_report(result, walked, ruleset, problems=problems)
    store.record_scan(document, result.findings)


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.store = store_module.Store(Path(self._tmp.name) / "findings.sqlite3")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_empty_store_renders_an_explanation(self) -> None:
        markup = dashboard.render_dashboard(self.store)
        self.assertIn("No scans stored yet", markup)
        self.assertEqual(audit_html(markup), [])

    def test_page_is_self_contained(self) -> None:
        """Served from localhost restricts nothing about what a page may fetch."""
        _populate(self.store)
        self.assertEqual(audit_html(dashboard.render_dashboard(self.store)), [])

    def test_shows_findings_with_triage_controls(self) -> None:
        _populate(self.store)
        markup = dashboard.render_dashboard(self.store)
        self.assertIn("<select data-finding=", markup)
        self.assertIn("False positive", markup)

    def test_trend_appears_once_there_is_history(self) -> None:
        _populate(self.store)
        self.assertNotIn("Over time", dashboard.render_dashboard(self.store))
        _populate(self.store)
        self.assertIn("Over time", dashboard.render_dashboard(self.store))

    def test_escapes_untrusted_transcript_content(self) -> None:
        hostile = Record(
            employee="x", session_id="s", source="claude-code", kind="tool_result",
            text="AWS_ACCESS_KEY_ID=AKIA4XZQ7MNPKD3RTBWV <img src=x onerror=alert(1)>",
            location=Location("x/s.jsonl", 0, 0),
        )
        ruleset = rules.load_rules()
        result = detect.Engine(ruleset).scan([hostile])
        document = report.build_report(result, ingest.Ingest(root="x"), ruleset)
        self.store.record_scan(document, result.findings)
        markup = dashboard.render_dashboard(self.store)
        self.assertNotIn("<img src=x onerror", markup)
        self.assertIn("&lt;img", markup)


class ServerTests(unittest.TestCase):
    """The HTTP surface, exercised against a real loopback server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = ProjectTempDir()
        cls.store = store_module.Store(Path(cls._tmp.name) / "findings.sqlite3")
        _populate(cls.store)

        handler = type("Handler", (dashboard._Handler,), {})
        cls.server = dashboard._Server(("127.0.0.1", 0), handler)
        cls.server.store = cls.store
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls._tmp.cleanup()

    def _url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def test_binds_loopback_only(self) -> None:
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_serves_the_page(self) -> None:
        with urllib.request.urlopen(self._url("/")) as response:
            body = response.read().decode("utf-8")
        self.assertEqual(response.status, 200)
        self.assertIn("Leak triage", body)

    def test_sends_a_content_security_policy(self) -> None:
        """Belt and braces: the page cannot fetch even if a rule slips through."""
        with urllib.request.urlopen(self._url("/")) as response:
            policy = response.headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", policy)

    def test_findings_api(self) -> None:
        with urllib.request.urlopen(self._url("/api/findings")) as response:
            findings = json.loads(response.read())
        self.assertGreater(len(findings), 0)
        self.assertIn("finding_id", findings[0])

    def test_findings_api_never_returns_raw_values(self) -> None:
        with urllib.request.urlopen(self._url("/api/findings")) as response:
            findings = json.loads(response.read())
        self.assertTrue(all("value" not in f for f in findings))
        self.assertTrue(all("value_redacted" in f for f in findings))

    def test_triage_round_trip(self) -> None:
        target = self.store.findings()[0]["finding_id"]
        request = urllib.request.Request(
            self._url("/api/triage"),
            data=json.dumps({"finding_id": target, "state": "remediated"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request) as response:
            self.assertEqual(json.loads(response.read()), {"ok": True})
        saved = next(f for f in self.store.findings() if f["finding_id"] == target)
        self.assertEqual(saved["state"], "remediated")

    def test_bad_triage_state_is_rejected(self) -> None:
        request = urllib.request.Request(
            self._url("/api/triage"),
            data=json.dumps({"finding_id": "x", "state": "nonsense"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        self.assertEqual(caught.exception.code, 400)
        caught.exception.close()

    def test_unknown_path_is_404(self) -> None:
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(self._url("/etc/passwd"))
        self.assertEqual(caught.exception.code, 404)
        caught.exception.close()


if __name__ == "__main__":
    unittest.main()
