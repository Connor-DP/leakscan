"""A local dashboard for triaging findings, on loopback only.

Serves one self-contained page plus a tiny JSON API for setting triage state.
Bound to 127.0.0.1, so nothing on the network can reach it — and the page itself
is inline CSS and script with no remote references, because being served from
localhost restricts nothing about what a page may *fetch*.

``server_bind`` is overridden to skip :func:`socket.getfqdn`, which the standard
library calls to set ``server_name`` and which would attempt a name lookup the
egress guard is there to prevent.
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .report import _STYLE
from .store import STATES, Store

__all__ = ["render_dashboard", "serve"]

_SEVERITIES = ("critical", "high", "medium", "low")

_STATE_LABEL = {
    "open": "Open",
    "confirmed": "Confirmed",
    "false_positive": "False positive",
    "remediated": "Remediated",
}

_EXTRA_STYLE = """
.triage { display: flex; gap: 8px; align-items: center; margin: 8px 0 0; }
.triage select { font: inherit; font-size: 13px; padding: 3px 8px; border-radius: 4px;
                 border: 1px solid var(--border); background: var(--bg); color: var(--text); }
.state { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
.state.confirmed { color: var(--critical); }
.state.false_positive { color: var(--muted); }
.state.remediated { color: var(--medium); }
.finding.false_positive { opacity: 0.55; }
.trend td.bar { padding: 0; }
.trend .track { display: block; height: 10px; border-radius: 3px; background: var(--critical); }
.saved { font-size: 12px; color: var(--muted); }
"""

_SCRIPT = """
(function () {
  document.querySelectorAll('select[data-finding]').forEach(function (select) {
    select.addEventListener('change', function () {
      var card = select.closest('.finding');
      var note = card.querySelector('.saved');
      fetch('/api/triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ finding_id: select.dataset.finding, state: select.value })
      }).then(function (response) {
        if (!response.ok) { throw new Error('failed'); }
        note.textContent = 'saved';
        card.classList.toggle('false_positive', select.value === 'false_positive');
      }).catch(function () { note.textContent = 'could not save'; });
    });
  });
  var buttons = document.querySelectorAll('.controls button');
  var cards = document.querySelectorAll('.finding');
  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      var want = button.dataset.filter;
      cards.forEach(function (card) {
        card.hidden = want !== 'all'
          && card.dataset.severity !== want
          && card.dataset.state !== want;
      });
      buttons.forEach(function (other) {
        other.setAttribute('aria-pressed', String(other.dataset.filter === want));
      });
    });
  });
})();
"""


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def render_dashboard(store: Store) -> str:
    """Render the triage page from what the store holds."""
    findings = store.findings()
    trend = store.trend()
    scans = store.scans()

    by_severity: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_state[finding["state"]] = by_state.get(finding["state"], 0) + 1

    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Leak triage</title>",
        f"<style>{_STYLE}{_EXTRA_STYLE}</style>",
        "</head><body><main>",
        "<h1>Leak triage</h1>",
    ]

    if not scans:
        parts += [
            '<p class="sub">No scans stored yet. Run '
            "<code>leakscan scan &lt;path&gt;</code> first.</p>",
            "</main></body></html>",
        ]
        return "\n".join(parts)

    latest = scans[-1]
    parts.append(
        f'<p class="sub">{_e(len(findings))} findings from the scan of '
        f'<code>{_e(latest["root"])}</code> on {_e(latest["finished_at"])}</p>'
    )

    parts.append('<div class="tiles">')
    for state in STATES:
        parts.append(
            f'<div class="tile"><div class="n">{_e(by_state.get(state, 0))}</div>'
            f'<div class="l">{_e(_STATE_LABEL[state])}</div></div>'
        )
    parts.append("</div>")

    # -- trend -------------------------------------------------------------
    if len(trend) > 1:
        peak = max(entry["total"] for entry in trend) or 1
        parts.append("<h2>Over time</h2><div class=\"scroll\"><table class=\"trend\">")
        parts.append(
            "<thead><tr><th>Scan</th><th>When</th><th class='num'>Findings</th>"
            "<th>Shape</th></tr></thead><tbody>"
        )
        for entry in trend:
            width = round(entry["total"] / peak * 100)
            parts.append(
                f'<tr><td>#{_e(entry["scan_id"])}</td>'
                f'<td>{_e(entry["finished_at"])}</td>'
                f'<td class="num">{_e(entry["total"])}</td>'
                f'<td class="bar"><span class="track" style="width:{width}%"></span></td></tr>'
            )
        parts.append("</tbody></table></div>")

    # -- findings ----------------------------------------------------------
    parts.append("<h2>Findings</h2>")
    parts.append('<div class="controls">')
    parts.append('<button type="button" data-filter="all" aria-pressed="true">All</button>')
    for severity in _SEVERITIES:
        if by_severity.get(severity):
            parts.append(
                f'<button type="button" data-filter="{_e(severity)}" aria-pressed="false">'
                f"{_e(severity.title())} ({_e(by_severity[severity])})</button>"
            )
    for state in ("open", "confirmed", "remediated"):
        if by_state.get(state):
            parts.append(
                f'<button type="button" data-filter="{_e(state)}" aria-pressed="false">'
                f"{_e(_STATE_LABEL[state])} ({_e(by_state[state])})</button>"
            )
    parts.append("</div>")

    for finding in findings:
        options = "".join(
            f'<option value="{_e(state)}"'
            f'{" selected" if finding["state"] == state else ""}>'
            f"{_e(_STATE_LABEL[state])}</option>"
            for state in STATES
        )
        repeat = f' · seen {finding["occurrences"]}x' if finding["occurrences"] > 1 else ""
        parts.append(
            f'<div class="finding {_e(finding["severity"])} '
            f'{_e(finding["state"]) if finding["state"] == "false_positive" else ""}" '
            f'data-severity="{_e(finding["severity"])}" data-state="{_e(finding["state"])}">'
            f'<div class="head"><span class="sev">{_e(finding["severity"])}</span>'
            f'<span class="what">{_e(finding["category"])} / {_e(finding["subtype"])}</span>'
            f'<span class="where">{_e(finding["confidence"])}% confidence{_e(repeat)}</span></div>'
            f'<p class="where">{_e(finding["employee"])} · '
            f'{_e(finding["location_kind"].replace("_", " "))} · '
            f'<code>{_e(finding["location"])}</code></p>'
            f'<p class="snippet">{_e(finding["snippet"])}</p>'
            f'<div class="triage">'
            f'<select data-finding="{_e(finding["finding_id"])}">{options}</select>'
            f'<span class="saved"></span></div>'
            f"</div>"
        )

    parts.append(
        "<footer>Triage is remembered across scans. Values are redacted here and "
        "in the store — the database never holds a raw secret. "
        "Delete everything with <code>leakscan purge --all</code>.</footer>"
    )
    parts.append("</main>")
    parts.append(f"<script>{_SCRIPT}</script>")
    parts.append("</body></html>")
    return "\n".join(parts)


class _Handler(BaseHTTPRequestHandler):
    store: Store  # set on the server class

    # Quiet by default: the access log would otherwise print locations, which
    # are the one part of a finding that says where a secret lives.
    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # The page is self-contained; forbid it fetching anything at all.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path)
        if route.path in ("/", "/index.html"):
            body = render_dashboard(self.server.store).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
        elif route.path == "/api/findings":
            query = parse_qs(route.query)
            scan = query.get("scan", [None])[0]
            findings = self.server.store.findings(int(scan) if scan else None)
            self._send(200, json.dumps(findings).encode("utf-8"), "application/json")
        elif route.path == "/api/trend":
            body = json.dumps(self.server.store.trend()).encode("utf-8")
            self._send(200, body, "application/json")
        else:
            self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/api/triage":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
            self.server.store.set_triage(
                str(payload["finding_id"]),
                str(payload["state"]),
                str(payload.get("note", "")),
            )
        except (ValueError, KeyError, TypeError) as exc:
            self._send(
                400, json.dumps({"error": str(exc)}).encode("utf-8"), "application/json"
            )
            return
        self._send(200, b'{"ok":true}', "application/json")


class _Server(HTTPServer):
    """Binds without a reverse name lookup, which the egress guard would refuse."""

    store: Store

    def server_bind(self) -> None:
        # HTTPServer.server_bind calls socket.getfqdn here purely to set
        # server_name. Skip it: we know the host, and a name lookup is exactly
        # what this tool promises not to do.
        super(HTTPServer, self).server_bind()
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


def serve(store: Store, port: int = 8787, host: str = "127.0.0.1") -> None:
    """Run the dashboard until interrupted. Loopback only."""
    handler = type("Handler", (_Handler,), {})
    server = _Server((host, port), handler)
    server.store = store
    print(f"Dashboard on http://{host}:{port}  (loopback only — Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
