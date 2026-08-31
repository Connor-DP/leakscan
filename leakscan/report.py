"""Build the report: machine-readable JSON and a self-contained HTML page.

Three things govern everything here.

**The report is a second copy of the leak.** It lists exactly which credentials
exist and where, ranked and deduplicated — more useful to an attacker than the
transcripts it came from. So values are redacted unless ``--reveal`` is passed,
that choice is recorded *in the report itself*, and both files are created 0600
from the outset rather than chmod'ed afterwards.

**The HTML must not phone home.** Being opened from ``file://`` or localhost
restricts nothing outbound: one web-font ``<link>`` and the viewer's browser
announces to a third party that an audit report was opened, from which address
and when. Everything is inline — CSS, the small filter script, the SVG. No
fonts, no CDN, no images. :func:`leakscan.audit.audit_html` enforces it.

**Transcript content is untrusted input.** A snippet can contain anything a
person or a tool result put in front of an assistant, including ``<script>``.
Every value rendered into the page is escaped.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .detect import ScanResult, redact
from .ingest import Ingest
from .paths import ensure_private_dir, write_private_text
from .rules import RuleSet

__all__ = ["build_report", "render_html", "write_reports"]

_SEVERITIES = ("critical", "high", "medium", "low")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def build_report(
    result: ScanResult,
    walked: Ingest,
    ruleset: RuleSet,
    *,
    problems: list[str] | None = None,
    reveal: bool = False,
    started_at: str | None = None,
) -> dict:
    """Assemble the report structure. This is exactly what ``report.json`` holds."""
    problems = problems or []
    counts = result.by_employee()
    employees = sorted({source.employee for source in walked.files})

    employee_rows = []
    for name in employees:
        findings = [f for f in result.findings if f.employee == name]
        employee_rows.append({
            "employee": name,
            "findings": len(findings),
            "clean": not findings,
            "by_severity": {
                severity: sum(1 for f in findings if f.severity == severity)
                for severity in _SEVERITIES
                if any(f.severity == severity for f in findings)
            },
        })

    findings = []
    for finding in result.findings:
        entry = {
            "rule_id": finding.rule_id,
            "category": finding.category,
            "subtype": finding.subtype,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "employee": finding.employee,
            "session_id": finding.session_id,
            "source": finding.source,
            "location_kind": finding.kind,
            "location": finding.location,
            "occurrences": finding.occurrences,
            "also_at": list(finding.also_at),
            "value_redacted": redact(finding.value),
            "snippet": finding.snippet,
        }
        if reveal:
            entry["value"] = finding.value
        findings.append(entry)

    return {
        "tool": {
            "name": "transcript-leak-scanner",
            "version": __version__,
            "rule_packs": sorted(ruleset.packs),
            "rules": len(ruleset.rules),
            "suppressors": len(ruleset.suppressors),
        },
        "scan": {
            "root": walked.root,
            "started_at": started_at or _now(),
            "finished_at": _now(),
            # Recorded so a reader always knows whether they are holding a
            # redacted document or the leak itself.
            "redaction": "revealed" if reveal else "redacted",
            "files_parsed": len(walked.files),
            "files_skipped": len(walked.skipped),
            "records": result.records_scanned,
            "characters": result.characters_scanned,
        },
        "totals": {
            "findings": len(result.findings),
            "suppressed_as_noise": result.suppressed_total,
            "employees_scanned": len(employees),
            "employees_with_findings": len(counts),
            "by_severity": result.by_severity(),
            "by_category": result.by_category(),
            "by_employee": counts,
        },
        "employees": employee_rows,
        "findings": findings,
        "suppressed": dict(sorted(result.suppressed.items())),
        "skipped_files": [
            {"path": item.path, "reason": item.reason} for item in walked.skipped
        ],
        "parse_problems": problems,
        "caveat": (
            "A clean result is not proof that nothing leaked. Detection is "
            "best-effort and measured against a synthetic corpus; treat findings "
            "as leads, not as an exhaustive inventory."
        ),
    }


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --panel: #f6f7f9;
  --border: #d9dde3;
  --text: #14181d;
  --muted: #5b6572;
  --critical: #a4232b;
  --high: #a35207;
  --medium: #1f5c8b;
  --low: #55606e;
  --warn-bg: #fdf3d8;
  --warn-border: #d9a441;
  --warn-text: #5c4209;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14181d;
    --panel: #1c2229;
    --border: #303841;
    --text: #e8ebee;
    --muted: #9aa4b1;
    --critical: #f08b8b;
    --high: #e5ab63;
    --medium: #7cb8e0;
    --low: #97a3b1;
    --warn-bg: #322a12;
    --warn-border: #8a6b21;
    --warn-text: #f0dca6;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 32px 24px 64px;
  background: var(--bg); color: var(--text);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -0.01em; }
h2 { font-size: 17px; margin: 40px 0 12px; letter-spacing: -0.01em; }
.sub { color: var(--muted); font-size: 13px; margin: 0 0 4px; }
.meta { color: var(--muted); font-size: 13px; margin: 12px 0 0; }
.meta code { font-size: 12px; word-break: break-all; }
.warn {
  margin: 20px 0 0; padding: 12px 14px; border-radius: 6px;
  background: var(--warn-bg); border: 1px solid var(--warn-border); color: var(--warn-text);
  font-size: 14px;
}
.tiles { display: flex; flex-wrap: wrap; gap: 10px; margin: 24px 0 0; }
.tile {
  flex: 1 1 150px; padding: 14px 16px; border-radius: 8px;
  background: var(--panel); border: 1px solid var(--border);
}
.tile .n { font-size: 26px; font-weight: 600; letter-spacing: -0.02em; }
.tile .l { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); }
th { font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.clean { color: var(--muted); }
.finding {
  border: 1px solid var(--border); border-left: 3px solid var(--border);
  border-radius: 6px; padding: 12px 14px; margin: 0 0 8px; background: var(--panel);
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.head { display: flex; flex-wrap: wrap; gap: 8px; align-items: baseline; }
.sev { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
.critical .sev { color: var(--critical); }
.high .sev { color: var(--high); }
.medium .sev { color: var(--medium); }
.low .sev { color: var(--low); }
.what { font-weight: 600; }
.where { color: var(--muted); font-size: 12.5px; margin: 4px 0 0; word-break: break-all; }
.snippet {
  margin: 8px 0 0; padding: 8px 10px; border-radius: 4px;
  background: var(--bg); border: 1px solid var(--border);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12.5px; white-space: pre-wrap; word-break: break-word;
}
.controls { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 14px; }
.controls button {
  font: inherit; font-size: 13px; padding: 5px 12px; cursor: pointer;
  border-radius: 999px; border: 1px solid var(--border);
  background: var(--panel); color: var(--text);
}
.controls button[aria-pressed="true"] { background: var(--text); color: var(--bg); border-color: var(--text); }
details { margin: 0 0 8px; }
summary { cursor: pointer; font-size: 14px; }
ul.plain { margin: 8px 0 0; padding-left: 18px; font-size: 13.5px; color: var(--muted); }
footer { margin: 48px 0 0; padding: 16px 0 0; border-top: 1px solid var(--border);
         color: var(--muted); font-size: 13px; }
"""

_SCRIPT = """
(function () {
  var buttons = document.querySelectorAll('.controls button');
  var findings = document.querySelectorAll('.finding');
  function apply(value) {
    findings.forEach(function (el) {
      el.hidden = value !== 'all' && el.dataset.severity !== value;
    });
    buttons.forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.dataset.filter === value));
    });
  }
  buttons.forEach(function (b) {
    b.addEventListener('click', function () { apply(b.dataset.filter); });
  });
})();
"""


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _tile(number, label) -> str:
    return f'<div class="tile"><div class="n">{_e(number)}</div><div class="l">{_e(label)}</div></div>'


def render_html(report: dict) -> str:
    """Render the report as one self-contained HTML page."""
    scan = report["scan"]
    totals = report["totals"]
    revealed = scan["redaction"] == "revealed"

    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Transcript leak report</title>",
        f"<style>{_STYLE}</style>",
        "</head><body><main>",
        "<h1>Transcript leak report</h1>",
        f'<p class="sub">{_e(totals["findings"])} findings across '
        f'{_e(totals["employees_scanned"])} people · {_e(scan["finished_at"])}</p>',
    ]

    if revealed:
        parts.append(
            '<p class="warn"><strong>Unredacted report.</strong> This was generated '
            "with <code>--reveal</code>, so it contains the leaked values in clear. "
            "It is as sensitive as the transcripts it came from: store it "
            "accordingly and delete it when you are done.</p>"
        )

    parts.append('<div class="tiles">')
    parts.append(_tile(totals["findings"], "findings"))
    parts.append(_tile(totals["by_severity"].get("critical", 0), "critical"))
    parts.append(_tile(
        f'{totals["employees_with_findings"]}/{totals["employees_scanned"]}',
        "people affected",
    ))
    parts.append(_tile(totals["suppressed_as_noise"], "suppressed as noise"))
    parts.append("</div>")

    parts.append(
        f'<p class="meta">Scanned <code>{_e(scan["root"])}</code> — '
        f'{_e(scan["files_parsed"])} files, {_e(scan["records"])} records, '
        f'{scan["characters"]:,} characters. '
        f'{_e(report["tool"]["rules"])} rules across '
        f'{_e(", ".join(report["tool"]["rule_packs"]))}. '
        f'Values are {"shown in clear" if revealed else "redacted"}.</p>'
    )

    # -- people ------------------------------------------------------------
    parts.append("<h2>By person</h2><div class=\"scroll\"><table>")
    parts.append(
        "<thead><tr><th>Person</th><th class='num'>Findings</th>"
        + "".join(f"<th class='num'>{_e(s.title())}</th>" for s in _SEVERITIES)
        + "</tr></thead><tbody>"
    )
    for row in sorted(report["employees"], key=lambda r: (-r["findings"], r["employee"])):
        cells = "".join(
            f"<td class='num'>{_e(row['by_severity'].get(s, 0)) if row['by_severity'].get(s) else '·'}</td>"
            for s in _SEVERITIES
        )
        clean = ' class="clean"' if row["clean"] else ""
        label = _e(row["employee"]) + ("" if not row["clean"] else " — nothing found")
        parts.append(
            f"<tr{clean}><td>{label}</td><td class='num'>{_e(row['findings'])}</td>{cells}</tr>"
        )
    parts.append("</tbody></table></div>")

    # -- findings ----------------------------------------------------------
    parts.append("<h2>Findings</h2>")
    if report["findings"]:
        parts.append('<div class="controls">')
        parts.append('<button type="button" data-filter="all" aria-pressed="true">All</button>')
        for severity in _SEVERITIES:
            count = totals["by_severity"].get(severity, 0)
            if count:
                parts.append(
                    f'<button type="button" data-filter="{_e(severity)}" aria-pressed="false">'
                    f"{_e(severity.title())} ({_e(count)})</button>"
                )
        parts.append("</div>")

        for finding in report["findings"]:
            repeat = (
                f" · seen {finding['occurrences']}×"
                if finding["occurrences"] > 1
                else ""
            )
            value_line = ""
            if "value" in finding:
                value_line = (
                    f'<p class="snippet"><strong>Value:</strong> {_e(finding["value"])}</p>'
                )
            parts.append(
                f'<div class="finding {_e(finding["severity"])}" '
                f'data-severity="{_e(finding["severity"])}">'
                f'<div class="head"><span class="sev">{_e(finding["severity"])}</span>'
                f'<span class="what">{_e(finding["category"])} / {_e(finding["subtype"])}</span>'
                f'<span class="where">{_e(finding["confidence"])}% confidence{_e(repeat)}</span></div>'
                f'<p class="where">{_e(finding["employee"])} · '
                f'{_e(finding["location_kind"].replace("_", " "))} · '
                f'<code>{_e(finding["location"])}</code></p>'
                f'<p class="snippet">{_e(finding["snippet"])}</p>'
                f"{value_line}</div>"
            )
    else:
        parts.append("<p>No findings.</p>")

    # -- what was not scanned ---------------------------------------------
    if report["skipped_files"] or report["parse_problems"] or report["suppressed"]:
        parts.append("<h2>Scan quality</h2>")
        if report["suppressed"]:
            total = sum(report["suppressed"].values())
            parts.append(
                f"<details><summary>{_e(total)} matches suppressed as noise</summary>"
                "<ul class='plain'>"
                + "".join(
                    f"<li>{_e(name)} — {_e(count)}</li>"
                    for name, count in report["suppressed"].items()
                )
                + "</ul></details>"
            )
        if report["skipped_files"]:
            parts.append(
                f"<details><summary>{_e(len(report['skipped_files']))} files skipped</summary>"
                "<ul class='plain'>"
                + "".join(
                    f"<li>{_e(item['path'])} — {_e(item['reason'])}</li>"
                    for item in report["skipped_files"]
                )
                + "</ul></details>"
            )
        if report["parse_problems"]:
            parts.append(
                f"<details><summary>{_e(len(report['parse_problems']))} parse problems</summary>"
                "<ul class='plain'>"
                + "".join(f"<li>{_e(item)}</li>" for item in report["parse_problems"])
                + "</ul></details>"
            )

    parts.append(f"<footer>{_e(report['caveat'])}</footer>")
    parts.append("</main>")
    parts.append(f"<script>{_SCRIPT}</script>")
    parts.append("</body></html>")
    return "\n".join(parts)


def write_reports(report: dict, output_dir: Path) -> list[Path]:
    """Write ``report.json`` and ``report.html``, owner-readable only."""
    directory = ensure_private_dir(Path(output_dir))
    written = [
        write_private_text(
            directory / "report.json",
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        ),
        write_private_text(directory / "report.html", render_html(report)),
    ]
    return written
