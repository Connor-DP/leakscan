"""Command-line entry point.

The egress guard is installed before arguments are even parsed, so no code path
— including a mistyped command — runs with the network reachable. There is
deliberately no flag to disable it.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from . import (
    adapters,
    dashboard,
    detect,
    ingest,
    netguard,
    report,
    rules,
    selfcheck,
    store as store_module,
    survey,
)
from .paths import default_output_dir

__all__ = ["build_parser", "main"]

_SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def _run_scan(args: argparse.Namespace) -> int:
    started = report._now()
    try:
        ruleset = rules.load_rules([Path(p) for p in args.rules] if args.rules else None)
    except rules.RuleError as exc:
        print(f"Rule pack error: {exc}")
        return 2

    walked = ingest.walk(Path(args.input))
    if not walked.files:
        print(f"No transcripts found in {args.input}.")
        for item in walked.skipped:
            print(f"  skipped {item.path} — {item.reason}")
        return 1

    problems: list[str] = []
    records = []
    for source in walked.files:
        records.extend(adapters.parse_file(source, problems))

    result = detect.Engine(ruleset).scan(records)
    counts = result.by_employee()

    print(f"Scanned:    {walked.root}")
    print(f"Rules:      {len(ruleset.rules)} across {len(ruleset.packs)} packs")
    print(
        f"Parsed:     {len(walked.files)} files, {result.records_scanned} records "
        f"({result.characters_scanned:,} characters)"
    )
    print(f"Findings:   {len(result.findings)}  ({result.suppressed_total} suppressed as noise)")

    if result.findings:
        severities = result.by_severity()
        print(
            "            "
            + " · ".join(
                f"{_SEVERITY_LABEL[name]} {severities[name]}"
                for name in ("critical", "high", "medium", "low")
                if name in severities
            )
        )

    print()
    for employee, count in sorted(counts.items(), key=lambda item: -item[1]):
        print(f"  {employee:<16} {count:>3} findings")
    # An employee with nothing is a result worth printing, not an absence.
    for employee in sorted({s.employee for s in walked.files} - set(counts)):
        print(f"  {employee:<16}   0 findings")

    shown = result.findings if args.all else result.findings[: args.limit]
    if shown:
        print(f"\nShowing {len(shown)} of {len(result.findings)} findings:\n")
        for finding in shown:
            marker = f"[{_SEVERITY_LABEL[finding.severity]}]"
            repeat = f" x{finding.occurrences}" if finding.occurrences > 1 else ""
            print(f"{marker:<11} {finding.category}/{finding.subtype}{repeat}")
            print(f"            {finding.employee} · {finding.kind} · {finding.location}")
            print(f"            {finding.snippet[:100]}")
            print()

    if problems:
        print(f"Parse problems ({len(problems)}):")
        for problem in problems[:10]:
            print(f"  {problem}")
        print()

    document = report.build_report(
        result, walked, ruleset, problems=problems, reveal=args.reveal, started_at=started
    )
    written = report.write_reports(document, Path(args.output_dir))
    store = store_module.Store(Path(args.output_dir) / store_module.DEFAULT_DB_NAME)
    scan_id = store.record_scan(document, result.findings)

    print("Report written:")
    for path in written:
        print(f"  {path}")
    print(f"  stored as scan #{scan_id} in {store.path.name}")
    print("  browse and triage it with: leakscan serve")

    if args.reveal:
        print(
            "\n  ! --reveal was used: the report contains the leaked values in "
            "clear.\n    It is as sensitive as the transcripts. Delete it when done."
        )
    else:
        print("\n  Values are redacted. Re-run with --reveal to include them.")
    return 0


def _run_inspect(args: argparse.Namespace) -> int:
    result = survey.survey(Path(args.input))
    print(survey.format_survey(result))
    if not result.files:
        print("\nNothing was parsed. Check the path, or that the ZIP contains transcripts.")
        return 1
    return 0


def _store_for(args: argparse.Namespace) -> store_module.Store:
    return store_module.Store(Path(args.output_dir) / store_module.DEFAULT_DB_NAME)


def _run_serve(args: argparse.Namespace) -> int:
    store = _store_for(args)
    if store.latest_scan_id() is None:
        print("No scans stored yet. Run 'leakscan scan <path>' first.")
        return 1
    dashboard.serve(store, port=args.port)
    return 0


def _run_purge(args: argparse.Namespace) -> int:
    if not (args.all or args.scan or args.employee):
        print("Nothing selected. Pass --all, --scan ID, or --employee NAME.")
        return 2

    store = _store_for(args)
    result = store.purge(
        everything=args.all,
        scan_id=int(args.scan) if args.scan else None,
        employee=args.employee,
        output_dir=Path(args.output_dir),
    )

    if not result.anything:
        print("Nothing to delete.")
        return 0

    print(
        f"Deleted {result.findings} findings, {result.scans} scans, "
        f"{result.triage} triage records."
    )
    for path in result.files:
        print(f"  removed {path}")
    print("Database vacuumed: the freed pages have been rewritten.")
    print(
        "This cannot reach a backup, snapshot or Time Machine copy that already ran."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakscan",
        description=(
            "Scan AI-assistant session transcripts for leaked PII, secrets and "
            "confidential data. Runs entirely offline; nothing it reads leaves "
            "this host."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan", help="scan a ZIP or directory of transcripts and write a report"
    )
    scan.add_argument(
        "input", help="path to a transcripts ZIP, or a directory of them"
    )
    scan.add_argument(
        "-o",
        "--output-dir",
        default=str(default_output_dir()),
        help="where to write the report (default: ./output)",
    )
    scan.add_argument(
        "--rules",
        action="append",
        default=None,
        metavar="PACK",
        help="YAML rule pack to load; repeatable (default: the bundled packs)",
    )
    scan.add_argument(
        "--reveal",
        action="store_true",
        help=(
            "write matched values unredacted. The report then contains the "
            "leaked data itself; use of this flag is recorded in the report."
        ),
    )
    scan.add_argument(
        "--limit", type=int, default=10, help="how many findings to print (default: 10)"
    )
    scan.add_argument("--all", action="store_true", help="print every finding")
    scan.set_defaults(func=_run_scan)

    serve = subparsers.add_parser(
        "serve", help="browse findings in a local dashboard (loopback only)"
    )
    serve.add_argument("--port", type=int, default=8787, help="default: 8787")
    serve.add_argument(
        "-o", "--output-dir", default=str(default_output_dir()),
        help="where the findings store lives (default: ./output)",
    )
    serve.set_defaults(func=_run_serve)

    purge = subparsers.add_parser(
        "purge", help="permanently delete stored findings and reports"
    )
    purge.add_argument("--all", action="store_true", help="delete every scan")
    purge.add_argument("--scan", metavar="ID", help="delete one scan by id")
    purge.add_argument("--employee", metavar="NAME", help="delete one employee's findings")
    purge.add_argument(
        "-o", "--output-dir", default=str(default_output_dir()),
        help="where the findings store lives (default: ./output)",
    )
    purge.set_defaults(func=_run_purge)

    inspect = subparsers.add_parser(
        "inspect",
        help="parse transcripts and report what was understood — no detection",
        description=(
            "Walks a ZIP or directory, parses every transcript, and prints what "
            "came out: records by location, per employee, plus anything skipped "
            "or unparseable. Run this before trusting a scan — 'no findings' "
            "means nothing if the files were never read."
        ),
    )
    inspect.add_argument("input", help="path to a transcripts ZIP, or a directory")
    inspect.set_defaults(func=_run_inspect)

    check = subparsers.add_parser(
        "selfcheck", help="verify the offline guarantee (runtime guard + source audit)"
    )
    check.set_defaults(func=lambda args: selfcheck.run())

    return parser


def main(argv: list[str] | None = None) -> int:
    netguard.install()
    args = build_parser().parse_args(argv)
    return args.func(args)
