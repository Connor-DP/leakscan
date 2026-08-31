"""The offline self-check: prove the privacy invariant before trusting a scan.

Runs two independent checks and fails loudly if either does:

* the **runtime** guard actually refuses outbound connections and DNS
  (:func:`leakscan.netguard.self_test`), and
* the **source** contains no import capable of egress or of executing another
  program (:func:`leakscan.audit.audit_source`).

Run it whenever you want the guarantee re-established — before an audit, after
an upgrade, or as the first step of a scan.
"""

from __future__ import annotations

from . import PACKAGE_ROOT
from .audit import audit_source
from .netguard import self_test

__all__ = ["run"]

_PASS = "PASS"
_FAIL = "FAIL"


def run(*, verbose: bool = True) -> int:
    """Run every check. Returns a process exit code: 0 all passed, 1 otherwise."""
    failures = 0
    lines: list[str] = ["Runtime egress guard"]

    for name, passed, detail in self_test():
        failures += 0 if passed else 1
        lines.append(f"  [{_PASS if passed else _FAIL}] {name} — {detail}")

    lines.append("")
    lines.append("Source audit")
    violations = audit_source(PACKAGE_ROOT)
    if violations:
        failures += len(violations)
        for violation in violations:
            lines.append(f"  [{_FAIL}] {violation}")
    else:
        lines.append(f"  [{_PASS}] no forbidden imports in {PACKAGE_ROOT.name}/")

    lines.append("")
    if failures:
        lines.append(
            f"{failures} check(s) FAILED — do not scan real transcripts until "
            f"this is resolved."
        )
    else:
        lines.append("All checks passed. Nothing this tool reads can leave the host.")

    if verbose:
        print("\n".join(lines))

    return 1 if failures else 0
