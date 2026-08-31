"""Loading and validating rule packs.

A rule is a declaration, not code: a pattern, what it means, how bad it is, and
when it does *not* count. Keeping that in YAML is what lets a customer add their
own client names and project codenames — the one category no vendor can ship.

Two design points worth stating.

**Rules fail loudly.** A pack with a bad regex or a missing field raises at load
time rather than being skipped. A rule that silently never runs is a detection
gap that looks exactly like a clean result.

**Suppressors are first-class.** Precision matters more than recall here: a
report a compliance lead stops trusting is worth nothing. Every suppression is
counted, so a tuned-out category is visible rather than quietly missing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import PACKAGE_ROOT
from .records import KINDS
from .yamlite import YamlError, loads

__all__ = [
    "RULEPACK_DIR",
    "Rule",
    "Suppressor",
    "RuleSet",
    "RuleError",
    "load_pack",
    "load_rules",
]

RULEPACK_DIR = PACKAGE_ROOT / "rulepacks"

CATEGORIES = ("secret", "commercial", "pii", "special-category", "internal")
SEVERITIES = ("critical", "high", "medium", "low")
VALIDATORS = ("luhn", "none")


class RuleError(ValueError):
    """Raised when a rule pack is malformed."""


@dataclass(frozen=True, slots=True)
class Rule:
    """One detection."""

    id: str
    name: str
    category: str
    subtype: str
    severity: str
    confidence: int
    pattern: re.Pattern[str]
    #: Which record kinds this applies to. Empty means all of them.
    kinds: tuple[str, ...] = ()
    #: Capture group holding the value to report; 0 is the whole match.
    group: int = 0
    #: At least one of these must appear near the match for it to count. Used to
    #: keep loose patterns (a bare 40-char string) from firing on prose.
    requires_context: tuple[str, ...] = ()
    #: How far either side of the match to look for that context.
    context_window: int = 120
    #: Minimum Shannon entropy of the matched value, for catch-all rules.
    min_entropy: float = 0.0
    #: Extra arithmetic check: currently just the Luhn checksum for card numbers.
    validate: str = "none"
    #: Rule-local exceptions, tried against the matched value.
    ignore: tuple[re.Pattern[str], ...] = ()

    def applies_to(self, kind: str) -> bool:
        return not self.kinds or kind in self.kinds


@dataclass(frozen=True, slots=True)
class Suppressor:
    """A reason a match is *not* a finding."""

    id: str
    name: str
    pattern: re.Pattern[str]
    #: ``value`` tests the matched text; ``window`` tests the surrounding text,
    #: for cases where the giveaway is nearby ("reserved documentation values").
    scope: str = "value"
    #: Limit to particular categories; empty means all.
    categories: tuple[str, ...] = ()

    def covers(self, category: str) -> bool:
        return not self.categories or category in self.categories


@dataclass(slots=True)
class RuleSet:
    rules: list[Rule] = field(default_factory=list)
    suppressors: list[Suppressor] = field(default_factory=list)
    packs: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.rules)


def _require(mapping: dict, key: str, pack: str, rule_id: str):
    if key not in mapping or mapping[key] in (None, ""):
        raise RuleError(f"{pack}: rule {rule_id!r} is missing required field {key!r}")
    return mapping[key]


def _compile(pattern: str, pack: str, rule_id: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RuleError(f"{pack}: rule {rule_id!r} has an invalid pattern — {exc}") from exc


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _build_rule(raw: dict, pack: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError(f"{pack}: expected a mapping per rule, got {type(raw).__name__}")

    rule_id = str(raw.get("id") or "<unnamed>")
    category = str(_require(raw, "category", pack, rule_id))
    if category not in CATEGORIES:
        raise RuleError(f"{pack}: rule {rule_id!r} has unknown category {category!r}")
    severity = str(_require(raw, "severity", pack, rule_id))
    if severity not in SEVERITIES:
        raise RuleError(f"{pack}: rule {rule_id!r} has unknown severity {severity!r}")

    kinds = _as_tuple(raw.get("kinds"))
    for kind in kinds:
        if kind not in KINDS:
            raise RuleError(f"{pack}: rule {rule_id!r} names unknown record kind {kind!r}")

    validate = str(raw.get("validate") or "none")
    if validate not in VALIDATORS:
        raise RuleError(f"{pack}: rule {rule_id!r} has unknown validator {validate!r}")

    confidence = int(raw.get("confidence", 70))
    if not 0 <= confidence <= 100:
        raise RuleError(f"{pack}: rule {rule_id!r} confidence must be 0-100")

    return Rule(
        id=rule_id,
        name=str(_require(raw, "name", pack, rule_id)),
        category=category,
        subtype=str(_require(raw, "subtype", pack, rule_id)),
        severity=severity,
        confidence=confidence,
        pattern=_compile(str(_require(raw, "pattern", pack, rule_id)), pack, rule_id),
        kinds=kinds,
        group=int(raw.get("group", 0)),
        requires_context=_as_tuple(raw.get("requires_context")),
        context_window=int(raw.get("context_window", 120)),
        min_entropy=float(raw.get("min_entropy", 0.0)),
        validate=validate,
        ignore=tuple(_compile(str(p), pack, rule_id) for p in _as_tuple(raw.get("ignore"))),
    )


def _build_suppressor(raw: dict, pack: str) -> Suppressor:
    if not isinstance(raw, dict):
        raise RuleError(f"{pack}: expected a mapping per suppressor")
    rule_id = str(raw.get("id") or "<unnamed>")
    scope = str(raw.get("scope") or "value")
    if scope not in ("value", "window"):
        raise RuleError(f"{pack}: suppressor {rule_id!r} has unknown scope {scope!r}")
    return Suppressor(
        id=rule_id,
        name=str(_require(raw, "name", pack, rule_id)),
        pattern=_compile(str(_require(raw, "pattern", pack, rule_id)), pack, rule_id),
        scope=scope,
        categories=_as_tuple(raw.get("categories")),
    )


def load_pack(path: Path, into: RuleSet | None = None) -> RuleSet:
    """Load one ``.yaml`` rule pack."""
    result = into if into is not None else RuleSet()
    try:
        document = loads(path.read_text(encoding="utf-8"))
    except YamlError as exc:
        raise RuleError(f"{path.name}: {exc}") from exc
    except OSError as exc:
        raise RuleError(f"{path.name}: unreadable ({exc})") from exc

    if not isinstance(document, dict):
        raise RuleError(f"{path.name}: expected a mapping at the top level")

    pack = str(document.get("pack") or path.stem)
    seen = {rule.id for rule in result.rules}

    for raw in document.get("rules") or []:
        rule = _build_rule(raw, pack)
        if rule.id in seen:
            raise RuleError(f"{pack}: duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        result.rules.append(rule)

    for raw in document.get("suppress") or []:
        result.suppressors.append(_build_suppressor(raw, pack))

    result.packs.append(pack)
    return result


def load_rules(paths: list[Path] | None = None) -> RuleSet:
    """Load the bundled packs, or the ones given."""
    if paths is None:
        paths = sorted(RULEPACK_DIR.glob("*.yaml"))
    if not paths:
        raise RuleError(f"no rule packs found in {RULEPACK_DIR}")

    result = RuleSet()
    for path in paths:
        load_pack(Path(path), result)
    if not result.rules:
        raise RuleError("rule packs contained no rules")
    return result
