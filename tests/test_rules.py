"""Tests for rule pack loading and validation."""

from __future__ import annotations

import unittest
from pathlib import Path

from leakscan import rules

from .support import ProjectTempDir

VALID = """
pack: test
rules:
  - id: test.thing.v1
    name: A thing
    category: secret
    subtype: thing
    severity: high
    confidence: 90
    pattern: 'abc'
"""


class BundledPackTests(unittest.TestCase):
    """The shipped packs must load, or the product does nothing."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ruleset = rules.load_rules()

    def test_all_packs_load(self) -> None:
        self.assertEqual(
            sorted(self.ruleset.packs),
            ["commercial", "internal", "noise", "pii", "secrets"],
        )

    def test_every_category_is_covered(self) -> None:
        categories = {rule.category for rule in self.ruleset.rules}
        self.assertEqual(set(rules.CATEGORIES), categories)

    def test_rule_ids_are_unique(self) -> None:
        ids = [rule.id for rule in self.ruleset.rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_suppressors_exist(self) -> None:
        self.assertGreater(len(self.ruleset.suppressors), 5)


class ValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = ProjectTempDir()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _load(self, text: str) -> rules.RuleSet:
        path = self.root / "pack.yaml"
        path.write_text(text, encoding="utf-8")
        return rules.load_pack(path)

    def test_valid_pack_loads(self) -> None:
        ruleset = self._load(VALID)
        self.assertEqual(len(ruleset.rules), 1)
        self.assertEqual(ruleset.rules[0].id, "test.thing.v1")

    def test_invalid_regex_is_refused(self) -> None:
        with self.assertRaises(rules.RuleError) as caught:
            self._load(VALID.replace("pattern: 'abc'", "pattern: '[unclosed'"))
        self.assertIn("invalid pattern", str(caught.exception))

    def test_missing_field_is_refused(self) -> None:
        with self.assertRaises(rules.RuleError) as caught:
            self._load(VALID.replace("    subtype: thing\n", ""))
        self.assertIn("subtype", str(caught.exception))

    def test_unknown_category_is_refused(self) -> None:
        with self.assertRaises(rules.RuleError):
            self._load(VALID.replace("category: secret", "category: nonsense"))

    def test_unknown_severity_is_refused(self) -> None:
        with self.assertRaises(rules.RuleError):
            self._load(VALID.replace("severity: high", "severity: apocalyptic"))

    def test_unknown_record_kind_is_refused(self) -> None:
        with self.assertRaises(rules.RuleError) as caught:
            self._load(VALID + "    kinds: [tool_result, telepathy]\n")
        self.assertIn("record kind", str(caught.exception))

    def test_duplicate_rule_id_is_refused(self) -> None:
        doubled = VALID + VALID.split("rules:")[1]
        with self.assertRaises(rules.RuleError) as caught:
            self._load(doubled)
        self.assertIn("duplicate rule id", str(caught.exception))

    def test_confidence_range_is_enforced(self) -> None:
        with self.assertRaises(rules.RuleError):
            self._load(VALID.replace("confidence: 90", "confidence: 900"))

    def test_bad_yaml_is_refused_with_context(self) -> None:
        with self.assertRaises(rules.RuleError) as caught:
            self._load("pack: test\nrules: {a: 1}\n")
        self.assertIn("pack.yaml", str(caught.exception))


class RuleBehaviourTests(unittest.TestCase):
    def test_empty_kinds_means_all_kinds(self) -> None:
        rule = rules.Rule(
            id="x", name="x", category="secret", subtype="x", severity="low",
            confidence=50, pattern=rules.re.compile("x"),
        )
        self.assertTrue(rule.applies_to("tool_result"))
        self.assertTrue(rule.applies_to("user_message"))

    def test_kinds_restrict(self) -> None:
        rule = rules.Rule(
            id="x", name="x", category="secret", subtype="x", severity="low",
            confidence=50, pattern=rules.re.compile("x"), kinds=("tool_result",),
        )
        self.assertTrue(rule.applies_to("tool_result"))
        self.assertFalse(rule.applies_to("user_message"))


if __name__ == "__main__":
    unittest.main()
