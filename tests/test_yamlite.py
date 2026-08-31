"""Tests for the YAML subset loader.

The loader's job is to be predictable and to refuse anything it does not
genuinely support, because a rule pack that parses differently from what its
author meant is a detection that silently never fires.
"""

from __future__ import annotations

import unittest

from leakscan.yamlite import YamlError, loads


class ScalarTests(unittest.TestCase):
    def test_types(self) -> None:
        document = loads(
            "text: hello\n"
            "number: 42\n"
            "decimal: 3.5\n"
            "yes_value: true\n"
            "no_value: false\n"
            "nothing: null\n"
            "tilde: ~\n"
        )
        self.assertEqual(
            document,
            {
                "text": "hello",
                "number": 42,
                "decimal": 3.5,
                "yes_value": True,
                "no_value": False,
                "nothing": None,
                "tilde": None,
            },
        )

    def test_single_quotes_keep_backslashes_literal(self) -> None:
        # The reason rule patterns are single-quoted.
        document = loads(r"pattern: '\b[A-Z]{2}\d{6}\s?[A-D]\b'")
        self.assertEqual(document["pattern"], r"\b[A-Z]{2}\d{6}\s?[A-D]\b")

    def test_escaped_single_quote(self) -> None:
        self.assertEqual(loads("p: 'it''s here'")["p"], "it's here")

    def test_double_quotes_process_escapes(self) -> None:
        self.assertEqual(loads('p: "a\\tb"')["p"], "a\tb")

    def test_colon_inside_quoted_value(self) -> None:
        self.assertEqual(loads("p: 'https://example.com/x'")["p"], "https://example.com/x")

    def test_hash_inside_quotes_is_not_a_comment(self) -> None:
        self.assertEqual(loads("p: 'a # b'  # trailing")["p"], "a # b")


class StructureTests(unittest.TestCase):
    def test_nested_mapping(self) -> None:
        document = loads("outer:\n  inner:\n    leaf: 1\n")
        self.assertEqual(document, {"outer": {"inner": {"leaf": 1}}})

    def test_sequence_of_scalars(self) -> None:
        self.assertEqual(loads("items:\n  - a\n  - b\n"), {"items": ["a", "b"]})

    def test_sequence_at_key_indentation(self) -> None:
        self.assertEqual(loads("items:\n- a\n- b\n"), {"items": ["a", "b"]})

    def test_inline_sequence(self) -> None:
        self.assertEqual(loads("kinds: [tool_result, user_message]")["kinds"],
                         ["tool_result", "user_message"])

    def test_inline_sequence_respects_quoted_commas(self) -> None:
        self.assertEqual(loads("k: ['a, b', c]")["k"], ["a, b", "c"])

    def test_sequence_of_mappings(self) -> None:
        document = loads(
            "rules:\n"
            "  - id: one\n"
            "    severity: high\n"
            "  - id: two\n"
            "    severity: low\n"
        )
        self.assertEqual(
            document["rules"],
            [{"id": "one", "severity": "high"}, {"id": "two", "severity": "low"}],
        )

    def test_nested_list_inside_sequence_item(self) -> None:
        document = loads(
            "rules:\n"
            "  - id: one\n"
            "    requires_context:\n"
            "      - key\n"
            "      - token\n"
        )
        self.assertEqual(document["rules"][0]["requires_context"], ["key", "token"])

    def test_comments_and_blank_lines_ignored(self) -> None:
        document = loads("# header\n\na: 1\n\n# note\nb: 2\n")
        self.assertEqual(document, {"a": 1, "b": 2})

    def test_empty_document(self) -> None:
        self.assertIsNone(loads("# nothing but a comment\n"))


class StrictnessTests(unittest.TestCase):
    """Unsupported syntax must raise, never parse into something unintended."""

    def test_tabs_rejected(self) -> None:
        with self.assertRaises(YamlError):
            loads("a:\n\tb: 1\n")

    def test_flow_mapping_rejected(self) -> None:
        with self.assertRaises(YamlError) as caught:
            loads("a: {b: 1}")
        self.assertIn("flow mappings", str(caught.exception))

    def test_block_scalar_rejected(self) -> None:
        with self.assertRaises(YamlError) as caught:
            loads("a: |\n  text\n")
        self.assertIn("block scalars", str(caught.exception))

    def test_duplicate_key_rejected(self) -> None:
        with self.assertRaises(YamlError) as caught:
            loads("a: 1\na: 2\n")
        self.assertIn("duplicate key", str(caught.exception))

    def test_unterminated_quote_rejected(self) -> None:
        with self.assertRaises(YamlError):
            loads("a: 'unclosed\n")

    def test_error_reports_a_line_number(self) -> None:
        with self.assertRaises(YamlError) as caught:
            loads("a: 1\nb: {c: 2}\n")
        self.assertEqual(caught.exception.line, 2)


if __name__ == "__main__":
    unittest.main()
