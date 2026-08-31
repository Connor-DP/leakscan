"""Tests for the detection engine, against the synthetic corpus.

Everything here runs on fabricated data — the invented keys, NI numbers and ARR
figures in ``corpus/build.py``. No real transcript is read.
"""

from __future__ import annotations

import json
import re
import unittest

from leakscan import adapters, detect, ingest, rules
from leakscan.records import Location, Record

from .support import REPO_ROOT

CORPUS_ZIP = REPO_ROOT / "corpus" / "synthetic-transcripts.zip"
CONTROL_EMPLOYEE = "sam.doyle"


def _corpus_secrets() -> list[str]:
    """The fabricated credential strings, taken from the corpus ground truth.

    Filtered to actual key material: marker lines like ``BEGIN RSA PRIVATE KEY``
    and URL prefixes are labelled as secrets but are not themselves sensitive,
    and a snippet may legitimately show them.
    """
    plants = json.loads(
        (REPO_ROOT / "corpus" / "expected.json").read_text(encoding="utf-8")
    )["findings"]
    return [
        plant["value"]
        for plant in plants
        if plant["category"] == "secret"
        and len(plant["value"]) >= 24
        and " " not in plant["value"]
        and not plant["value"].startswith("-----")
    ]


_CORPUS_SECRETS = _corpus_secrets()


def _record(text: str, kind: str = "tool_result", employee: str = "test.person") -> Record:
    return Record(
        employee=employee,
        session_id="s1",
        source="claude-code",
        kind=kind,
        text=text,
        location=Location("test/session.jsonl", 0, 0),
    )


class HelperTests(unittest.TestCase):
    def test_entropy_separates_random_from_repetitive(self) -> None:
        self.assertGreater(detect.entropy("hR7pQ2mZx9TfKd4LbN8vYcJ3sWe6UaGi"), 4.0)
        self.assertLess(detect.entropy("aaaaaaaaaaaaaaaaaaaaaaaa"), 1.0)
        self.assertEqual(detect.entropy(""), 0.0)

    def test_luhn(self) -> None:
        self.assertTrue(detect.luhn_valid("4539 5821 0043 7622"))
        self.assertFalse(detect.luhn_valid("4539 5821 0043 7621"))
        self.assertFalse(detect.luhn_valid("1234"))

    def test_redaction_keeps_only_the_edges(self) -> None:
        masked = detect.redact("sk_live_51QhZ8mKvRt3NpX7dLbYw2Ec9")
        self.assertTrue(masked.startswith("sk_l"))
        self.assertNotIn("QhZ8mKvRt3", masked)

    def test_short_values_are_fully_masked(self) -> None:
        self.assertEqual(detect.redact("abc123"), "******")


class CorpusDetectionTests(unittest.TestCase):
    """The headline behaviour: find the planted leaks, report nothing on the control."""

    @classmethod
    def setUpClass(cls) -> None:
        ruleset = rules.load_rules()
        records = []
        problems: list[str] = []
        for source in ingest.walk(CORPUS_ZIP).files:
            records.extend(adapters.parse_file(source, problems))
        cls.result = detect.Engine(ruleset).scan(records)
        cls.problems = problems

    def _subtypes(self, employee: str) -> set[str]:
        return {f.subtype for f in self.result.findings if f.employee == employee}

    def test_control_employee_yields_nothing(self) -> None:
        """Placeholders and test fixtures must not be reported.

        This is the test that matters most. A report containing
        `your-api-key-here` and Stripe's test card teaches its reader to skim,
        and after that the real critical finding goes unread.
        """
        noise = [f for f in self.result.findings if f.employee == CONTROL_EMPLOYEE]
        self.assertEqual(
            noise, [], f"false positives on the control: {[f.rule_id for f in noise]}"
        )

    def test_every_employee_with_planted_data_is_flagged(self) -> None:
        self.assertEqual(
            set(self.result.by_employee()),
            {"alice.chen", "ben.okafor", "priya.nair"},
        )

    def test_finds_the_credentials(self) -> None:
        found = self._subtypes("alice.chen")
        for subtype in (
            "aws_access_key_id",
            "anthropic_api_key",
            "stripe_live_key",
            "github_pat",
            "private_key_pem",
            "database_connection_string",
            "service_role_jwt",
            "slack_bot_token",
        ):
            with self.subTest(subtype=subtype):
                self.assertIn(subtype, found)

    def test_finds_the_commercial_data(self) -> None:
        found = self._subtypes("ben.okafor")
        # Deliberately sector-neutral: revenue, margins, contract values and
        # transactional documents exist in every industry. SaaS metrics do not.
        for subtype in (
            "revenue", "gross_margin", "client_contract_values", "discount_terms",
            "money_figure", "transactional_document", "contract", "restructuring_plan",
        ):
            with self.subTest(subtype=subtype):
                self.assertIn(subtype, found)

    def test_finds_personal_and_special_category_data(self) -> None:
        found = self._subtypes("priya.nair")
        for subtype in (
            "uk_ni_number",
            "bank_details",
            "payment_card",
            "iban",
            "health_condition",
            "criminal_record",
            "occupational_health",
        ):
            with self.subTest(subtype=subtype):
                self.assertIn(subtype, found)

    def test_bulk_export_is_flagged_as_its_own_finding(self) -> None:
        """Volume changes the meaning: a CSV of staff records is not a mention."""
        bulk = [f for f in self.result.findings if f.subtype == "bulk_personal_records"]
        self.assertTrue(bulk)
        self.assertEqual(bulk[0].severity, "critical")
        self.assertEqual(bulk[0].employee, "priya.nair")

    def test_tool_results_are_credited_as_the_source(self) -> None:
        """Most credentials arrived via tool output, not something anyone typed."""
        secrets = [f for f in self.result.findings if f.category == "secret"]
        from_tools = [f for f in secrets if f.kind == "tool_result"]
        self.assertGreater(len(from_tools), len(secrets) / 2)

    def test_noise_was_suppressed_and_counted(self) -> None:
        self.assertGreater(self.result.suppressed_total, 0)
        self.assertIn("noise.known_test_card", self.result.suppressed)

    def test_findings_are_ordered_by_severity(self) -> None:
        order = [detect._SEVERITY_ORDER[f.severity] for f in self.result.findings]
        self.assertEqual(order, sorted(order))

    def test_no_snippet_leaks_any_detected_value(self) -> None:
        """A snippet is a window of surrounding text — which in an .env dump is
        other credentials. None of them may appear in clear."""
        values = {
            f.value
            for f in self.result.findings
            if len(f.value) >= 12 and not f.descriptive
        }
        leaks = [
            f"{finding.rule_id} exposes {value[:16]}…"
            for finding in self.result.findings
            for value in values
            if value in finding.snippet
        ]
        self.assertEqual(leaks, [], f"snippets leaked values in clear: {leaks[:5]}")

    def test_parsing_the_corpus_produced_no_problems(self) -> None:
        self.assertEqual(self.problems, [])

    def test_no_snippet_leaks_a_fragment_of_a_neighbouring_secret(self) -> None:
        """Regression: the window cuts through the next credential along.

        An earlier version redacted by string replacement, so a value clipped by
        the 100-character window matched nothing and printed in clear. Half an
        API key in a forwarded report is still half an API key.
        """
        # Checked against the corpus's own fabricated credentials rather than
        # against every finding value: a finding's "value" may legitimately be a
        # marker line ("BEGIN RSA PRIVATE KEY") or a description, and neither is
        # key material. These nine are.
        secrets = _CORPUS_SECRETS
        self.assertGreaterEqual(len(secrets), 8, "corpus should carry several credentials")
        snippets = "\n".join(finding.snippet for finding in self.result.findings)
        leaks = [
            f"{secret[:8]}… leaked as {secret[start:start + 10]!r}"
            for secret in secrets
            for start in range(len(secret) - 10)
            if secret[start : start + 10] in snippets
        ]
        self.assertEqual(leaks, [], f"snippets leaked secret fragments: {leaks[:5]}")


class SuppressionTests(unittest.TestCase):
    """Each noise class, checked in isolation."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = detect.Engine(rules.load_rules())

    def _findings(self, text: str, kind: str = "tool_result") -> list[detect.Finding]:
        return self.engine.scan([_record(text, kind)]).findings

    def test_placeholder_values(self) -> None:
        self.assertEqual(self._findings("API_KEY=your-api-key-here\nPASSWORD=changeme"), [])

    def test_provider_documentation_example(self) -> None:
        self.assertEqual(self._findings("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"), [])

    def test_stripe_test_key(self) -> None:
        self.assertEqual(self._findings("STRIPE_KEY=sk_test_51ExampleTestKeyNotReal"), [])

    def test_reserved_test_card(self) -> None:
        self.assertEqual(self._findings("card = 4242 4242 4242 4242"), [])

    def test_reserved_ni_number_is_rejected_by_the_pattern(self) -> None:
        # QQ is not a valid NI prefix, so no suppressor is needed for it.
        self.assertEqual(self._findings("TEST_NI = 'QQ123456C'"), [])

    def test_example_domain_email(self) -> None:
        self.assertEqual(self._findings("CONTACT=user@example.com"), [])

    def test_template_placeholders(self) -> None:
        self.assertEqual(self._findings("API_TOKEN=${GITHUB_TOKEN}\nKEY=<your-key>"), [])

    def test_a_real_key_still_gets_through(self) -> None:
        """The counterpart to every test above: suppression must not swallow the real thing."""
        findings = self._findings("AWS_ACCESS_KEY_ID=AKIA4XZQ7MNPKD3RTBWV")
        self.assertEqual([f.subtype for f in findings], ["aws_access_key_id"])


class EngineBehaviourTests(unittest.TestCase):
    def test_repeats_collapse_into_one_finding_with_a_count(self) -> None:
        ruleset = rules.RuleSet(rules=[
            rules.Rule(
                id="t.v1", name="t", category="secret", subtype="t",
                severity="high", confidence=90, pattern=re.compile("SECRETVALUE"),
            )
        ])
        text = "SECRETVALUE\n" * 5
        result = detect.Engine(ruleset).scan([_record(text)])
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].occurrences, 5)

    def test_context_requirement_suppresses_a_loose_match(self) -> None:
        ruleset = rules.RuleSet(rules=[
            rules.Rule(
                id="t.v1", name="t", category="secret", subtype="t",
                severity="high", confidence=50, pattern=re.compile(r"\b[a-z0-9]{20,}\b"),
                requires_context=("token",),
            )
        ])
        engine = detect.Engine(ruleset)
        self.assertEqual(engine.scan([_record("abcdefghij0123456789")]).findings, [])
        self.assertEqual(len(engine.scan([_record("token: abcdefghij0123456789")]).findings), 1)

    def test_rules_can_be_limited_to_particular_locations(self) -> None:
        ruleset = rules.RuleSet(rules=[
            rules.Rule(
                id="t.v1", name="t", category="secret", subtype="t",
                severity="high", confidence=90, pattern=re.compile("NEEDLE"),
                kinds=("tool_result",),
            )
        ])
        engine = detect.Engine(ruleset)
        self.assertEqual(len(engine.scan([_record("NEEDLE", "tool_result")]).findings), 1)
        self.assertEqual(engine.scan([_record("NEEDLE", "user_message")]).findings, [])

    def test_scan_counts_what_it_read(self) -> None:
        result = detect.Engine(rules.load_rules()).scan([_record("nothing here"), _record("x")])
        self.assertEqual(result.records_scanned, 2)
        self.assertEqual(result.characters_scanned, len("nothing here") + 1)


if __name__ == "__main__":
    unittest.main()
