#!/usr/bin/env python3
"""Generate the synthetic transcript corpus.

Everything in here is **fabricated**. The people, the employer, the clients, the
figures and every credential are invented for testing. No value was copied from
a real transcript, a real system, or a real person.

The corpus exists so the detection engine can be measured rather than guessed
at. Each planted item carries a label, and this script emits those labels to
``expected.json`` alongside the ZIP — so the ground truth cannot drift away from
the data it describes, because both come from this one file.

Four employees, chosen to cover the four detection families plus the case that
matters most for trust:

* ``alice.chen``  — engineer. Secrets and credentials, mostly arriving via tool
  results rather than anything she typed.
* ``ben.okafor``  — commercial and finance, deliberately sector-neutral:
  management accounts, an invoice run, a client contract schedule, tender
  pricing under NDA. Nothing here is specific to software, so a reader from
  a law firm or a haulier recognises their own week. Claude Desktop format.
* ``priya.nair``  — HR. Personal data including special-category health and
  criminal-record material.
* ``sam.doyle``   — the control. Placeholders, documentation examples and test
  fixtures only. **Expected findings: zero.** If the engine reports anything
  here, it is producing exactly the noise that makes a report untrustworthy.

Usage::

    python3 corpus/build.py             # write the ZIP and expected.json
    python3 corpus/build.py --extract   # also write a readable tree to corpus/src/
"""

from __future__ import annotations

import argparse
import base64
import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent
ZIP_PATH = CORPUS_DIR / "synthetic-transcripts.zip"
EXPECTED_PATH = CORPUS_DIR / "expected.json"
SRC_DIR = CORPUS_DIR / "src"

#: Fixed so the ZIP is byte-identical on every run.
BASE_TIMESTAMP = "2026-07-14T09:00:00.000Z"
ZIP_DATE_TIME = (2026, 7, 14, 9, 0, 0)


def _timestamp(index: int) -> str:
    """A deterministic, plausible timestamp: one minute per record."""
    minute = 9 * 60 + index
    return f"2026-07-14T{minute // 60:02d}:{minute % 60:02d}:00.000Z"


# --------------------------------------------------------------------------
# Fabricated values
# --------------------------------------------------------------------------
# Shaped like the real thing so the pattern rules get a fair test, but every
# one is invented. Key material is random text, not a revoked or example key
# from a provider's docs — those live in the NOISE section instead, where they
# belong, because a scanner must not report them.

FAKE = {
    "aws_key_id": "AKIA4XZQ7MNPKD3RTBWV",
    "aws_secret": "hR7pQ2mZx9TfKd4LbN8vYcJ3sWe6UaGi5oPqRt1X",
    "anthropic": "sk-ant-api03-Xk7Rm2Qp9Lv4Nb8Tz6Wc3Yh1Jd5Fg0Sa2Ue7Ir9Ot4Ay6Ep8Uw",
    "stripe_live": "sk_live_51QhZ8mKvRt3NpX7dLbYw2Ec9FgHjKlMnBvCxZaQwErTy",
    "github_pat": "ghp_9KdLm2QxTr7VbN4pZa8Wc3Ye6Uh1Jf0Sg5Dh",
    "slack_bot": "xoxb-2847391056-4193827465-Kd7Lm2QxTr9VbN4pZa8Wc3Ye",
    "supabase": "sbp_7f3c9a1e4b8d2650fa93c7e5b1d84a6029f3e7c1",
    "mailgun": "key-9f3c2a7e15b8d460ca93f7e2b1d84a60",
    "sentry_dsn": "https://4b8d2650fa93c7e5b1d84a60@o447951.ingest.sentry.io/5428192",
    "postgres": (
        "postgresql://app_user:Tr7VbN4pZa8Wc3@"
        "db-prod-01.internal.meridiansystems.co.uk:5432/meridian_prod"
    ),
    # Fabricated JWT carrying role=service_role — the shape that should score
    # Critical, since it bypasses row-level security and does not expire soon.
    "service_jwt": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJleHAiOjIwNTM0NTYwMDB9."
        "Kd7Lm2QxTr9VbN4pZa8Wc3Ye6Uh1Jf0Sg5DhX2mZ"
    ),
    "pem": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAxK7Rm2Qp9Lv4Nb8Tz6Wc3Yh1Jd5Fg0Sa2Ue7Ir9Ot4Ay6Ep\n"
        "8UwQz3Xv5Bn7Cm2Kd9Lf4Hg6Jt1Rs8Wy0Pq3Zx5Vb7Nc2Md4Kf6Lh8Jg0Ts2Rw\n"
        "4Yv6Bx8Nz0Cq2Ke4Lg6Mh8Ji0Rt2Sw4Uy6Vz8Xa0Cb2Dd4Ef6Gh8Ij0Kl2Mn4\n"
        "-----END RSA PRIVATE KEY-----"
    ),
    # Personal data — invented identifiers in valid formats.
    "ni_hartley": "JT602491A",
    "ni_okonkwo": "SN284719C",
    "nhs": "943 476 5919",
    "sort_code": "40-27-15",
    "account_no": "81234567",
    "iban": "GB17 MIDL 4025 1912 3456 78",
    "card": "4539 5821 0043 7622",  # Luhn-valid, issued to nobody
    "dob": "14 March 1989",
    "postcode": "M20 4XT",
    "address": "42 Beechfield Road, Manchester, M20 4XT",
    "phone": "07700 900184",  # Ofcom drama-reserved range
}

#: Values a scanner MUST NOT report. Provider documentation examples, reserved
#: test data, and obvious placeholders. This is the false-positive control.
NOISE = {
    "aws_doc_example": "AKIAIOSFODNN7EXAMPLE",
    "stripe_test": "sk_test_51ExampleTestKeyNotRealDoNotUse",
    "stripe_test_card": "4242 4242 4242 4242",
    "ni_reserved": "QQ123456C",
    "placeholder_key": "your-api-key-here",
    "placeholder_pw": "changeme",
    "example_email": "user@example.com",
    "doc_ip": "203.0.113.45",
    "placeholder_jwt": "eyJhbGciOiJIUzI1NiJ9.PLACEHOLDER.SIGNATURE",
}


# --------------------------------------------------------------------------
# Corpus model
# --------------------------------------------------------------------------


@dataclass
class Plant:
    """A deliberately planted item, and what the engine should make of it."""

    category: str  # secret | commercial | pii | special-category | internal
    subtype: str
    severity: str  # critical | high | medium | low
    value: str


@dataclass
class Event:
    """One turn in a transcript."""

    kind: str  # user_message | assistant_message | tool_call | tool_result | system_prompt
    text: str
    plants: list[Plant] = field(default_factory=list)
    tool: str = "Bash"


@dataclass
class Session:
    employee: str
    source: str  # claude-code | claude-desktop
    filename: str
    title: str
    events: list[Event]


# --------------------------------------------------------------------------
# alice.chen — secrets, mostly via tool results
# --------------------------------------------------------------------------

ALICE_DEPLOY = Session(
    employee="alice.chen",
    source="claude-code",
    filename="a1f4c8e2-7b3d-4a91-8c25-6e0d9f1b3a47.jsonl",
    title="Debug failing production deploy",
    events=[
        Event("user_message", "The prod deploy is failing on migrate. Can you look?"),
        Event(
            "assistant_message",
            "Let me check the environment configuration the deploy step uses.",
        ),
        Event("tool_call", "cat .env.production"),
        Event(
            "tool_result",
            "DATABASE_URL=" + FAKE["postgres"] + "\n"
            "AWS_ACCESS_KEY_ID=" + FAKE["aws_key_id"] + "\n"
            "AWS_SECRET_ACCESS_KEY=" + FAKE["aws_secret"] + "\n"
            "SUPABASE_SERVICE_ROLE_KEY=" + FAKE["service_jwt"] + "\n"
            "STRIPE_SECRET_KEY=" + FAKE["stripe_live"] + "\n"
            "MAILGUN_API_KEY=" + FAKE["mailgun"] + "\n"
            "SENTRY_DSN=" + FAKE["sentry_dsn"],
            plants=[
                Plant("secret", "postgres_connection_string", "critical", FAKE["postgres"]),
                Plant("secret", "aws_access_key_id", "critical", FAKE["aws_key_id"]),
                Plant("secret", "aws_secret_access_key", "critical", FAKE["aws_secret"]),
                Plant("secret", "supabase_service_role_jwt", "critical", FAKE["service_jwt"]),
                Plant("secret", "stripe_live_key", "critical", FAKE["stripe_live"]),
                Plant("secret", "mailgun_api_key", "high", FAKE["mailgun"]),
                Plant("secret", "sentry_dsn", "medium", FAKE["sentry_dsn"]),
                Plant("internal", "internal_hostname", "medium",
                      "db-prod-01.internal.meridiansystems.co.uk"),
            ],
        ),
        Event(
            "assistant_message",
            "The service role key is being used by the migration runner, which "
            "explains the permission error. I would not keep that key in the "
            "deploy environment.",
        ),
        Event(
            "user_message",
            "Here is the deploy key it uses too, in case that matters:\n"
            + FAKE["pem"],
            plants=[Plant("secret", "private_key_pem", "critical", "BEGIN RSA PRIVATE KEY")],
        ),
        Event("tool_call", "gh api /repos/meridian/platform/deployments"),
        Event(
            "tool_result",
            "Authorization: Bearer " + FAKE["github_pat"] + "\n"
            "{\"id\": 4471, \"environment\": \"production\", \"ref\": \"main\"}",
            plants=[Plant("secret", "github_pat", "critical", FAKE["github_pat"])],
        ),
    ],
)

ALICE_ALERTS = Session(
    employee="alice.chen",
    source="claude-code",
    filename="c7e91b04-2d5a-4f38-9b61-8a0c3e7d5f2b.jsonl",
    title="Wire up Slack alerting",
    events=[
        Event("user_message", "Add a Slack alert when the queue backs up."),
        Event(
            "assistant_message",
            "I will use the bot token from the alerting config.",
        ),
        Event("tool_call", "grep -r SLACK_ config/alerting.yml"),
        Event(
            "tool_result",
            "SLACK_BOT_TOKEN: " + FAKE["slack_bot"] + "\n"
            "SLACK_WEBHOOK: https://hooks.slack.com/services/T0284739/B4193827/Kd7Lm2QxTr9VbN4pZa8Wc3\n"
            "ANTHROPIC_API_KEY: " + FAKE["anthropic"] + "\n"
            "SUPABASE_ACCESS_TOKEN: " + FAKE["supabase"],
            plants=[
                Plant("secret", "slack_bot_token", "high", FAKE["slack_bot"]),
                Plant("secret", "slack_webhook_url", "high", "hooks.slack.com/services"),
                Plant("secret", "anthropic_api_key", "critical", FAKE["anthropic"]),
                Plant("secret", "supabase_access_token", "critical", FAKE["supabase"]),
            ],
        ),
        Event(
            "system_prompt",
            "CONFIDENTIAL — INTERNAL ONLY. This repository implements Project "
            "Kestrel, Meridian's unannounced logistics platform. Do not discuss "
            "externally before the Q4 launch.",
            plants=[
                Plant("internal", "classification_banner", "medium", "CONFIDENTIAL — INTERNAL ONLY"),
                Plant("internal", "project_codename", "medium", "Project Kestrel"),
                Plant("commercial", "unannounced_launch", "high", "unannounced logistics platform"),
            ],
        ),
    ],
)


# --------------------------------------------------------------------------
# ben.okafor — commercial data, Claude Desktop export
# --------------------------------------------------------------------------

BEN_ACCOUNTS = Session(
    employee="ben.okafor",
    source="claude-desktop",
    filename="conversations.json",
    title="Tidy up the quarterly management report",
    events=[
        Event(
            "user_message",
            "Rewrite this section of the management report so it reads better.\n\n"
            "CONFIDENTIAL — MANAGEMENT ONLY\n"
            "Q3: revenue £4,200,000 against £3,100,000 last year, gross margin "
            "71%. Overdue receivables stand at £310,000, most of it on one "
            "account. Three clients account for 62% of revenue. If the Northgate "
            "renewal goes against us we will need to reduce headcount by 15%.",
            plants=[
                Plant("internal", "classification_banner", "medium",
                      "CONFIDENTIAL — MANAGEMENT ONLY"),
                Plant("commercial", "revenue", "high", "revenue £4,200,000"),
                Plant("commercial", "gross_margin", "high", "gross margin 71%"),
                Plant("commercial", "money_figure", "medium", "£310,000"),
                Plant("commercial", "restructuring_plan", "high", "reduce headcount by 15%"),
            ],
        ),
        Event(
            "assistant_message",
            "Here is a tighter version of that section, keeping every figure as "
            "given.",
        ),
        Event(
            "user_message",
            "And check this invoice run adds up before I send it out.\n"
            "invoice,client,net,vat,total,due\n"
            "INV-2041,Halyard Freight,15000.00,3000.00,18000.00,2026-09-30\n"
            "INV-2042,Brightmoor Care,7916.67,1583.33,9500.00,2026-09-30\n"
            "INV-2043,Northgate Retail,20000.00,4000.00,24000.00,2026-10-15\n"
            "INV-2044,Vantage Legal,5166.67,1033.33,6200.00,2026-10-15\n"
            "INV-2045,Halyard Freight,15000.00,3000.00,18000.00,2026-10-31\n"
            "INV-2046,Kestrel Plant Hire,3250.00,650.00,3900.00,2026-10-31\n"
            "INV-2047,Brightmoor Care,7916.67,1583.33,9500.00,2026-11-15\n",
            plants=[
                # No keyword needed for this one: the shape gives it away.
                Plant("internal", "bulk_data_export", "medium", "7 rows of tabular data"),
                Plant("commercial", "transactional_document", "medium", "invoice"),
            ],
        ),
        Event(
            "assistant_message",
            "The run totals £89,100 including VAT. INV-2044 is the only line "
            "where the VAT does not reconcile to the net.",
        ),
        Event(
            "user_message",
            "Set up this supplier on the ledger: Kestrel Plant Hire, company "
            "number 07654321, VAT GB 432 1098 76, UTR 47382 91056, settlement "
            "45 days from invoice date.",
            plants=[
                Plant("pii", "company_number", "low", "07654321"),
                Plant("pii", "vat_number", "low", "GB 432 1098 76"),
                Plant("pii", "utr", "high", "47382 91056"),
            ],
        ),
    ],
)

BEN_TENDER = Session(
    employee="ben.okafor",
    source="claude-desktop",
    filename="conversations.json",
    title="Check renewal pricing before the tender",
    events=[
        Event(
            "user_message",
            "Check my renewal maths against the client schedule:\n"
            "Halyard Freight — £180,000/yr, renews 2026-11-30, 35% discount, 60-day payment terms\n"
            "Brightmoor Care — £95,000/yr, renews 2027-01-15, list price\n"
            "Northgate Retail — £240,000/yr, renews 2026-09-01, at risk\n"
            "Vantage Legal — £62,000/yr, renews 2027-03-20, list price",
            plants=[
                Plant("commercial", "client_contract_values", "high",
                      "Halyard Freight — £180,000/yr"),
                Plant("commercial", "customer_list", "high", "Northgate Retail"),
                Plant("commercial", "discount_terms", "high", "35% discount"),
                Plant("commercial", "renewal_risk", "medium", "at risk"),
                Plant("commercial", "transactional_document", "medium", "payment terms"),
            ],
        ),
        Event(
            "assistant_message",
            "Your total contracted value is £577,000. The Northgate renewal is "
            "42% of the September exposure.",
        ),
        Event(
            "user_message",
            "We are bidding £1,450,000 on the Ashcombe framework agreement. "
            "Their incumbent is on roughly £1.8M and the whole tender is under "
            "NDA, so keep it to yourself.",
            plants=[
                Plant("commercial", "money_figure", "medium", "£1,450,000"),
                Plant("commercial", "contract", "high", "framework agreement"),
                Plant("commercial", "transactional_document", "medium", "tender"),
                Plant("internal", "under_nda", "high", "under NDA"),
            ],
        ),
        Event(
            "assistant_message",
            "At £1,450,000 you are roughly 19% under the incumbent's run rate.",
        ),
    ],
)


# --------------------------------------------------------------------------
# priya.nair — personal data, including special category
# --------------------------------------------------------------------------

PRIYA_HR = Session(
    employee="priya.nair",
    source="claude-code",
    filename="e2b7d945-6c18-4a03-b8f7-1d4e9a25c063.jsonl",
    title="Import new starter records",
    events=[
        Event("user_message", "Load the new starter CSV into the staging table."),
        Event("tool_call", "head -4 new-starters-july.csv"),
        Event(
            "tool_result",
            "name,dob,ni_number,address,postcode,phone,sort_code,account,salary\n"
            f"Daniel Hartley,{FAKE['dob']},{FAKE['ni_hartley']},"
            f"\"{FAKE['address']}\",{FAKE['postcode']},{FAKE['phone']},"
            f"{FAKE['sort_code']},{FAKE['account_no']},48000\n"
            f"Amara Okonkwo,2 September 1994,{FAKE['ni_okonkwo']},"
            "\"11 Sandhurst Avenue, Leeds\",LS8 1PN,07700 900237,"
            "20-14-88,44219073,52500\n"
            "Tomas Herrera,30 November 1991,PY731864B,"
            "\"8 Ashgrove Terrace, Cardiff\",CF14 3QR,07700 900412,"
            "60-83-27,19274058,45750",
            plants=[
                Plant("pii", "person_name", "medium", "Daniel Hartley"),
                Plant("pii", "date_of_birth", "medium", FAKE["dob"]),
                Plant("pii", "uk_ni_number", "high", FAKE["ni_hartley"]),
                Plant("pii", "uk_ni_number", "high", FAKE["ni_okonkwo"]),
                Plant("pii", "home_address", "medium", FAKE["address"]),
                Plant("pii", "uk_postcode", "low", FAKE["postcode"]),
                Plant("pii", "phone_number", "medium", FAKE["phone"]),
                Plant("pii", "bank_details", "critical", FAKE["sort_code"] + " / " + FAKE["account_no"]),
                Plant("pii", "salary", "medium", "48000"),
                Plant("pii", "bulk_personal_records", "critical", "multi-row employee export"),
                # Caught by shape, not by any national identifier format —
                # the header row alone gives it away.
                Plant("pii", "personal_data_export", "high", "4 rows naming personal fields"),
            ],
        ),
        Event(
            "user_message",
            "Also, Daniel's occupational health report says he has multiple "
            "sclerosis and needs a phased return, four days a week until "
            "January. And flag that Amara disclosed an unspent conviction for a "
            "driving offence on her vetting form.",
            plants=[
                Plant("special-category", "health_condition", "critical", "multiple sclerosis"),
                Plant("special-category", "occupational_health", "critical",
                      "occupational health report"),
                Plant("special-category", "criminal_record", "critical", "unspent conviction"),
            ],
        ),
        Event(
            "assistant_message",
            "I will record the phased return as an adjustment. That health "
            "information is special-category data under UK GDPR, so it should "
            "not sit in the general staff table.",
        ),
        Event("tool_call", "psql -c 'SELECT email, nhs_number, iban FROM staff LIMIT 2'"),
        Event(
            "tool_result",
            "        email             |   nhs_number   |          iban\n"
            "--------------------------+----------------+------------------------\n"
            f" d.hartley@meridiansystems.co.uk | {FAKE['nhs']}  | {FAKE['iban']}\n"
            f" a.okonkwo@meridiansystems.co.uk | 611 209 4477   | GB82 WEST 1234 5698 7654 32\n"
            "(2 rows)",
            plants=[
                Plant("pii", "email_address", "low", "d.hartley@meridiansystems.co.uk"),
                Plant("pii", "nhs_number", "high", FAKE["nhs"]),
                Plant("pii", "iban", "critical", FAKE["iban"]),
            ],
        ),
        Event(
            "user_message",
            "One more — the company card on the account is " + FAKE["card"] + ".",
            plants=[Plant("pii", "payment_card", "critical", FAKE["card"])],
        ),
        Event(
            "user_message",
            "Add Daniel's driving licence HARTL903144DH9AB to the file, and his "
            "DBS certificate number is 003847195062 — the enhanced check came "
            "back clear last week.",
            plants=[
                # The licence number encodes his surname and date of birth.
                Plant("pii", "driving_licence", "high", "HARTL903144DH9AB"),
                Plant("special-category", "dbs_certificate", "high", "003847195062"),
            ],
        ),
    ],
)


# --------------------------------------------------------------------------
# sam.doyle — the false-positive control. Nothing here is a finding.
# --------------------------------------------------------------------------

SAM_CONTROL = Session(
    employee="sam.doyle",
    source="claude-code",
    filename="9d3a6f18-4b72-4e50-a1c9-7f2b8e0d5a34.jsonl",
    title="Write onboarding docs and a test fixture",
    events=[
        Event(
            "user_message",
            "Write the setup docs. Use placeholders for anything secret.",
        ),
        Event(
            "assistant_message",
            "Here is the example configuration:\n\n"
            f"API_KEY={NOISE['placeholder_key']}\n"
            f"DB_PASSWORD={NOISE['placeholder_pw']}\n"
            f"AWS_ACCESS_KEY_ID={NOISE['aws_doc_example']}\n"
            f"STRIPE_KEY={NOISE['stripe_test']}\n"
            f"CONTACT={NOISE['example_email']}",
        ),
        Event("tool_call", "cat tests/fixtures/payment.test.ts"),
        Event(
            "tool_result",
            "const TEST_CARD = '" + NOISE["stripe_test_card"] + "';\n"
            "const TEST_NI = '" + NOISE["ni_reserved"] + "';\n"
            "const TEST_HOST = '" + NOISE["doc_ip"] + "';\n"
            "const TEST_TOKEN = '" + NOISE["placeholder_jwt"] + "';\n"
            "// Reserved documentation values — see RFC 5737 and RFC 2606.",
        ),
        Event(
            "assistant_message",
            "Those fixtures use reserved test values, so they are safe to commit.",
        ),
    ],
)


SESSIONS = [
    ALICE_DEPLOY,
    ALICE_ALERTS,
    BEN_ACCOUNTS,
    BEN_TENDER,
    PRIYA_HR,
    SAM_CONTROL,
]


# --------------------------------------------------------------------------
# Sidecar files
# --------------------------------------------------------------------------
# Claude Code spills large tool outputs to files under `tool-results/` rather
# than inlining them, so the biggest results — schema dumps, query output — do
# not live in the .jsonl at all. A scanner that reads only .jsonl misses exactly
# the material most worth finding.

_SIDECAR_SESSION = "a1f4c8e2-7b3d-4a91-8c25-6e0d9f1b3a47"

SIDECARS: list[tuple[str, str, list[Plant]]] = [
    (
        f"alice.chen/claude-code/{_SIDECAR_SESSION}/tool-results/"
        f"psql-describe-1786393745790.txt",
        "Connected to "
        "postgresql://readonly:Wc3Ye6Uh1Jf0Sg@db-replica-02.internal.meridiansystems.co.uk"
        ":5432/meridian_prod\n"
        "\n"
        "                     Table \"public.staff\"\n"
        "   Column    |  Type   | Nullable |          Default\n"
        "-------------+---------+----------+---------------------------\n"
        " id          | uuid    | not null | gen_random_uuid()\n"
        " email       | text    | not null |\n"
        " ni_number   | text    |          |\n"
        " salary      | numeric |          |\n"
        "\n"
        "Sample rows:\n"
        " j.whitfield@meridiansystems.co.uk | NK918273B | 61000\n"
        " r.castellano@meridiansystems.co.uk | PT456190D | 58500\n",
        [
            Plant(
                "secret",
                "database_connection_string",
                "critical",
                "postgresql://readonly:Wc3Ye6Uh1Jf0Sg@db-replica-02.internal."
                "meridiansystems.co.uk:5432/meridian_prod",
            ),
            Plant("pii", "uk_ni_number", "high", "NK918273B"),
            Plant("internal", "internal_hostname", "medium",
                  "db-replica-02.internal.meridiansystems.co.uk"),
        ],
    ),
]


# --------------------------------------------------------------------------
# An embedded, base64-encoded secret
# --------------------------------------------------------------------------
# Encoding is not a hiding place: a credential that has been base64'd matches no
# pattern in any rule pack until something decodes it.

_SIGNING_SECRET = "8f3c9a1e4b8d2650fa93c7e5b1d84a60ca93f7e2"
_ENCODED_BLOB = base64.b64encode(
    (
        f"SLACK_SIGNING_SECRET={_SIGNING_SECRET}\n"
        "DEPLOY_ENV=production\n"
        "OWNER=platform-team\n"
    ).encode("utf-8")
).decode("ascii")

ALICE_ALERTS.events.insert(
    4,
    Event(
        "tool_result",
        "restored config blob from backup:\n" + _ENCODED_BLOB,
        # The planted value is the credential itself, not the whole assignment:
        # the variable name is not sensitive and must not count as a leak.
        plants=[Plant("secret", "env_assignment", "high", _SIGNING_SECRET)],
    ),
)


# --------------------------------------------------------------------------
# Writers
# --------------------------------------------------------------------------


def _claude_code_records(session: Session) -> list[dict]:
    """Render a session in Claude Code's ``.jsonl`` shape.

    Tool results come back as user-role messages carrying a ``tool_result``
    block, which is how the real format represents them — and is precisely why
    the parser must not assume "user message" means "something a human typed".
    """
    session_id = session.filename.removesuffix(".jsonl")
    records: list[dict] = []
    pending_tool_id: str | None = None

    for index, event in enumerate(session.events):
        uuid = f"{session_id}-{index:04d}"
        common = {
            "uuid": uuid,
            "sessionId": session_id,
            "timestamp": _timestamp(index),
        }

        if event.kind == "user_message":
            records.append({
                **common,
                "type": "user",
                "message": {"role": "user", "content": [{"type": "text", "text": event.text}]},
            })
        elif event.kind == "assistant_message":
            records.append({
                **common,
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": event.text}],
                },
            })
        elif event.kind == "tool_call":
            pending_tool_id = f"toolu_{index:04d}"
            records.append({
                **common,
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use",
                        "id": pending_tool_id,
                        "name": event.tool,
                        "input": {"command": event.text, "description": session.title},
                    }],
                },
            })
        elif event.kind == "tool_result":
            records.append({
                **common,
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": pending_tool_id or f"toolu_{index:04d}",
                        "content": event.text,
                    }],
                },
            })
        elif event.kind == "system_prompt":
            records.append({
                **common,
                "type": "system",
                "subtype": "project_instructions",
                "content": event.text,
            })
        else:  # pragma: no cover - guards against a typo in the corpus above
            raise ValueError(f"unknown event kind: {event.kind}")

    return records


def _claude_desktop_conversation(session: Session, index: int) -> dict:
    """Render a session in the Claude Desktop account-export shape."""
    conversation_id = f"conv-{index:04d}-{session.employee}"
    messages = []
    for position, event in enumerate(session.events):
        sender = "human" if event.kind == "user_message" else "assistant"
        messages.append({
            "uuid": f"{conversation_id}-{position:04d}",
            "sender": sender,
            "created_at": _timestamp(position),
            "text": event.text,
            "content": [{"type": "text", "text": event.text}],
        })
    return {
        "uuid": conversation_id,
        "name": session.title,
        "created_at": BASE_TIMESTAMP,
        "updated_at": BASE_TIMESTAMP,
        "chat_messages": messages,
    }


def build_files() -> dict[str, str]:
    """Build the whole corpus in memory: ``archive path -> file content``."""
    files: dict[str, str] = {}

    # Claude Code: one .jsonl per session.
    for session in SESSIONS:
        if session.source != "claude-code":
            continue
        path = f"{session.employee}/claude-code/{session.filename}"
        lines = [json.dumps(record, ensure_ascii=False) for record in _claude_code_records(session)]
        files[path] = "\n".join(lines) + "\n"

    # Claude Desktop: one conversations.json per employee, all sessions inside.
    desktop_by_employee: dict[str, list[Session]] = {}
    for session in SESSIONS:
        if session.source == "claude-desktop":
            desktop_by_employee.setdefault(session.employee, []).append(session)

    for employee, sessions in desktop_by_employee.items():
        conversations = [
            _claude_desktop_conversation(session, index)
            for index, session in enumerate(sessions)
        ]
        path = f"{employee}/claude-desktop/conversations.json"
        files[path] = json.dumps(conversations, ensure_ascii=False, indent=2) + "\n"

    for path, content, _ in SIDECARS:
        files[path] = content

    return files


def build_expected() -> dict:
    """The ground truth: every planted item, addressed by where it was planted."""
    entries = []
    # Claude Desktop puts every conversation in one file and the parser numbers
    # messages continuously across it, so a session's records start where the
    # previous session for that employee left off. Ground truth has to agree
    # with the parser or a correct detection reads as a miss.
    desktop_offsets: dict[str, int] = {}

    for session in SESSIONS:
        if session.source == "claude-code":
            path = f"{session.employee}/claude-code/{session.filename}"
            offset = 0
        else:
            path = f"{session.employee}/claude-desktop/conversations.json"
            offset = desktop_offsets.get(session.employee, 0)
            desktop_offsets[session.employee] = offset + len(session.events)

        for index, event in enumerate(session.events):
            for plant in event.plants:
                entries.append({
                    "employee": session.employee,
                    "file": path,
                    "session_title": session.title,
                    "record_index": offset + index,
                    "location_kind": event.kind,
                    "category": plant.category,
                    "subtype": plant.subtype,
                    "severity": plant.severity,
                    "value": plant.value,
                })

    for path, _, plants in SIDECARS:
        for plant in plants:
            entries.append({
                "employee": path.split("/", 1)[0],
                "file": path,
                "session_title": "spilled tool result",
                "record_index": 0,
                "location_kind": "tool_result",
                "category": plant.category,
                "subtype": plant.subtype,
                "severity": plant.severity,
                "value": plant.value,
            })

    by_category: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for entry in entries:
        by_category[entry["category"]] = by_category.get(entry["category"], 0) + 1
        by_severity[entry["severity"]] = by_severity.get(entry["severity"], 0) + 1

    employees = sorted({session.employee for session in SESSIONS})
    with_findings = sorted({entry["employee"] for entry in entries})

    return {
        "description": (
            "Ground truth for the synthetic corpus. Every value is fabricated. "
            "Generated by corpus/build.py — edit that, not this file."
        ),
        "employees": employees,
        "employees_expected_clean": [e for e in employees if e not in with_findings],
        "totals": {
            "findings": len(entries),
            "by_category": dict(sorted(by_category.items())),
            "by_severity": dict(sorted(by_severity.items())),
        },
        "findings": entries,
    }


def write_zip(files: dict[str, str]) -> None:
    """Write the archive with fixed timestamps, so the output is reproducible."""
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, files[path].encode("utf-8"))


def write_tree(files: dict[str, str]) -> None:
    for path, content in sorted(files.items()):
        target = SRC_DIR / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--extract",
        action="store_true",
        help="also write a readable tree to corpus/src/ for inspection",
    )
    args = parser.parse_args()

    files = build_files()
    write_zip(files)

    expected = build_expected()
    EXPECTED_PATH.write_text(
        json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    if args.extract:
        write_tree(files)

    print(f"wrote {ZIP_PATH.name}: {len(files)} transcript files")
    for path in sorted(files):
        print(f"  {path}  ({len(files[path]):,} bytes)")
    print()
    print(f"wrote {EXPECTED_PATH.name}: {expected['totals']['findings']} planted findings")
    print(f"  by category: {expected['totals']['by_category']}")
    print(f"  by severity: {expected['totals']['by_severity']}")
    print(f"  expected clean: {expected['employees_expected_clean']}")
    if args.extract:
        print(f"\nextracted a readable tree to {SRC_DIR}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
