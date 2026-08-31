# Detection scope — what counts as a leak

The catalogue of what the scanner looks for. This is the spec the YAML rule
packs implement, so if something is missing here it will not be found.

One rule throughout: we report **what was actually exposed in the transcript**.
Not what might be risky in theory, not what the assistant speculated about —
what a person put in front of an AI assistant, or what a tool result pulled in
and handed to it.

---

## 1. Where to look inside a transcript

Most of the value is not in what the employee typed. Ranked by how much leaked
data each field carries in practice:

| Location | Why it matters |
|---|---|
| **Tool results** | The biggest source by far. File reads, `SELECT *` output, `env` dumps, API responses, log tails. Nobody chose to paste this — it arrived as a side effect. |
| **Tool call arguments** | Connection strings, tokens passed as flags, file paths, SQL. |
| **User messages** | Deliberate pastes: a stack trace, a `.env`, a CSV, a contract, a board deck. |
| **Attachments / pasted file content** | Whole documents inlined into the conversation. |
| **Assistant messages** | The model echoing a secret back, or reproducing it in generated code. Same exposure, and easy to forget. |
| **System prompt / project instructions** | `CLAUDE.md`, custom instructions — often carry internal architecture and client names. |

Out of scope for v1: images (no OCR) and anything referenced by a path but not
actually included in the transcript.

---

## 2. Secrets and credentials

Highest severity: these are live and directly exploitable.

**Provider key shapes** — anchored patterns, high confidence, low false-positive rate:

- Anthropic `sk-ant-…`, OpenAI `sk-…` / `sk-proj-…`
- AWS `AKIA…` / `ASIA…` (+ a nearby 40-char secret access key)
- Google `AIza…`, OAuth client secrets `GOCSPX-…`, service-account JSON (`"type": "service_account"` with a `private_key`)
- Stripe `sk_live_…` / `sk_test_…` / `rk_…` / `whsec_…`
- GitHub `ghp_` / `gho_` / `ghs_` / `github_pat_…`
- Slack `xoxb-` / `xoxp-` / `xapp-`, and webhook URLs `hooks.slack.com/services/…`
- Supabase `sbp_…` and `service_role` JWTs
- Airtable `pat…` / legacy `key…`
- Resend `re_…`, SendGrid `SG.…`, Mailgun `key-…`, Postmark, Twilio `AC…` / `SK…`
- npm `npm_…`, PyPI `pypi-…`, HuggingFace `hf_…`, Datadog, Sentry DSNs (`https://<key>@…sentry.io/…`)

**Generic shapes:**

- JWTs — `eyJ…`, decoded far enough to read `role`/`exp`; a `service_role` or non-expiring token is Critical
- PEM private keys — `-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----`
- Connection strings with inline credentials — `postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://`
- Basic-auth credentials in URLs; `Authorization: Bearer …` headers in pasted `curl` commands
- Pre-signed URLs carrying a token — `X-Amz-Signature`, SAS tokens, signed GCS URLs
- `.env`-style assignments — `*_KEY=`, `*_SECRET=`, `*_TOKEN=`, `PASSWORD=`, `PASSWD=`, `API_KEY=` with a non-placeholder value
- kubeconfigs, `.npmrc` / `.pypirc` auth lines, SSH private keys
- **High-entropy catch-all** — base64/hex runs above a length and entropy floor that match no known shape. Lower confidence by construction; this is the net for in-house token formats.

**Live vs dead matters.** `sk_test_`, obvious placeholders, and documentation
examples are downranked, never Critical. We do not validate a key by calling the
provider — that would both leak the key and break the offline guarantee.

---

## 2a. Structural signals — the ones that work anywhere

Every rule in this document except these depends on **vocabulary**, and
vocabulary does not travel. A law firm has matters, a hospital has patients, a
haulier has consignments, and none of them have monthly recurring revenue. A
scanner built only on keyword lists is a scanner built for whoever wrote the
lists.

Shape travels. These detectors read the *form* of what was pasted and need no
keyword at all, which is what makes the tool useful to an organisation whose
words — and whose country's identifier formats — nobody here has seen:

- **Tabular data** — lines agreeing on how many delimiters they contain. Four or
  more rows of it is a data export, not a conversation. Delimiters are counted
  outside quotes, because a personal-data CSV almost always has a quoted address
  with commas in it.
- **Personal-data exports by header row** — a line naming three or more personal
  fields (`name`, `date of birth`, `email`, `address`, `employee id`, `salary`)
  above rows of data. This catches an export whose *values* no rule pack
  recognises: a US, German or Brazilian identifier in a UK-shaped ruleset still
  sits under a column heading that gives it away.
- **Pasted documents** — a single message or attachment over a few thousand
  characters carrying document structure (numbered clauses, headings, bullets,
  paragraph breaks). "Someone pasted a twelve-page document into a chat" is a
  finding in any sector. Restricted to what a person pasted or attached; a long
  tool result is a log.
- **Monetary magnitude** — a seven-figure sum, with no keyword required. Worth a
  look whether it is revenue, a contract, a claim, a settlement or a budget.

Severity scales with volume: four rows of people is High, twelve is Critical.

## 3. Commercial and business data

The category most tools miss entirely, and the one an employee is most likely to
paste without thinking. Detected mainly by **keyword + numeric context** rather
than shape, so these lean on the noise filter.

Keep the sector-neutral terms first-class — **revenue, margin, contract values,
invoices, purchase orders, quotations, tenders, payment terms** exist wherever
there are customers. The SaaS vocabulary below (ARR, MRR, CAC/LTV, cap table,
runway) is a *profile*, not the default: valuable when it applies, dead weight
for a manufacturer or a practice, and no substitute for the structural signals
in §2a.

- **Financial metrics** — revenue, ARR, MRR, gross margin, EBITDA, burn rate, runway, P&L lines, balance-sheet figures, forecasts, budget vs actual
- **Growth metrics** — user/customer counts, signups, activation, churn, retention cohorts, CAC, LTV, conversion rates, NPS, MAU/DAU
- **Dashboard and analytics dumps** — pasted KPI tables, BI exports, SQL result sets over business tables, weekly-metrics emails
- **Pricing** — rate cards, quotes, discount structures, deal values, margin per client, contract values
- **Customers and pipeline** — client lists, account names, logos under NDA, CRM exports, opportunity stages, renewal dates
- **Contracts and legal** — MSAs, SOWs, NDAs, T&Cs, clauses, signature blocks, termination and liability terms
- **Corporate confidential** — board packs, investor updates, cap tables, valuations, fundraising terms, M&A discussions, restructuring or redundancy plans, unannounced launches, roadmap and release dates
- **Employment commercial** — headcount plans, comp bands, individual salaries, bonus pools, equity grants

Severity rises with specificity: "revenue was up" is noise; a table of named
clients against contract values is High.

---

## 4. Personal data (PII) — UK

Deliberately British. The market is UK organisations, so the pack goes deep on
UK identifiers rather than shallow on everybody's. Non-UK formats are out of
scope by design; where they turn up, the structural detectors in §2a still
catch the export they are sitting in.

- **Identity** — full names (key-based: `"first_name":`, `Employee:`), DOB, personal addresses, UK postcodes, personal phone numbers, personal email addresses
- **Government identifiers** — National Insurance number (prefix-validated, so the
  reserved `QQ123456C` is rejected without needing a suppressor), NHS number,
  passport number, **DVLA driving licence number** (which encodes the holder's
  surname and date of birth — personal data disguised as a reference), **UTR**
- **Financial personal** — sort code + account number, IBAN, card numbers (Luhn-validated), salary and payslip figures
- **Business identifiers** — **VAT number**, **EORI number**, **Companies House
  number**. Low severity individually since they are on the public register or
  printed on every invoice, but they corroborate that a real supplier or client
  record was pasted rather than an example
- **Employment records** — contracts, disciplinary notes, performance reviews, right-to-work documents
- **Special category (UK GDPR Art. 9) — always High or Critical** — health and medical, disability, occupational-health reports, sickness records, criminal convictions, ethnicity, religion, trade-union membership, sexual orientation, biometric data

Volume is itself a signal: one email address is Low; a two-hundred-row export of
customer records is Critical regardless of the fields involved.

---

## 5. Internal and proprietary

- **Classification banners** — `CONFIDENTIAL`, `INTERNAL ONLY`, `PROPRIETARY`, `DO NOT DISTRIBUTE`, `UNDER NDA`, `PRIVILEGED`. Cheap, precise, high-value: the document already declared itself.
- **Customer-supplied term lists** — the client's own client names, project and product codenames, internal system names. Configured per customer in a rule pack; no vendor can ship these.
- **Internal infrastructure** — private hostnames, internal URLs and admin panels, private IP ranges, database and bucket names, repo paths, Jira/ticket IDs
- **Proprietary source** — code carrying an internal copyright header or a licence forbidding disclosure

---

## 6. Noise control

Precision matters more than recall here: a report a compliance lead stops
trusting is worth nothing. Suppressed by default —

- Documentation and placeholder values — `sk_test_…`, `AKIAIOSFODNN7EXAMPLE`, `your-api-key-here`, `xxx`, `<redacted>`, `changeme`
- Reserved test data — `QQ123456C` (NI), `4242424242424242` (Stripe test card), RFC 5737 / RFC 2606 addresses (`example.com`, `203.0.113.0/24`)
- Vendor and infrastructure domains in email matches — `@sentry.io`, `@supabase.io`, `@github.com`, and the customer's own domain, configurable
- Known test fixtures and seed data, by path or by content hash
- Anything on the per-customer allowlist

Every suppression is counted in the report, so a tuned-out category is visible
rather than silently missing.

---

## 7. Severity

| Severity | Meaning | Examples |
|---|---|---|
| **Critical** | Live credential, or bulk personal data | Production API key, `service_role` JWT, private key, DB connection string with password, a customer table export |
| **High** | Special-category PII, or material commercial data | Health or criminal records, board pack, cap table, named client list with contract values |
| **Medium** | Ordinary personal data, or internal-only material | An employee's address and DOB, an internal hostname, a document marked Confidential |
| **Low** | Weak signal, or already-public information | A single work email address, a company name, an unvalidated high-entropy string |

Confidence is scored separately from severity: a Critical finding at 40%
confidence still needs a human to look, but it sorts below a Critical at 95%.
