# Synthetic corpus

Fabricated transcripts used to measure the detection engine. **Nothing here is
real.** The people, the employer (Meridian Systems Ltd), the clients, the
figures and every credential are invented. No value was copied from a real
transcript, system or person.

## Files

| File | What it is |
|---|---|
| `build.py` | The source of truth. Holds the content, writes the other two. |
| `synthetic-transcripts.zip` | The corpus, laid out folder-per-employee — the shape a real audit ZIP takes. |
| `expected.json` | Ground truth: every planted item, with category, subtype, severity and where it sits. |

Regenerate both with:

```sh
python3 corpus/build.py            # rewrite the ZIP and expected.json
python3 corpus/build.py --extract  # also write a readable tree to corpus/src/
```

Output is deterministic — fixed timestamps, sorted entries — so the ZIP is
byte-identical between runs and a diff means the content actually changed.
Edit `build.py` and regenerate; never hand-edit `expected.json`, or the ground
truth drifts away from the data it describes.

## What's in it

Six files across four employees, in both v1 formats — Claude Code `.jsonl`
and the Claude Desktop account export — plus a spilled `tool-results/`
sidecar. They carry **55 planted findings**: 16 pii, 15 secret, 14 commercial, 7 internal, 3 special-category.
By severity: 17 critical, 18 high, 18 medium, 2 low.

- **`alice.chen`** — engineer. Secrets and credentials, mostly arriving in
  **tool results** rather than anything she typed: a `cat .env.production` dump,
  a `service_role` JWT, a pasted private key, a bearer token in an API response.
  This is the realistic case — nobody chose to expose these.
- **`ben.okafor`** — commercial and finance, in Claude Desktop format, and
  deliberately sector-neutral: a confidential management report (revenue,
  margin, overdue receivables, a headcount cut), an invoice run, a client
  contract schedule with values and discounts, and tender pricing under NDA.
  No ARR, no cap table — a partner at a law firm should recognise their own
  week here, not a software company's.
- **`priya.nair`** — HR. A new-starter CSV in a tool result (names, DOB, NI
  numbers, addresses, bank details, salaries), an NHS number and IBAN from a
  `SELECT`, a Luhn-valid card number, and **special-category** data: a health
  condition, an occupational health report, an unspent conviction.
- **`sam.doyle`** — **the control. Expected findings: zero.** Placeholders
  (`your-api-key-here`, `changeme`), provider documentation examples
  (`AKIAIOSFODNN7EXAMPLE`, `sk_test_…`), and reserved test data (`QQ123456C`,
  `4242 4242 4242 4242`, `203.0.113.45`). If the engine reports anything from
  this employee, it is generating exactly the noise that makes a report
  untrustworthy — so this file is as important as the other four.

## Two things to know

**Secret scanners will flag this repo.** The corpus contains strings shaped like
live credentials — that is the point of it. GitHub secret scanning and similar
tools may alert on `corpus/`. They are all invented and grant access to nothing.

**A passing score here is not proof the engine works.** The corpus measures the
engine against leaks we thought to plant. Real transcripts will contain shapes
nobody anticipated. Treat the score as a regression guard, not as coverage.
