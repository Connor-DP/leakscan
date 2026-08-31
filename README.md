# Transcript Leak Scanner

Scans exported AI-assistant session transcripts and reports **what was actually
exposed in them** — secrets and API keys, commercial data and metrics, personal
data, and internal or proprietary material.

It runs entirely on the machine where the transcripts already live. Nothing it
reads leaves that host — no upload, no API call, not even a DNS lookup. That is
the point of the product, so it is enforced in code rather than promised in a
policy.

See [`docs/detection-scope.md`](docs/detection-scope.md) for the full catalogue
of what counts as a leak, and where in a transcript it tends to hide. (Short
version: tool results, not the prompts, are where most of it is.)

> **Status:** working end to end — scan, report, triage, purge. Built and
> measured against a synthetic corpus; not yet run against a real customer set.

## Requirements

Python **3.11+**, standard library only. No `pip install`, no virtualenv, no
dependency tree — which also means it works on locked-down corporate machines.

Runs on macOS, Linux and Windows. macOS and Linux ship Python already; on
Windows install it once from [python.org](https://www.python.org/downloads/) or
the Microsoft Store, then use `py -m leakscan` in place of `python3 -m leakscan`.

## Quickstart

```sh
python3 -m leakscan selfcheck                                 # verify the offline guarantee
python3 -m leakscan inspect corpus/synthetic-transcripts.zip  # parse only: what was understood
python3 -m leakscan scan    corpus/synthetic-transcripts.zip  # scan, report, store
python3 -m leakscan serve                                     # triage in a local dashboard
python3 -m leakscan purge --all                               # delete everything, for good
```

`selfcheck` verifies the offline guarantee two independent ways and exits
non-zero if either fails. **Run it before every audit.**

```
Runtime egress guard
  [PASS] guard installed — socket API is patched
  [PASS] outbound TCP blocked — connect to 203.0.113.1:80 refused
  [PASS] outbound DNS blocked — resolution of example.invalid refused
  [PASS] loopback permitted — 127.0.0.1 resolves

Source audit
  [PASS] no forbidden imports in leakscan/

All checks passed. Nothing this tool reads can leave the host.
```

## How the offline guarantee works

Two independent controls, because either one alone can have a gap:

**At runtime** — [`leakscan/netguard.py`](leakscan/netguard.py) installs a
process-wide guard before arguments are even parsed. Outbound connections and
non-local DNS raise `EgressBlocked`. Loopback still works, so the local
dashboard can run. There is deliberately **no flag to disable it**.

**At review time** — [`leakscan/audit.py`](leakscan/audit.py) parses every
source file and rejects imports that could move data off the host or execute
another program: `subprocess`, HTTP clients, mail and FTP modules, and `socket`
anywhere except `netguard.py`. The entire network surface a reviewer has to read
is therefore one file.

## The report

`scan` writes two files to `output/`:

- **`report.json`** — every finding with its rule, category, severity,
  confidence, employee, location and occurrence count, plus the scan-quality
  record: what was suppressed as noise, what was skipped, what failed to parse.
- **`report.html`** — the same thing for a human. One self-contained page:
  inline CSS and script, no fonts, no CDN, no images. Opening it calls nothing.

Both are created mode 0600 from the outset. Values are redacted, and *every*
detected value in a snippet is masked by character offset — not just the matched
one, because in an `.env` dump the surrounding context is other credentials, and
a window that clips a neighbouring key would otherwise print the fragment in
clear. Transcript content is escaped before rendering: a snippet is attacker-
controlled text and may contain markup.

## Triage and history

`scan` also stores its findings in a local SQLite file, and `serve` opens a
dashboard on `127.0.0.1:8787` to work through them: filter by severity or state,
mark each finding **confirmed**, **false positive** or **remediated**, and see
how the totals move scan to scan.

Two properties make that worth using:

- **Triage survives re-scanning.** A finding's identity is a hash of employee,
  rule and value — deliberately *not* its location, because re-exporting a
  transcript shifts record indices. Without that, every "we checked this" would
  be lost on the next scan, and triage nobody trusts gets abandoned.
- **The store never holds a raw secret.** Only the redacted value and redacted
  snippet. A findings database is already a ranked index of every credential in
  the company; keeping the plaintext out means the worst case is a map of where
  to look, not the keys themselves. There's a test that greps the database file
  for the corpus's own credentials.

## Deleting it

```sh
python3 -m leakscan purge --all               # everything, plus the report files
python3 -m leakscan purge --scan 3            # one scan
python3 -m leakscan purge --employee a.chen   # one person
```

Rows are dropped and the database is `VACUUM`ed, so the freed pages are
rewritten rather than left readable in the file. It **cannot** reach a backup,
a filesystem snapshot or a Time Machine copy that has already run — tell
customers that plainly.

## Handling the output

The report lists exactly which secrets exist and where, so it needs the same
care as the transcripts themselves:

- **Redacted by default.** `--reveal` writes matched values in the clear and
  records in the report that it was used.
- **Owner-only files.** Created mode 0600 on POSIX from the outset, never
  chmod'ed after the fact. Windows has no equivalent without a subprocess or a
  dependency, so `harden()` returns `False` there rather than pretending — keep
  output under the user profile, whose own ACL restricts it.
- **`output/`, `input/` and the findings store are gitignored.** Keep it that way.
- **Delete it when you are done.** `purge` hard-deletes findings, `VACUUM`s the
  database so freed pages are overwritten, and unlinks reports. It cannot defeat
  backups or snapshots that already ran.

A clean report is not proof that nothing leaked. Detection is best-effort and
measured against a synthetic corpus; treat findings as leads, not as an
exhaustive inventory.

## Development

```sh
python3 -m unittest discover -s tests -t .
```

The suite reads only this repo's own source and writes only to `.tmp/` inside
the project — never the OS temp area, never your transcripts. Its two network
probes (a TCP connect and a DNS lookup) use RFC-reserved addresses and are
refused by the guard before any syscall, which is the point of them.

Two rules keep the privacy claim true, and the test suite enforces both:

1. **No new dependencies.** Standard library only.
2. **No forbidden imports.** If you need one, you almost certainly need a
   different design — `test_audit.py` will fail the build.

The engine is developed and tested against a **synthetic corpus of fabricated
PII and fake credentials**, never against real transcripts.

## Layout

```
leakscan/
  netguard.py   runtime egress guard — the only file that imports socket
  audit.py      static import audit, plus the remote-asset check for reports
  selfcheck.py  runs both, and is what `selfcheck` calls
  paths.py      per-OS locations, owner-only file writes
  ingest.py     walk a ZIP or directory; employee attribution; skip list
  records.py    the normalised Record every later stage works from
  adapters/     claude_code.py, claude_desktop.py — format in, records out
  survey.py     parse-only summary, behind `inspect`
  cli.py        command-line surface
corpus/
  build.py             generates the synthetic corpus and its ground truth
  expected.json        50 planted findings, labelled
docs/
  detection-scope.md   what counts as a leak — the rule-pack spec
tests/
```

### `inspect` before you trust a scan

"No findings" means nothing if the files were never read. `inspect` parses
without detecting and shows what was understood — records by location, per
employee, plus anything skipped or unparseable:

```
Files:    5 parsed, 0 skipped
Records:  32 (5,118 characters of text)

By location:
  tool_result              6
  tool_call                6
  user_message            10
  assistant_message        9
  system_prompt            1
```

Nothing is dropped quietly: an unreadable file, an unrecognised block type or a
malformed line is counted and named, because a silently skipped file looks
exactly like a clean result.

## Detection

Built for **UK organisations**, and specific about it: National Insurance and
NHS numbers, UTRs, sort codes, VAT and EORI numbers, Companies House numbers,
DVLA licence numbers, DBS certificates, UK postcodes and phone formats, and
UK GDPR Article 9 special-category handling. A scanner that half-knows twelve
countries knows none of them properly.

Rules live in [`leakscan/rulepacks/`](leakscan/rulepacks/) as YAML, four families
plus a noise pack — 71 rules covering secrets and credentials, commercial data
and metrics, personal and special-category data, and internal or proprietary
material. The catalogue behind them is
[`docs/detection-scope.md`](docs/detection-scope.md).

Each match runs a gauntlet before it becomes a finding: **validate** (Luhn for
card numbers, a Shannon-entropy floor for catch-all patterns), **require
context** where the pattern alone is too loose, then **suppress** placeholders,
provider documentation examples and reserved test data. Repeats of the same
value collapse into one finding with a count.

### Structural detection — why it works outside your own industry

Keyword rules only find what someone thought to write down, and vocabulary does
not travel: a law firm has matters, a hospital has patients, a haulier has
consignments, and none of them have monthly recurring revenue. So alongside the
packs there are detectors that read the **shape** of what was pasted and need no
keyword at all:

- **Tabular data** — four or more rows agreeing on their delimiter count is an
  export, not a conversation. Counted outside quotes, since a personal-data CSV
  almost always has a quoted address with commas in it.
- **Personal-data exports by header row** — a line naming three or more personal
  fields above rows of data. Catches an export whose *values* no pack
  recognises: an internal employee-ID scheme, a bespoke reference format, or a
  column nobody wrote a rule for.
- **Pasted documents** — a long, structured message or attachment. "Someone
  pasted a twelve-page document into a chat" lands in any sector.
- **Monetary magnitude** — a seven-figure sum, keyword-free.

**Add your own terms.** `internal.custom_term` in
[`internal.yaml`](leakscan/rulepacks/internal.yaml) is a stub for your client
names, project codenames and internal system names — the one category no vendor
can ship, and the reason the packs are YAML rather than code.

### Measuring it

```sh
python3 corpus/score.py --detail
```

Scores the engine against the corpus ground truth. Current state: **50/50
planted findings (100%)**, and **zero findings on the control employee**, whose
transcript contains nothing but placeholders and reserved test values. The
control is the number that matters — a report full of `your-api-key-here`
teaches its reader to skim, and after that the real critical finding on page
three goes unread.

A passing score is a regression guard, not proof of coverage: it measures the
engine against leaks we thought to plant.
