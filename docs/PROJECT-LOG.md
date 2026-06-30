# Project Log — Brand & Domain Monitor

A running record of key decisions, scope changes, and rationale.
Kept independent of any specific chat tool so context survives across
sessions, machines, and conversations.

---

## 2026-06-30 — Project kickoff and scoping

**Decision: split brand monitoring into two separate tools, not one.**

- Tool 1 (this repo): **Brand & Domain Monitor** — lookalike/typosquat
  domain detection, DNS resolution checks, certificate transparency
  log monitoring (crt.sh)
- Tool 2 (separate, future repo): **Social Media Monitoring Agent** —
  impersonation account detection across platforms

Rationale: different data sources, different APIs, different rate-limit
and ToS considerations per platform. Combining them into one agent
would make both harder to reason about, test, and document cleanly.

---

**Decision: build locally, not in a cloud Codespace.**

Reasons:
1. DNS/crt.sh lookups benefit from a stable, predictable network
   origin — cloud datacenter IP ranges can behave inconsistently
   with some resolvers, which matters for reproducible evidence.
2. The `threat intel` project already hit real Codespace friction
   (Ollama install issues, port visibility config) — no need to
   import that overhead into a new project before it's started.
3. No dependency here needs cloud infrastructure (no GPU, no
   specific service stack) — lightweight DNS/HTTP work runs fine
   in a local `.venv`, same pattern as `lab`, `lab2`, `lab3`, `lab4`.
4. Consistency: local build → `.venv` → commit to GitHub. A
   `.devcontainer` config can be added later purely so others can
   spin up a Codespace to *run* the published tool — a packaging
   convenience added at the end, not the dev environment itself.

---

**Decision: project folder structure, matching `threat intel`'s pattern.**

```
/Users/radium/ai projects/brand domain monitor/
├── brand_monitor/        ← renamed from initial cti_agent (collision fix)
│   ├── __init__.py
│   ├── config.py         ← brand/domain to protect, lookalike rules
│   ├── agent.py          ← orchestration
│   ├── sources.py        ← crt.sh + DNS lookups
│   └── net.py            ← HTTP layer
├── evidence/
├── reports/
├── docs/
│   └── PROJECT-LOG.md    ← this file
├── .devcontainer/        ← added later, for published-repo convenience
├── README.md
├── LICENSE
├── requirements.txt
└── run.sh
```

**Naming fix applied:** initial scaffold used `cti_agent/` as the
package name (copy-pasted habit from the `threat intel` project
structure). Renamed to `brand_monitor/` before any code was written —
avoids an import collision if both projects' venvs or PYTHONPATH ever
overlap, and the name should describe what the tool does, not what
the previous project was called.

---

**Decision: v1 scope is narrow and read-only-public-data only.**

In scope for v1:
- Generate plausible lookalike/typosquat variants of a target domain
  (character substitution, TLD swaps, hyphenation, homoglyphs)
- Check DNS resolution for each variant — does it exist at all?
- For resolving variants, check certificate transparency logs (crt.sh)
  for recently issued certs
- Output: structured report of which lookalikes are registered/active

Explicitly out of scope for v1 (deferred, not forgotten):
- Active scraping or content comparison of discovered lookalike sites
- Social media impersonation detection (separate tool — see above)
- Dark web / paste site monitoring
- Any interaction with discovered domains beyond passive DNS/cert lookups

Rationale for the read-only boundary: passive DNS resolution and
public certificate transparency log queries are unambiguous and safe
regardless of target. Active scraping, bulk WHOIS at scale, or repeated
probing of third-party infrastructure starts touching ToS and
computer-misuse-statute territory depending on jurisdiction and target
— that line should be designed around from day one, not retrofitted
after something is flagged.

**Test target for v1 development: `example.com`** — IANA-reserved
specifically for documentation and testing, so all lookups against it
are unambiguously fine with no authorization questions.

---

**Decision: continuity strategy across chat sessions.**

- A Claude Project will hold persistent instructions (this log's key
  points, naming conventions, scope decisions) so new chats inside the
  Project start with context already loaded.
- This `PROJECT-LOG.md` is the durable, tool-independent record —
  lives with the code, gets updated at each meaningful decision point,
  and survives regardless of which chat session or AI tool is in use
  six months from now.

---

*Next session: scaffold `config.py`, `sources.py`, `net.py`, `agent.py`
against the `example.com` test target.*

---

## 2026-06-30 — v1 + v1.1 + two-tier scan + full IANA sweep: complete build session

**Starting point:** scaffold in place from the previous session (`config.py`,
`agent.py`, `sources.py`, `content_check.py` placeholders; venv active;
project log started). This session built all functional code, found and
fixed four real bugs, expanded scope twice (v1.1 content check, then
the two-tier + full-TLD-sweep capability), and ran the tool for real
against both the test target (`example.com`) and a genuine pre-launch
brand check (`timesof.uk`, a domain the user owns).

### v1 — core pipeline built

- `config.py` — protected domain, homoglyph substitution rules,
  curated TLD variant list, crt.sh endpoint, polite rate-limit settings
- `sources.py` — lookalike candidate generation (character substitution
  + TLD swapping), DNS resolution check, crt.sh Certificate
  Transparency lookup
- `agent.py` — orchestration: generate → scan → classify → save report

### Bugs found and fixed, in order

1. **SSL certificate verification failure on all crt.sh requests.**
   Root cause: the python.org macOS installer's bundled Python ships
   its own root certificate store, separate from the system trust
   store, never initialised on this machine. Fixed by running
   `/Applications/Python 3.14/Install Certificates.command`. Not a
   code bug — an environment setup step, documented here so it isn't
   re-diagnosed from scratch on a future machine.

2. **Unhandled `TimeoutError` crashed the entire scan.** Original
   exception handling in `check_certificate_transparency()` only
   caught `URLError`, `HTTPError`, `JSONDecodeError`. A raw timeout
   propagated uncaught and killed the whole run over one slow request.
   Fixed by broadening the caught exceptions to include `TimeoutError`
   and `OSError` — any single failed candidate is now recorded
   gracefully rather than taking down the entire scan.

3. **HTTP 404 from crt.sh misclassified as an error (UNKNOWN) rather
   than a legitimate zero-result (LOW).** crt.sh returns 404 for some
   "no certificates match" cases rather than an empty JSON array.
   Fixed by catching `HTTPError` specifically and treating a 404 as
   `certificates_found: 0`, distinct from every other HTTP error code.

4. **Report files grew to 65KB+ on domains with many historical
   certificates** (`exampl3.com` returned 66 raw crt.sh entries).
   Fixed by adding `_summarise_certificates()` — keeps the true
   `certificates_found` count (never hidden) but retains only the 5
   most recent entries' key fields in the saved report. Reports now
   consistently under 5KB.

### v1.1 — content status check added

After researching what reputable commercial brand-monitoring vendors
actually do (a single, polite homepage fetch — the same action a
browser takes — followed by lightweight pattern-based classification,
before any finding is escalated to a human for review), v1.1 added
`content_check.py`: ONE HTTP GET per HIGH-tier resolving candidate
only (never the full candidate list), classifying PARKED vs
HAS_CONTENT vs COULD_NOT_FETCH via known parking-page signature
matching. Raw HTML never stored — only classification + metadata.
Output modelled on a real client-facing vendor alert: observation +
recommendation for human review, never an automated conclusion of
maliciousness. A subsequent fix added per-scheme error capture
(`fetch_errors` field) so a `COULD_NOT_FETCH` result always explains
why, rather than failing silently.

### Honest, evidenced finding — existence ≠ malicious

DNS resolution + a valid SSL certificate on a lookalike domain is
**not** evidence of malicious intent. Three confirmed-resolving
candidates against `example.com` (`example.co`, `example.org`,
`exampl3.com`) are almost certainly unrelated, legitimately-registered
domains that happen to share a similar string — not phishing
infrastructure. Confirmed by manually visiting `example.org` and
observing the standard, boring IANA documentation placeholder page.
The tool correctly separates "this exists and is worth a human
glance" (HIGH tier / HAS_CONTENT) from any claim of "this is
malicious" — that distinction is preserved explicitly in every
finding's recommendation text.

### crt.sh reliability, observed directly

Over roughly 6 runs against `example.com`, crt.sh's own service
quality varied significantly — several runs returned `HTTP 502: Bad
Gateway` or timeouts on most candidates, while other runs (minutes
apart, identical code) returned clean results. Expected behaviour for
a free, volunteer-run public service; handled correctly by the
broadened exception handling from fix #2 — every failure recorded
honestly as UNKNOWN, never silently treated as a clean negative.

### Two-tier scan architecture — scope expansion #2

Prompted by the realistic observation that a real organisation
monitoring its one canonical brand domain cares about exhaustive TLD
coverage, not just a curated high-abuse subset. Restructured
`run_scan()` into:

- **Tier 1** — broad, cheap sweep: DNS resolution only, across the
  full candidate list (curated or full-IANA, see below). No crt.sh,
  no rate-limit constraint, safe to scale up.
- **Tier 2** — granular: for the (typically much smaller) resolving
  subset only, run crt.sh lookup + risk classification + content
  check (HIGH-tier only).

This is the architecture that makes the full-IANA-sweep mode (below)
tractable — Tier 1 can scale to ~1,480 candidates because DNS lookups
are cheap; Tier 2 only ever processes whatever actually resolves.

### TLD list — evidenced expansion

`COMMON_TLD_VARIANTS` expanded from 6 to 16 entries, justified by
named, current industry research rather than guessed: Spamhaus's
domain reputation reporting, Interisle's Phishing Landscape 2026
data, and CSC's highest-threat-TLD analysis all independently and
consistently flag a specific set of newer, cheaply-registrable gTLDs
(`.xyz`, `.top`, `.xin`, `.bond`, `.cfd`, `.click`, `.icu`, `.cyou`)
plus certain ccTLDs (`.ru`, `.es`) as disproportionately associated
with phishing/abuse, generally correlating with low registration cost
and weak vetting enabling bulk/automated registration. Source
citations recorded for the original research conversation.

**Test result against `example.com`:** 0 of these 14 higher-risk TLD
variants were found registered at all — a genuine, evidenced negative
result, not a tool failure.

### Full IANA TLD sweep mode — scope expansion #3

For a thorough, one-time pre-launch brand check (the actual stated
use case: verifying `timesof.uk`, a domain the user owns, has not
been squatted before going live), added:

- `sources.fetch_iana_tld_list()` — fetches IANA's official root zone
  list (`data.iana.org/TLD/tlds-alpha-by-domain.txt`), caches locally
  (30-day max age) to avoid repeated fetches of a list that rarely
  changes
- `sources.generate_full_tld_candidates()` — TLD-swap candidates
  across the full ~1,470-1,480 TLD list rather than the curated subset
- `agent.run_scan(..., use_full_tld_list=True)` — new flag switching
  Tier 1 between curated and full-IANA candidate generation; Tier 2
  behaviour unchanged either way

**Known cost, accepted deliberately:** Tier 1's DNS check currently
runs sequentially with no concurrency. A full ~1,480-candidate sweep
is estimated/expected to take up to roughly an hour. Explicitly
judged an acceptable trade-off for a free, self-built tool used
occasionally for thorough one-time checks, not a service requiring
fast turnaround — concurrency (e.g. `ThreadPoolExecutor`) identified
as a future improvement if this becomes a routine/frequent operation
rather than an occasional pre-launch check.

### Process note, reaffirmed from previous session

Targeted `sed`-based edits (using exact `grep -n` line numbers
confirmed before each edit, followed immediately by `head`/`wc -l`/
`python3 -c "import ast; ast.parse(...)"` verification) proved
reliable throughout this session, including for a large multi-line
function insert via `sed -i '' 'Na\...'`. One cosmetic issue surfaced:
`\u2014` Unicode escapes inside a `sed` insert do not get interpreted
as em-dashes (they land as literal `u2014` text) — `sed` has no
Unicode-escape support; the raw UTF-8 byte sequence (`\xe2\x80\x94`)
must be used instead if an em-dash is needed inside a `sed`-inserted
block. Full-file replacement via heredoc remains the fallback for any
edit complex enough that a one-shot `sed` substitution risks getting
the surrounding structure wrong.

### Outstanding / next session

- [ ] Confirm `timesof.uk` full-IANA-sweep result once the run
      completes (started this session, in progress)
- [ ] Consider adding `ThreadPoolExecutor` concurrency to Tier 1's
      DNS sweep if full-TLD scans become a routine operation
- [ ] `.co.uk` / `.org.uk` second-level variant generation not yet
      implemented — relevant specifically for `.uk` ccTLD domains
      like `timesof.uk`, where squatting can target the second level
      as well as a different top-level TLD entirely
- [ ] Separate, distinct task raised but deliberately deferred:
      hosting/publishing a real page to `timesof.uk` via GoDaddy —
      explicitly scoped as a different kind of action (write/deploy,
      not passive security monitoring) requiring its own planning,
      not folded into this session's domain-monitoring build. No
      GoDaddy credentials handled or requested per standing policy.
