# Cyber Brand Monitoring Agent

A lightweight, passive-by-design agent for detecting lookalike/typosquat
domains registered against a protected brand domain — built as a
companion piece to [cyber_threat_intel](https://github.com/NarendraKarki/cyber_threat_intel)
and the broader [ai-security-lab](https://github.com/NarendraKarki/ai-security-lab)
research programme.

## What it does

1. **Generates candidate lookalike domains** — character-substitution
   (homoglyph) variants and TLD swaps, against either a curated,
   evidence-based list of historically high-abuse TLDs, or the full
   IANA root zone (~1,480 TLDs) for a thorough one-time sweep.
2. **Tier 1 — broad sweep:** checks DNS resolution only across all
   generated candidates. Cheap, fast, no rate-limit concerns.
3. **Tier 2 — granular detail:** for the (typically much smaller)
   resolving subset, checks Certificate Transparency logs (crt.sh)
   and classifies risk based on what was actually observed.
4. **Content status check:** for HIGH-tier candidates only, a single
   polite HTTP fetch classifies the page as parked/placeholder or
   serving live content — never automated beyond a one-time check,
   modelled on the first-step methodology used by reputable
   commercial brand-monitoring vendors.

## What it deliberately does not do

- No active scraping, crawling beyond a single homepage, or form
  interaction with any discovered domain
- No automated conclusions of malicious intent — every finding is
  framed as a recommendation for human review, exactly as a real
  client-facing brand-protection report would be
- No bulk/rapid-fire querying of any third-party service — crt.sh
  and IANA lookups are deliberately rate-limited and polite

## Scope and honesty note

A domain resolving with a valid SSL certificate is **not** evidence
of malicious intent on its own — it may simply be an unrelated,
legitimately-registered domain that happens to share a similar
string. This agent surfaces candidates worth a human glance; it does
not, and is not designed to, make the final call.

## Usage

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m brand_monitor.agent
```

Edit `brand_monitor/config.py` to set `PROTECTED_DOMAIN`, or call
`agent.run_scan(protected_domain="yourdomain.com", use_full_tld_list=True)`
directly for a one-time thorough pre-launch sweep across the full
IANA TLD list.

## Stack

Python standard library only — `socket`, `urllib`, `json`, `re`. No
third-party dependencies for the core pipeline.

## Author

Narendra Karki · CAISP · CISSP · CISM · CISA
