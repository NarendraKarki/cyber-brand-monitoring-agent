"""Brand & Domain Monitor — lookalike generation and data sources.

Two independent signal sources, both passive and read-only:
  1. DNS resolution — does a candidate lookalike domain exist at all?
  2. Certificate Transparency logs (crt.sh) — has anyone obtained an
     SSL certificate for a candidate, even if it isn't resolving yet?

Generating candidates is pure string manipulation (no network calls).
Checking them is the only part that talks to the outside world, and
it only ever queries public, read-only sources — no scraping, no
active probing of discovered domains beyond resolution/cert checks.
"""

import socket
import os
import time
import json
import urllib.request
import urllib.error

from . import config


def generate_character_substitution_variants(domain: str) -> list[str]:
    """Generate lookalike variants by substituting one character at a
    time, using the homoglyph rules in config. Each variant differs
    from the original by exactly one character — mirrors real-world
    typosquatting, which favours minimal, hard-to-notice changes."""
    name, _, tld = domain.partition(".")
    variants = set()

    for i, char in enumerate(name):
        if char in config.HOMOGLYPH_SUBSTITUTIONS:
            for replacement in config.HOMOGLYPH_SUBSTITUTIONS[char]:
                variant_name = name[:i] + replacement + name[i + 1:]
                variants.add(f"{variant_name}.{tld}")

    return sorted(variants)


def generate_tld_variants(domain: str) -> list[str]:
    """Generate variants of the same domain name under different
    common TLDs — a separate, equally common typosquatting pattern."""
    name, _, original_tld = domain.partition(".")
    variants = set()

    for tld in config.COMMON_TLD_VARIANTS:
        candidate = f"{name}{tld}"
        if candidate != domain:
            variants.add(candidate)

    return sorted(variants)


def generate_all_candidates(domain: str) -> list[str]:
    """Combine both generation strategies into one candidate list."""
    candidates = set()
    candidates.update(generate_character_substitution_variants(domain))
    candidates.update(generate_tld_variants(domain))
    return sorted(candidates)


def check_dns_resolution(domain: str) -> dict:
    """Passive check: does this domain resolve to an IP address at
    all? No connection is made to whatever IP is returned — this is
    purely a DNS lookup, the same kind of request any browser makes
    before connecting to a site."""
    try:
        ip_address = socket.gethostbyname(domain)
        return {"domain": domain, "resolves": True, "ip_address": ip_address}
    except socket.gaierror:
        return {"domain": domain, "resolves": False, "ip_address": None}


def _summarise_certificates(entries: list[dict]) -> list[dict]:
    """Reduce crt.sh's raw certificate entries down to the handful of
    fields actually useful for review, keeping only the 5 most recent.
    crt.sh can return dozens or hundreds of historical entries for a
    long-lived domain — the full raw list is rarely needed for triage
    and makes saved reports unwieldy to read or share. Only the count
    (certificates_found) plus this trimmed sample are kept."""
    summarised = []
    for entry in entries[:5]:
        summarised.append({
            "issuer_name": entry.get("issuer_name"),
            "not_before": entry.get("not_before"),
            "not_after": entry.get("not_after"),
            "common_name": entry.get("common_name"),
        })
    return summarised


def check_certificate_transparency(domain: str) -> dict:
    """Query crt.sh's public Certificate Transparency log search for
    any certificates ever issued containing this domain name. This is
    a read-only HTTP GET to a public service — no authentication, no
    write operations, no interaction with the domain itself.

    crt.sh is a free, volunteer-run service. It can be genuinely slow
    (handled below as a recorded timeout, not a crash), and it can
    also return an HTTP 404 to mean "no certificates match this query"
    rather than an empty JSON array — that 404 case is treated as a
    legitimate zero-result finding, not an error, since it reflects
    real data (no certificates exist), not a failure to retrieve data.

    Only a trimmed summary of certificate entries is kept in the
    result (see _summarise_certificates) — certificates_found still
    reflects the TRUE total count, even though only a sample of the
    actual entries is retained, so the report stays lightweight and
    shareable without losing the headline finding."""
    url = config.CRTSH_QUERY_URL.format(domain=domain)
    request = urllib.request.Request(
        url, headers={"User-Agent": "brand-domain-monitor/0.1 (research)"}
    )

    try:
        with urllib.request.urlopen(
            request, timeout=config.REQUEST_TIMEOUT_SECONDS
        ) as response:
            raw = response.read().decode("utf-8")
            if not raw.strip():
                return {"domain": domain, "certificates_found": 0, "entries_sample": []}
            entries = json.loads(raw)
            return {
                "domain": domain,
                "certificates_found": len(entries),
                "entries_sample": _summarise_certificates(entries),
            }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"domain": domain, "certificates_found": 0, "entries_sample": []}
        return {"domain": domain, "certificates_found": None,
                 "error": f"HTTP {e.code}: {e.reason}"}

    except (
        urllib.error.URLError,
        json.JSONDecodeError,
        TimeoutError,
        OSError,
    ) as e:
        return {"domain": domain, "certificates_found": None, "error": str(e)}


def scan_candidates(candidates: list[str]) -> list[dict]:
    """Run both checks against every candidate, with a polite delay
    between requests so we are never hammering crt.sh's free public
    service with a burst of rapid-fire queries."""
    results = []
    for domain in candidates:
        dns_result = check_dns_resolution(domain)
        cert_result = check_certificate_transparency(domain)
        results.append({**dns_result, **cert_result})
        time.sleep(config.REQUEST_DELAY_SECONDS)
    return results


def fetch_iana_tld_list(force_refresh: bool = False) -> list[str]:
    """Fetch the full, current IANA root zone TLD list, with a local
    cache so we don't re-fetch 1,500+ TLDs from IANA on every run.

    Used for a thorough, one-time brand sweep (e.g. checking a domain
    name across every existing TLD before a launch) — as opposed to
    the curated, evidence-based COMMON_TLD_VARIANTS list used for
    routine, ongoing monitoring."""
    cache_path = config.IANA_TLD_CACHE_PATH

    if not force_refresh and os.path.exists(cache_path):
        cache_age_seconds = time.time() - os.path.getmtime(cache_path)
        cache_age_days = cache_age_seconds / 86400
        if cache_age_days < config.IANA_TLD_CACHE_MAX_AGE_DAYS:
            with open(cache_path, "r") as f:
                return [line.strip() for line in f if line.strip()]

    request = urllib.request.Request(
        config.IANA_TLD_LIST_URL,
        headers={"User-Agent": "brand-domain-monitor/0.1 (research)"},
    )
    with urllib.request.urlopen(
        request, timeout=config.REQUEST_TIMEOUT_SECONDS
    ) as response:
        raw = response.read().decode("utf-8")

    tlds = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tlds.append("." + line.lower())

    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w") as f:
        f.write("\n".join(tlds))

    return tlds


def generate_full_tld_candidates(domain: str) -> list[str]:
    """Generate TLD-swap candidates across the FULL IANA TLD list
    (1,500+), rather than the curated COMMON_TLD_VARIANTS subset.
    Intended for a one-time, thorough pre-launch brand sweep where
    completeness matters more than keeping the candidate count small.

    Character-substitution variants are NOT regenerated here."""
    name, _, original_tld = domain.partition(".")
    all_tlds = fetch_iana_tld_list()

    candidates = set()
    for tld in all_tlds:
        candidate = f"{name}{tld}"
        if candidate != domain:
            candidates.add(candidate)

    return sorted(candidates)
