"""Brand & Domain Monitor — orchestration agent.

Pipeline:
    1. GENERATE   produce lookalike domain candidates for the
                  protected brand
    2. SCAN       check DNS resolution + Certificate Transparency
                  logs for every candidate (both passive, read-only)
    3. CLASSIFY   assign each result a risk tier based on what was
                  actually observed — no speculation beyond the data
    4. CONTENT    for HIGH-tier resolving candidates only, fetch the
                  homepage once and classify parked vs live content
    5. REPORT     write a structured, timestamped record to disk

This agent makes no automated decisions and takes no automated
action against any discovered domain. It produces a report for a
human to review. Nothing beyond passive DNS/certificate lookups and
a single homepage fetch (HIGH-tier candidates only) is performed
against any candidate domain.
"""

import json
import os
from datetime import datetime, timezone

from . import config, sources, content_check


def classify_risk(result: dict) -> str:
    """Assign a risk tier based purely on what was actually observed.
    No inference beyond the two signals collected — resolution status
    and certificate count."""
    resolves = result.get("resolves", False)
    cert_count = result.get("certificates_found")

    if cert_count is None:
        return "UNKNOWN — certificate transparency check failed"
    if resolves and cert_count > 0:
        return "HIGH — domain resolves AND has a certificate issued"
    if not resolves and cert_count > 0:
        return "MEDIUM — certificate issued, not yet resolving (possible staging)"
    if resolves and cert_count == 0:
        return "MEDIUM — resolves but no certificate found (unusual, worth a manual look)"
    return "LOW — no resolution, no certificate"


def run_scan(protected_domain: str = None, use_full_tld_list: bool = False) -> dict:
    """Run the two-tier pipeline once and return a structured result.

    Tier 1 — broad sweep: generate candidates across the full TLD
    list and check DNS resolution only. Cheap and fast, no rate-limit
    concerns, safe to run across a larger TLD set.

    Tier 2 — granular detail: for the (typically much smaller)
    subset that actually resolves, run the full pipeline —
    certificate transparency lookup, risk classification, and
    content status check for HIGH-tier results."""
    domain = protected_domain or config.PROTECTED_DOMAIN
    timestamp = datetime.now(timezone.utc)

    if use_full_tld_list:
        char_variants = sources.generate_character_substitution_variants(domain)
        tld_variants = sources.generate_full_tld_candidates(domain)
        all_candidates = sorted(set(char_variants) | set(tld_variants))
    else:
        all_candidates = sources.generate_all_candidates(domain)

    tier1_sweep = [sources.check_dns_resolution(c) for c in all_candidates]
    resolving_candidates = [r["domain"] for r in tier1_sweep if r["resolves"]]

    raw_results = sources.scan_candidates(resolving_candidates)

    classified_results = []
    for result in raw_results:
        risk_tier = classify_risk(result)
        classified_results.append({**result, "risk_tier": risk_tier})

    risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "UNKNOWN": 3}
    classified_results.sort(
        key=lambda r: risk_order.get(r["risk_tier"].split(" ")[0], 9)
    )

    summary = {
        "protected_domain": domain,
        "scan_timestamp_utc": timestamp.isoformat(),
        "tier1_candidates_generated": len(all_candidates),
        "tier1_candidates_resolving": len(resolving_candidates),
        "tier2_candidates_scanned": len(raw_results),
        "findings_by_tier": {
            tier: sum(1 for r in classified_results if r["risk_tier"].startswith(tier))
            for tier in ["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        },
        "scope_note": (
            "Tier 1: DNS resolution only, across the full TLD list. "
            "Tier 2: Certificate Transparency lookup and content check "
            "(HIGH-tier only) for the resolving subset only. No "
            "crawling, no form interaction, no comparison against the "
            "protected domain's own content."
        ),
        "non_resolving_candidates": [
            r["domain"] for r in tier1_sweep if not r["resolves"]
        ],
        "results": classified_results,
    }

    high_tier_domains = [
        r["domain"] for r in classified_results
        if r["risk_tier"].startswith("HIGH")
    ]
    content_findings = [
        content_check.check_content_status(d) for d in high_tier_domains
    ]
    summary["content_check_results"] = content_findings

    return summary

def save_report(summary: dict, output_dir: str = "reports") -> str:
    """Write the scan result to a timestamped JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"scan-{summary['protected_domain'].replace('.', '_')}-{timestamp_str}.json"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump(summary, f, indent=2)

    return filepath


if __name__ == "__main__":
    print(f"Scanning lookalikes for: {config.PROTECTED_DOMAIN}")
    print("This may take a moment — one request per candidate, "
          f"{config.REQUEST_DELAY_SECONDS}s delay between each.\n")

    result = run_scan()
    report_path = save_report(result)

    print(f"\n{'='*60}")
    print(f"Scan complete: {result['protected_domain']}")
    print(f"Tier 1 — candidates generated: {result['tier1_candidates_generated']}")
    print(f"Tier 1 — resolving: {result['tier1_candidates_resolving']}")
    print(f"Tier 2 — scanned: {result['tier2_candidates_scanned']}")
    print(f"Findings by tier: {result['findings_by_tier']}")
    if result['content_check_results']:
        print(f"Content checks run: {len(result['content_check_results'])}")
        for c in result['content_check_results']:
            print(f"  {c['domain']}: {c['classification']} — {c['recommendation']}")
    print(f"Report saved to: {report_path}")
    print(f"{'='*60}\n")
