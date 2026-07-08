"""
report.py
Cyber Domain and Brand Monitoring AI Agent
Generates clean, presentable ASCII reports from scan results.
Pure ASCII only - compatible with all Windows terminals.
"""

from __future__ import annotations
import json
import datetime
from typing import Optional


def _div(char="-", n=60):
    return char * n


def generate_text(scan: dict) -> str:
    """Generate clean ASCII text report from scan results."""
    brand     = scan.get("protected_brand", "unknown")
    started   = scan.get("started", "")[:19].replace("T", " ")
    completed = scan.get("completed", "")[:19].replace("T", " ")
    summary   = scan.get("summary", {})
    findings  = scan.get("findings", [])

    lines = []

    # HEADER
    lines += [
        "",
        "=" * 60,
        "  CYBER DOMAIN AND BRAND MONITORING AI AGENT",
        f"  Protected brand: {brand}",
        f"  Scan started:    {started} UTC",
        f"  Scan completed:  {completed} UTC",
        "=" * 60,
        "",
        "  SCAN SUMMARY",
        _div(),
        f"  Variants checked:  {summary.get('variants_checked', 0):,}",
        f"  Resolving domains: {summary.get('resolving', 0)}",
        f"  Domains analysed:  {summary.get('analysed', 0)}",
        "",
        f"  [HIGH]   HIGH risk:    {summary.get('high_risk', 0)}",
        f"  [MEDIUM] MEDIUM risk:  {summary.get('medium_risk', 0)}",
        f"  [LOW]    LOW risk:     {summary.get('low_risk', 0)}",
        _div(),
    ]

    if not findings:
        lines += [
            "",
            "  [OK] No resolving lookalike domains found.",
            "       Brand appears clean across all checked TLDs.",
            "",
            "=" * 60,
        ]
        return "\n".join(lines)

    # FINDINGS
    high_f   = [f for f in findings if f["risk_tier"] == "HIGH"]
    medium_f = [f for f in findings if f["risk_tier"] == "MEDIUM"]
    low_f    = [f for f in findings if f["risk_tier"] == "LOW"]

    for tier_label, tier_findings in [
        ("HIGH RISK FINDINGS",   high_f),
        ("MEDIUM RISK FINDINGS", medium_f),
        ("LOW RISK FINDINGS",    low_f),
    ]:
        if not tier_findings:
            continue

        lines += ["", f"  {tier_label}", _div()]

        for f in tier_findings:
            domain   = f.get("domain", "")
            ip       = f.get("ip", "")
            score    = f.get("risk_score", "?")
            threat   = f.get("threat_type", "UNKNOWN")
            urgency  = f.get("urgency", "MONITOR")
            narrative= f.get("narrative", "")
            certs    = f.get("cert_count", 0)
            cert_rec = f.get("cert_most_recent", "")
            content  = f.get("content", {})
            actions  = f.get("recommended_actions", [])

            lines += [
                "",
                f"  Domain:       {domain}",
                f"  IP:           {ip}",
                f"  Risk score:   {score}/10  |  Threat: {threat}",
                f"  Urgency:      {urgency}",
                f"  Certs issued: {certs}"
                + (f"  |  Most recent: {cert_rec}" if cert_rec else ""),
            ]

            if content.get("fetched"):
                lines.append(
                    f"  Content:      {content.get('classification','UNKNOWN')} "
                    f"({content.get('confidence','')} confidence)"
                )
                if content.get("indicators"):
                    indic = ", ".join(content["indicators"][:3])
                    lines.append(f"  Indicators:   {indic}")

            if narrative:
                # Word wrap at 54 chars
                words, line_, wrapped = narrative.split(), "", []
                for w in words:
                    if len(line_) + len(w) + 1 > 54:
                        wrapped.append(line_.strip())
                        line_ = w + " "
                    else:
                        line_ += w + " "
                if line_:
                    wrapped.append(line_.strip())
                lines.append(f"  Analysis:     {wrapped[0]}")
                for wl in wrapped[1:]:
                    lines.append(f"                {wl}")

            if actions:
                lines.append("  Actions:")
                for a in actions[:3]:
                    lines.append(f"    -> {a}")

            lines.append(_div("-", 55))

    # RESPONSE WORKFLOW
    if high_f:
        lines += [
            "",
            "=" * 60,
            "  RESPONSE WORKFLOW FOR HIGH RISK FINDINGS",
            "=" * 60,
            "",
            "  Step 1 - Verify manually:",
            "    Open domain. Screenshot. Do NOT click links.",
            "",
            "  Step 2 - Report to Google Safe Browsing (FREE):",
            "    safebrowsing.google.com/safebrowsing/report_phish",
            "    Blocks in Chrome for 2 billion users within hours.",
            "",
            "  Step 3 - Report to domain registrar:",
            "    WHOIS lookup -> submit abuse report with evidence.",
            "    Expect 24-72 hours from cooperative registrars.",
            "",
            "  Step 4 - Report to hosting provider:",
            "    IP lookup -> separate abuse report to host.",
            "",
            "  Step 5 - Report to national authority:",
            "    UK:  report.ncsc.gov.uk",
            "    BH:  cert@bh.cert.gov.bh  (BH-CERT)",
            "    SA:  report@cert.gov.sa   (CERT-SA)",
            "",
            "  Step 6 - Block at your gateway NOW:",
            "    Add to email security + web proxy immediately.",
            "    Do not wait for takedown to protect your users.",
            "",
            "  Step 7 - UDRP if registrar unresponsive:",
            "    ICANN UDRP filing. Cost: GBP 8,000-12,000.",
            "    Reserved for persistent high-impact threats.",
            _div(),
        ]

    # FOOTER
    lines += [
        "",
        "  Cyber Domain and Brand Monitoring AI Agent",
        "  Module 7 of 57 - AI Security Platform",
        "  github.com/NarendraKarki/cyber-domain-monitoring-ai-agent",
        "  All LLM inference is local - no data leaves your environment",
        "",
        "=" * 60,
        "",
    ]

    return "\n".join(lines)


def generate_json(scan: dict, filepath: Optional[str] = None) -> str:
    """Generate machine-readable JSON report."""
    output = json.dumps(scan, indent=2, ensure_ascii=True)
    if filepath:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(output)
    return output


def save_text(scan: dict, filepath: str) -> None:
    """Write text report to file."""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(generate_text(scan))


def print_report(scan: dict) -> None:
    """Print formatted report to terminal."""
    text = generate_text(scan)
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))
