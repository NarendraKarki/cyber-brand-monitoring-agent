"""
report.py
Cyber Domain and Brand Monitoring AI Agent
Generates clean, presentable reports from scan results.
"""

from __future__ import annotations
import json
import datetime
from typing import Optional


# ── risk colours for terminal output ────────────────────────────────────────
_RISK_EMOJI = {
    "HIGH":   "🔴",
    "MEDIUM": "🟡",
    "LOW":    "🟢",
}

_URGENCY_LABEL = {
    "IMMEDIATE":  "⚡ IMMEDIATE ACTION REQUIRED",
    "THIS_WEEK":  "⚠  Action required this week",
    "MONITOR":    "👁  Monitor closely",
    "NO_ACTION":  "✓  No action required",
}


def _divider(char="─", n=60):
    return char * n


def generate_text(scan: dict) -> str:
    """
    Generate a clean human-readable text report from scan results.
    Suitable for terminal display and LinkedIn screenshots.
    """
    brand     = scan.get("protected_brand", "unknown")
    started   = scan.get("started", "")[:19].replace("T", " ")
    completed = scan.get("completed", "")[:19].replace("T", " ")
    summary   = scan.get("summary", {})
    findings  = scan.get("findings", [])

    lines = []

    # ── HEADER ────────────────────────────────────────────────────────────
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
        _divider(),
        f"  Variants checked:  {summary.get('variants_checked', 0):,}",
        f"  Resolving domains: {summary.get('resolving', 0)}",
        f"  Domains analysed:  {summary.get('analysed', 0)}",
        "",
        f"  🔴 HIGH risk:      {summary.get('high_risk', 0)}",
        f"  🟡 MEDIUM risk:    {summary.get('medium_risk', 0)}",
        f"  🟢 LOW risk:       {summary.get('low_risk', 0)}",
        _divider(),
    ]

    if not findings:
        lines += [
            "",
            "  ✅ No resolving lookalike domains found.",
            "     Brand appears clean across all checked TLDs.",
            "",
        ]
        lines.append("=" * 60)
        return "\n".join(lines)

    # ── FINDINGS ──────────────────────────────────────────────────────────
    high_findings   = [f for f in findings if f["risk_tier"] == "HIGH"]
    medium_findings = [f for f in findings if f["risk_tier"] == "MEDIUM"]
    low_findings    = [f for f in findings if f["risk_tier"] == "LOW"]

    for tier_label, tier_findings in [
        ("HIGH RISK FINDINGS",   high_findings),
        ("MEDIUM RISK FINDINGS", medium_findings),
        ("LOW RISK FINDINGS",    low_findings),
    ]:
        if not tier_findings:
            continue

        emoji = _RISK_EMOJI.get(tier_label.split()[0], "")
        lines += ["", f"  {emoji} {tier_label}", _divider()]

        for f in tier_findings:
            domain   = f.get("domain", "")
            ip       = f.get("ip", "")
            score    = f.get("risk_score", "?")
            threat   = f.get("threat_type", "UNKNOWN")
            urgency  = _URGENCY_LABEL.get(f.get("urgency", "MONITOR"), "Monitor")
            narrative= f.get("narrative", "")
            certs    = f.get("cert_count", 0)
            cert_rec = f.get("cert_most_recent", "")
            content  = f.get("content", {})
            actions  = f.get("recommended_actions", [])

            lines += [
                "",
                f"  Domain:       {domain}",
                f"  IP:           {ip}",
                f"  Risk score:   {score}/10  |  Threat type: {threat}",
                f"  Urgency:      {urgency}",
                f"  Certificates: {certs} issued{f'  |  Most recent: {cert_rec}' if cert_rec else ''}",
            ]

            if content.get("fetched"):
                lines += [
                    f"  Content:      {content.get('classification', 'UNKNOWN')} "
                    f"({content.get('confidence', '')} confidence)",
                ]
                if content.get("indicators"):
                    lines.append(
                        f"  Indicators:   {', '.join(content['indicators'][:3])}"
                    )

            if narrative:
                # Word-wrap narrative at 55 chars
                words   = narrative.split()
                wrapped = []
                line_   = ""
                for w in words:
                    if len(line_) + len(w) + 1 > 55:
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
                lines.append(f"  Actions:")
                for a in actions[:3]:
                    lines.append(f"    → {a}")

            lines.append(_divider("-", 55))

    # ── RESPONSE WORKFLOW ─────────────────────────────────────────────────
    if high_findings:
        lines += [
            "",
            "=" * 60,
            "  RESPONSE WORKFLOW FOR HIGH RISK FINDINGS",
            "=" * 60,
            "",
            "  Step 1 — Verify manually:",
            "    Open domain. Screenshot. Do NOT click links.",
            "",
            "  Step 2 — Report to Google Safe Browsing (FREE):",
            "    safebrowsing.google.com/safebrowsing/report_phish",
            "    Blocks in Chrome for 2 billion users within hours.",
            "",
            "  Step 3 — Report to domain registrar:",
            "    WHOIS lookup → submit abuse report with evidence.",
            "    Expect 24-72 hours from cooperative registrars.",
            "",
            "  Step 4 — Report to hosting provider:",
            "    IP lookup → separate abuse report to host.",
            "    Cloudflare/major providers: 24-48 hours.",
            "",
            "  Step 5 — Report to national authority:",
            "    UK:  report.ncsc.gov.uk",
            "    BH:  cert@bh.cert.gov.bh (BH-CERT)",
            "    SA:  report@cert.gov.sa (CERT-SA)",
            "",
            "  Step 6 — Block at gateway NOW:",
            "    Add to email security + web proxy immediately.",
            "    Do not wait for takedown to protect your users.",
            "",
            "  Step 7 — UDRP if registrar unresponsive:",
            "    ICANN UDRP filing. Cost: £8,000-12,000.",
            "    Reserved for persistent high-impact threats.",
            _divider(),
        ]

    # ── FOOTER ────────────────────────────────────────────────────────────
    lines += [
        "",
        "  Cyber Domain and Brand Monitoring AI Agent",
        "  Module 7 — AI Security Platform",
        "  github.com/NarendraKarki/cyber-domain-monitoring-ai-agent",
        "  All LLM inference local — no data leaves your environment",
        "",
        "=" * 60,
        "",
    ]

    return "\n".join(lines)


def generate_json(scan: dict, filepath: Optional[str] = None) -> str:
    """
    Generate machine-readable JSON report.
    Optionally write to file.
    """
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
    print(generate_text(scan))
