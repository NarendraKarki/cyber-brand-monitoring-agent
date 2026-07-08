"""
report.py
Cyber Domain and Brand Monitoring AI Agent
Generates clean ASCII text reports and rich HTML reports.
"""

from __future__ import annotations
import json
import datetime
from typing import Optional


def _div(char="-", n=60):
    return char * n


# ── TEXT REPORT ──────────────────────────────────────────────────────────────

def generate_text(scan: dict) -> str:
    """Generate clean ASCII text report from scan results."""
    brand     = scan.get("protected_brand", "unknown")
    started   = scan.get("started", "")[:19].replace("T", " ")
    completed = scan.get("completed", "")[:19].replace("T", " ")
    summary   = scan.get("summary", {})
    findings  = scan.get("findings", [])

    lines = []
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
        lines += ["", "  [OK] No resolving lookalike domains found.", ""]
        lines.append("=" * 60)
        return "\n".join(lines)

    high_f   = [f for f in findings if f["risk_tier"] == "HIGH"]
    medium_f = [f for f in findings if f["risk_tier"] == "MEDIUM"]
    low_f    = [f for f in findings if f["risk_tier"] == "LOW"]

    for tier_label, tier_findings in [
        ("HIGH RISK FINDINGS", high_f),
        ("MEDIUM RISK FINDINGS", medium_f),
        ("LOW RISK FINDINGS", low_f),
    ]:
        if not tier_findings:
            continue
        lines += ["", f"  {tier_label}", _div()]
        for f in tier_findings:
            domain  = f.get("domain", "")
            ip      = f.get("ip", "")
            score   = f.get("risk_score", "?")
            threat  = f.get("threat_type", "UNKNOWN")
            urgency = f.get("urgency", "MONITOR")
            certs   = f.get("cert_count", 0)
            content = f.get("content", {})
            actions = f.get("recommended_actions", [])
            narrative = f.get("narrative", "")

            lines += [
                "",
                f"  Domain:       {domain}",
                f"  IP:           {ip}",
                f"  Risk score:   {score}/10  |  Threat: {threat}",
                f"  Urgency:      {urgency}",
                f"  Certs issued: {certs}",
            ]
            if content.get("fetched"):
                lines.append(
                    f"  Content:      {content.get('classification','UNKNOWN')} "
                    f"({content.get('confidence','')} confidence)"
                )
                if content.get("indicators"):
                    lines.append(f"  Indicators:   {', '.join(content['indicators'][:3])}")
            if narrative:
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

    if high_f:
        lines += [
            "", "=" * 60,
            "  RESPONSE WORKFLOW FOR HIGH RISK FINDINGS",
            "=" * 60, "",
            "  Step 1 - Verify manually:",
            "    Open domain. Screenshot. Do NOT click links.",
            "",
            "  Step 2 - Report to Google Safe Browsing (FREE):",
            "    safebrowsing.google.com/safebrowsing/report_phish",
            "",
            "  Step 3 - Report to domain registrar:",
            "    WHOIS lookup -> submit abuse report with evidence.",
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
            "",
            "  Step 7 - UDRP if registrar unresponsive:",
            "    ICANN UDRP filing. Cost: GBP 8,000-12,000.",
            _div(),
        ]

    lines += [
        "",
        "  Cyber Domain and Brand Monitoring AI Agent",
        "  Module 7 of 57 - AI Security Platform",
        "  github.com/NarendraKarki/cyber-domain-monitoring-ai-agent",
        "  All LLM inference is local - no data leaves your environment",
        "", "=" * 60, "",
    ]
    return "\n".join(lines)


# ── HTML REPORT ───────────────────────────────────────────────────────────────

def generate_html(scan: dict) -> str:
    """Generate rich HTML report — open in browser for screenshot."""
    brand     = scan.get("protected_brand", "unknown")
    started   = scan.get("started", "")[:19].replace("T", " ")
    completed = scan.get("completed", "")[:19].replace("T", " ")
    summary   = scan.get("summary", {})
    findings  = scan.get("findings", [])

    high_count   = summary.get("high_risk", 0)
    medium_count = summary.get("medium_risk", 0)
    low_count    = summary.get("low_risk", 0)

    risk_colors = {
        "HIGH":   {"bg": "#FEE2E2", "border": "#DC2626", "badge": "#DC2626", "text": "#991B1B"},
        "MEDIUM": {"bg": "#FEF9C3", "border": "#D97706", "badge": "#D97706", "text": "#92400E"},
        "LOW":    {"bg": "#DCFCE7", "border": "#16A34A", "badge": "#16A34A", "text": "#14532D"},
    }

    def finding_card(f):
        tier    = f.get("risk_tier", "MEDIUM")
        c       = risk_colors.get(tier, risk_colors["MEDIUM"])
        domain  = f.get("domain", "")
        ip      = f.get("ip", "")
        score   = f.get("risk_score", "?")
        threat  = f.get("threat_type", "UNKNOWN")
        urgency = f.get("urgency", "MONITOR")
        certs   = f.get("cert_count", 0)
        cert_r  = f.get("cert_most_recent", "")
        content = f.get("content", {})
        actions = f.get("recommended_actions", [])
        narrative = f.get("narrative", "")
        indicators = content.get("indicators", [])

        urgency_icon = {
            "IMMEDIATE": "&#9889;",
            "THIS_WEEK": "&#9888;",
            "MONITOR":   "&#128065;",
            "NO_ACTION": "&#10003;",
        }.get(urgency, "&#128065;")

        actions_html = "".join(
            f'<div style="padding:4px 0;color:#374151;font-size:13px">'
            f'&#8594; {a}</div>'
            for a in actions[:3]
        )

        indicators_html = ""
        if indicators:
            tags = "".join(
                f'<span style="background:#E0E7FF;color:#3730A3;'
                f'padding:2px 8px;border-radius:10px;font-size:11px;'
                f'margin-right:4px">{i}</span>'
                for i in indicators[:3]
            )
            indicators_html = f'<div style="margin-top:8px">{tags}</div>'

        return f'''
        <div style="background:{c["bg"]};border:1px solid {c["border"]};
                    border-left:4px solid {c["border"]};border-radius:8px;
                    padding:16px 20px;margin-bottom:12px">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px">
            <div>
              <span style="font-size:18px;font-weight:700;color:#0A1628">{domain}</span>
              <span style="background:{c["badge"]};color:white;font-size:11px;
                           font-weight:700;padding:2px 10px;border-radius:10px;
                           margin-left:10px">{tier}</span>
            </div>
            <div style="text-align:right">
              <div style="font-size:22px;font-weight:800;color:{c["border"]}">{score}/10</div>
              <div style="font-size:11px;color:#64748B">Risk Score</div>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:12px">
            <div style="background:white;border-radius:6px;padding:8px 12px">
              <div style="font-size:10px;color:#64748B;text-transform:uppercase">IP Address</div>
              <div style="font-size:12px;font-family:monospace;color:#1E40AF;margin-top:2px">{ip}</div>
            </div>
            <div style="background:white;border-radius:6px;padding:8px 12px">
              <div style="font-size:10px;color:#64748B;text-transform:uppercase">Threat Type</div>
              <div style="font-size:12px;font-weight:600;color:#374151;margin-top:2px">{threat}</div>
            </div>
            <div style="background:white;border-radius:6px;padding:8px 12px">
              <div style="font-size:10px;color:#64748B;text-transform:uppercase">Certificates</div>
              <div style="font-size:12px;font-weight:600;color:#374151;margin-top:2px">{certs} issued</div>
            </div>
          </div>
          <div style="background:white;border-radius:6px;padding:10px 12px;margin-bottom:10px">
            <div style="font-size:10px;color:#64748B;text-transform:uppercase;margin-bottom:4px">
              Content Classification
            </div>
            <div style="font-size:13px;color:#374151">
              <strong>{content.get("classification","UNKNOWN")}</strong>
              <span style="color:#64748B"> ({content.get("confidence","")} confidence)</span>
              &nbsp;&#124;&nbsp;
              <span style="font-size:10px;background:#E0E7FF;color:#3730A3;
                           padding:2px 8px;border-radius:10px">{content.get("recommended_action","MONITOR")}</span>
            </div>
            {indicators_html}
          </div>
          <div style="background:white;border-radius:6px;padding:10px 12px;margin-bottom:10px">
            <div style="font-size:10px;color:#64748B;text-transform:uppercase;margin-bottom:4px">Analysis</div>
            <div style="font-size:13px;color:#374151;line-height:1.5">{narrative}</div>
          </div>
          <div style="background:white;border-radius:6px;padding:10px 12px">
            <div style="font-size:10px;color:#64748B;text-transform:uppercase;margin-bottom:4px">Recommended Actions</div>
            {actions_html}
          </div>
          <div style="margin-top:10px;font-size:12px;color:{c["text"]};font-weight:600">
            {urgency_icon} Urgency: {urgency}
          </div>
        </div>'''

    findings_html = ""
    for f in findings:
        findings_html += finding_card(f)

    no_findings_html = ""
    if not findings:
        no_findings_html = '''
        <div style="background:#F0FDF4;border:1px solid #86EFAC;border-radius:8px;
                    padding:24px;text-align:center">
          <div style="font-size:32px">&#10003;</div>
          <div style="font-size:16px;font-weight:600;color:#15803D;margin-top:8px">
            No resolving lookalike domains found
          </div>
          <div style="font-size:13px;color:#64748B;margin-top:4px">
            Brand appears clean across all checked TLDs
          </div>
        </div>'''

    workflow_html = ""
    if high_count > 0:
        steps = [
            ("1", "Verify manually", "Open domain in browser. Take screenshot. Do NOT click any links or enter credentials."),
            ("2", "Report to Google Safe Browsing (FREE)", "safebrowsing.google.com/safebrowsing/report_phish — blocks in Chrome for 2 billion users within hours."),
            ("3", "Report to domain registrar", "WHOIS lookup to find registrar. Submit abuse report with screenshot evidence. Expect 24-72 hours."),
            ("4", "Report to hosting provider", "IP lookup to find host. Separate abuse report. Cloudflare/major providers: 24-48 hours."),
            ("5", "Report to national authority", "UK: report.ncsc.gov.uk &nbsp;|&nbsp; BH: cert@bh.cert.gov.bh &nbsp;|&nbsp; SA: report@cert.gov.sa"),
            ("6", "Block at your gateway NOW", "Add to email security blocklist and web proxy immediately. Do not wait for takedown."),
            ("7", "UDRP if registrar unresponsive", "ICANN UDRP filing. Cost: GBP 8,000-12,000. Reserved for persistent high-impact threats."),
        ]
        steps_html = "".join(f'''
            <div style="display:flex;gap:12px;padding:12px 0;
                        border-bottom:1px solid #E2E8F0">
              <div style="background:#DC2626;color:white;width:28px;height:28px;
                           border-radius:50%;display:flex;align-items:center;
                           justify-content:center;font-size:12px;font-weight:700;
                           flex-shrink:0">{num}</div>
              <div>
                <div style="font-size:13px;font-weight:600;color:#0A1628">{title}</div>
                <div style="font-size:12px;color:#64748B;margin-top:2px">{desc}</div>
              </div>
            </div>''' for num, title, desc in steps)
        workflow_html = f'''
        <div style="background:white;border-radius:12px;padding:24px;
                    box-shadow:0 1px 3px rgba(0,0,0,0.1);margin-top:20px">
          <h2 style="font-size:16px;font-weight:700;color:#DC2626;margin:0 0 16px">
            &#9889; Response Workflow for HIGH Risk Findings
          </h2>
          {steps_html}
        </div>'''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cyber Domain Monitor — {brand}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#F1F5F9; padding:24px; }}
</style>
</head>
<body>
  <!-- HEADER -->
  <div style="background:#0A1628;border-radius:12px;padding:24px 28px;
              margin-bottom:20px;display:flex;justify-content:space-between;
              align-items:center">
    <div>
      <div style="font-size:20px;font-weight:700;color:white">
        Cyber Domain and Brand Monitoring AI Agent
      </div>
      <div style="font-size:13px;color:#94A3B8;margin-top:4px">
        Protected brand: <strong style="color:#60A5FA">{brand}</strong>
        &nbsp;&#124;&nbsp; {started} UTC &#8594; {completed} UTC
      </div>
    </div>
    <div style="background:#16A34A;color:white;font-size:11px;font-weight:700;
                padding:6px 16px;border-radius:20px">Module 7 of 57</div>
  </div>

  <!-- SUMMARY CARDS -->
  <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px">
    <div style="background:white;border-radius:10px;padding:16px;text-align:center;
                box-shadow:0 1px 3px rgba(0,0,0,0.1)">
      <div style="font-size:28px;font-weight:800;color:#2563EB">
        {summary.get("variants_checked",0)}
      </div>
      <div style="font-size:11px;color:#64748B;text-transform:uppercase;margin-top:4px">
        Variants Checked
      </div>
    </div>
    <div style="background:white;border-radius:10px;padding:16px;text-align:center;
                box-shadow:0 1px 3px rgba(0,0,0,0.1)">
      <div style="font-size:28px;font-weight:800;color:#7C3AED">
        {summary.get("resolving",0)}
      </div>
      <div style="font-size:11px;color:#64748B;text-transform:uppercase;margin-top:4px">
        Resolving
      </div>
    </div>
    <div style="background:white;border-radius:10px;padding:16px;text-align:center;
                box-shadow:0 1px 3px rgba(0,0,0,0.1)">
      <div style="font-size:28px;font-weight:800;color:#0E7490">
        {summary.get("analysed",0)}
      </div>
      <div style="font-size:11px;color:#64748B;text-transform:uppercase;margin-top:4px">
        Analysed
      </div>
    </div>
    <div style="background:#FEE2E2;border-radius:10px;padding:16px;text-align:center;
                box-shadow:0 1px 3px rgba(0,0,0,0.1)">
      <div style="font-size:28px;font-weight:800;color:#DC2626">{high_count}</div>
      <div style="font-size:11px;color:#991B1B;text-transform:uppercase;margin-top:4px">
        HIGH Risk
      </div>
    </div>
    <div style="background:#FEF9C3;border-radius:10px;padding:16px;text-align:center;
                box-shadow:0 1px 3px rgba(0,0,0,0.1)">
      <div style="font-size:28px;font-weight:800;color:#D97706">{medium_count}</div>
      <div style="font-size:11px;color:#92400E;text-transform:uppercase;margin-top:4px">
        MEDIUM Risk
      </div>
    </div>
    <div style="background:#DCFCE7;border-radius:10px;padding:16px;text-align:center;
                box-shadow:0 1px 3px rgba(0,0,0,0.1)">
      <div style="font-size:28px;font-weight:800;color:#16A34A">{low_count}</div>
      <div style="font-size:11px;color:#14532D;text-transform:uppercase;margin-top:4px">
        LOW Risk
      </div>
    </div>
  </div>

  <!-- FINDINGS -->
  <div style="background:white;border-radius:12px;padding:24px;
              box-shadow:0 1px 3px rgba(0,0,0,0.1);margin-bottom:20px">
    <h2 style="font-size:16px;font-weight:700;color:#0A1628;margin-bottom:16px">
      Findings
    </h2>
    {findings_html or no_findings_html}
  </div>

  {workflow_html}

  <!-- FOOTER -->
  <div style="text-align:center;padding:20px;font-size:12px;color:#94A3B8">
    Cyber Domain and Brand Monitoring AI Agent &nbsp;&#124;&nbsp;
    Module 7 of 57 &nbsp;&#124;&nbsp;
    github.com/NarendraKarki/cyber-domain-monitoring-ai-agent
    &nbsp;&#124;&nbsp; All LLM inference local — no data leaves your environment
  </div>
</body>
</html>'''
    return html


# ── JSON REPORT ───────────────────────────────────────────────────────────────

def generate_json(scan: dict, filepath: Optional[str] = None) -> str:
    output = json.dumps(scan, indent=2, ensure_ascii=True)
    if filepath:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(output)
    return output


def save_text(scan: dict, filepath: str) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(generate_text(scan))


def save_html(scan: dict, filepath: str) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(generate_html(scan))


def print_report(scan: dict) -> None:
    text = generate_text(scan)
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))
