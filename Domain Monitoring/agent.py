"""
agent.py
Cyber Domain and Brand Monitoring AI Agent
Orchestrates the full two-tier scan pipeline with LLM risk synthesis.

Sources API (actual keys):
  check_dns_resolution  -> {domain, resolves, ip_address}
  check_certificate_transparency -> {domain, certificates_found, entries_sample}
  scan_candidates(list) -> merged list of both above
  generate_all_candidates(domain) -> list of candidate strings
"""

from __future__ import annotations
import datetime
from typing import Optional
from . import config, sources, content_check, llm


def _most_recent_cert(entries_sample: list) -> str:
    if not entries_sample:
        return ""
    try:
        dates = [e.get("not_before", "") for e in entries_sample if e.get("not_before")]
        return max(dates) if dates else ""
    except Exception:
        return ""


def _synthesise_risk(domain, protected_brand, ip_address,
                     cert_count, cert_recent, content_result):
    content_cls = (content_result or {}).get("classification", "NOT_FETCHED")
    content_sum = (content_result or {}).get("summary", "Not analysed.")
    indicators  = (content_result or {}).get("indicators", [])

    prompt = f"""You are a senior cybersecurity analyst specialising in
brand protection for financial institutions.

Protected brand:   {protected_brand}
Suspicious domain: {domain}
IP address:        {ip_address}

Certificate Transparency:
  Certificates issued: {cert_count}
  Most recent cert:    {cert_recent if cert_recent else 'unknown'}

Content classification: {content_cls}
Content summary: {content_sum}
Indicators found: {', '.join(indicators) if indicators else 'none'}

Synthesise all signals and produce a final risk assessment.
Consider certificate count, recency, content classification,
and whether this represents an active threat to the protected brand.

Respond in this exact JSON format with no other text:
{{
  "risk_tier": "HIGH",
  "risk_score": <integer 1-10>,
  "threat_type": "PHISHING or TYPOSQUAT or DOMAIN_SQUATTING or PARKED or LEGITIMATE or UNKNOWN",
  "narrative": "two to three sentence plain English risk narrative for a CISO",
  "recommended_actions": ["action1", "action2"],
  "urgency": "IMMEDIATE or THIS_WEEK or MONITOR or NO_ACTION"
}}"""

    return llm.generate_json(prompt)


def run_scan(protected_brand=None, mode="curated", max_tier2=10):
    brand   = protected_brand or config.PROTECTED_DOMAIN
    started = datetime.datetime.utcnow().isoformat() + "Z"

    print(f"\n{'='*60}")
    print(f"  CYBER DOMAIN AND BRAND MONITORING AI AGENT")
    print(f"  Protected brand: {brand}")
    print(f"  Scan mode:       {mode}")
    print(f"  Started:         {started}")
    print(f"{'='*60}\n")

    # TIER 1
    print(f"  [TIER 1] Generating candidate domains...")
    candidates    = sources.generate_all_candidates(brand)
    print(f"  Candidates: {len(candidates)}")
    print(f"  [TIER 1] Running DNS + certificate sweep...")
    tier1_results = sources.scan_candidates(candidates)
    resolving     = [r for r in tier1_results if r.get("resolves")]
    print(f"  Checked: {len(tier1_results)}  Resolving: {len(resolving)}")

    if not resolving:
        print(f"\n  No resolving domains found.")
        return {
            "protected_brand": brand, "scan_mode": mode,
            "started": started,
            "completed": datetime.datetime.utcnow().isoformat() + "Z",
            "summary": {
                "variants_checked": len(tier1_results), "resolving": 0,
                "high_risk": 0, "medium_risk": 0, "low_risk": 0,
            },
            "findings": [],
        }

    # TIER 2
    print(f"\n  [TIER 2] Deep LLM analysis (max {max_tier2})...")
    findings = []

    for i, result in enumerate(resolving[:max_tier2], 1):
        domain      = result.get("domain", "")
        ip_address  = result.get("ip_address", "unknown")
        cert_count  = result.get("certificates_found") or 0
        cert_sample = result.get("entries_sample") or []
        cert_recent = _most_recent_cert(cert_sample)

        print(f"\n  [{i}/{min(len(resolving),max_tier2)}] {domain}")
        print(f"    IP: {ip_address}  |  Certs: {cert_count}")

        # Content classification
        content_result = None
        if cert_count > 0 or ip_address not in (None, "unknown"):
            print(f"    Classifying page content...")
            content_result = content_check.classify(domain, brand)
            print(f"    Content: {content_result.get('classification','UNKNOWN')}")

        # Risk synthesis
        print(f"    Synthesising risk...")
        risk = _synthesise_risk(domain, brand, ip_address,
                                cert_count, cert_recent, content_result)

        # Escalate if phishing confirmed
        if content_result:
            cls = content_result.get("classification", "")
            if cls in ("PHISHING", "SUSPICIOUS"):
                risk["risk_tier"] = "HIGH"
                if risk.get("risk_score", 0) < 7:
                    risk["risk_score"] = 8

        tier  = risk.get("risk_tier", "MEDIUM")
        score = risk.get("risk_score", 5)
        print(f"    Risk: {tier} ({score}/10)")

        findings.append({
            "domain":              domain,
            "ip":                  ip_address,
            "risk_tier":           tier,
            "risk_score":          score,
            "threat_type":         risk.get("threat_type", "UNKNOWN"),
            "urgency":             risk.get("urgency", "MONITOR"),
            "narrative":           risk.get("narrative", ""),
            "recommended_actions": risk.get("recommended_actions", []),
            "cert_count":          cert_count,
            "cert_most_recent":    cert_recent,
            "content": {
                "fetched":            (content_result or {}).get("fetched", False),
                "classification":     (content_result or {}).get("classification", "NOT_FETCHED"),
                "confidence":         (content_result or {}).get("confidence", ""),
                "indicators":         (content_result or {}).get("indicators", []),
                "summary":            (content_result or {}).get("summary", ""),
                "recommended_action": (content_result or {}).get("recommended_action", "MONITOR"),
            },
        })

    findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    completed = datetime.datetime.utcnow().isoformat() + "Z"
    high   = sum(1 for f in findings if f["risk_tier"] == "HIGH")
    medium = sum(1 for f in findings if f["risk_tier"] == "MEDIUM")
    low    = sum(1 for f in findings if f["risk_tier"] == "LOW")

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE  High:{high}  Medium:{medium}  Low:{low}")
    print(f"{'='*60}\n")

    return {
        "protected_brand": brand, "scan_mode": mode,
        "started": started, "completed": completed,
        "summary": {
            "variants_checked": len(tier1_results),
            "resolving":        len(resolving),
            "analysed":         len(findings),
            "high_risk":        high,
            "medium_risk":      medium,
            "low_risk":         low,
        },
        "findings": findings,
    }
