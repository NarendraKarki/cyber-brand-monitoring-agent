"""
content_check.py
Cyber Domain and Brand Monitoring AI Agent
Classifies fetched homepage content using local Ollama/Llama3.
No data sent to external APIs. All inference is local.
"""

from __future__ import annotations
import re
import urllib.request
import urllib.error
import ssl
from typing import Optional
from . import llm

# ── constants ────────────────────────────────────────────────────────────────
FETCH_TIMEOUT   = 8
MAX_CONTENT     = 2_000
USER_AGENT      = (
    "Mozilla/5.0 (compatible; BrandMonitorBot/1.0; "
    "+https://github.com/NarendraKarki/cyber-domain-monitoring-ai-agent)"
)

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE


def _fetch_text(url: str) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(  # nosec B310
            req, timeout=FETCH_TIMEOUT, context=_SSL_CTX
        ) as resp:
            raw = resp.read(32_768).decode("utf-8", errors="replace")
        text = re.sub(r"<[^>]+>", " ", raw)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:MAX_CONTENT]
    except Exception:
        return None


def _build_prompt(domain: str, protected_brand: str, text: str) -> str:
    brand_name = protected_brand.split(".")[0].lower()
    return f"""You are a cybersecurity analyst reviewing a domain for brand impersonation.

Protected brand: {protected_brand}
Brand name keyword: {brand_name}
Suspicious domain: {domain}
Page content sample:

{text}

CLASSIFICATION RULES — read carefully before responding:

PHISHING: The page ACTIVELY impersonates the protected brand. Clear evidence required:
  - Fake login form mimicking the brand interface
  - Brand logo or name copied with intent to deceive
  - Credential harvesting targeting the brand's customers specifically
  - Explicit brand name used in deceptive context

SUSPICIOUS: Some brand similarity but not confirmed phishing:
  - Domain name similar but content unclear or partially loaded
  - Generic financial content that could be used for phishing
  - Redirect to unknown destination

PARKED: Domain is parked, for sale, or shows placeholder content:
  - "Domain for sale" message
  - Generic parking page (GoDaddy, Sedo, Dan.com etc)
  - Blank page or minimal placeholder content
  - Unrelated advertising links

LEGITIMATE: A real unrelated business or individual:
  - Established business with real content unrelated to brand
  - Same name but clearly different company or sector
  - News site, blog, or informational site

UNRELATED: Content has no connection to the protected brand at all.

IMPORTANT:
- No certificates (cert_count=0) alone does NOT indicate phishing
- Parked domains often resolve and redirect — this is NOT phishing
- Only classify PHISHING if you see CLEAR brand impersonation evidence
- When in doubt classify as SUSPICIOUS or PARKED not PHISHING

Respond in this exact JSON format with no other text:
{{
  "classification": "PHISHING" | "SUSPICIOUS" | "PARKED" | "LEGITIMATE" | "UNRELATED",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "indicators": ["specific indicator 1", "specific indicator 2"],
  "summary": "one sentence plain English summary of what the page actually shows",
  "recommended_action": "IMMEDIATE_REVIEW" | "MONITOR" | "NO_ACTION"
}}"""


def classify(
    domain: str,
    protected_brand: str,
    url: Optional[str] = None,
) -> dict:
    target_url = url or f"https://{domain}"
    text       = _fetch_text(target_url)

    if not text:
        text = _fetch_text(f"http://{domain}")

    if not text:
        return {
            "fetched":            False,
            "classification":     "UNKNOWN",
            "confidence":         "LOW",
            "indicators":         ["Could not fetch page content"],
            "summary":            "Homepage could not be retrieved for analysis.",
            "recommended_action": "MONITOR",
            "raw_text_len":       0,
        }

    prompt = _build_prompt(domain, protected_brand, text)
    result = llm.generate_json(prompt)

    return {
        "fetched":            True,
        "classification":     result.get("classification",     "UNKNOWN"),
        "confidence":         result.get("confidence",         "LOW"),
        "indicators":         result.get("indicators",         []),
        "summary":            result.get("summary",            ""),
        "recommended_action": result.get("recommended_action", "MONITOR"),
        "raw_text_len":       len(text),
    }
