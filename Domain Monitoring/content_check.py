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
FETCH_TIMEOUT   = 8        # seconds per homepage fetch
MAX_CONTENT     = 2_000    # chars of page text sent to LLM (keep prompt small)
USER_AGENT      = (
    "Mozilla/5.0 (compatible; BrandMonitorBot/1.0; "
    "+https://github.com/NarendraKarki/cyber-domain-monitoring-ai-agent)"
)

# ── SSL context (permissive — we are reading not trusting) ───────────────────
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode    = ssl.CERT_NONE


def _fetch_text(url: str) -> Optional[str]:
    """
    Fetch homepage and return visible text content.
    Returns None on any network or HTTP error.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(             # nosec B310
            req, timeout=FETCH_TIMEOUT, context=_SSL_CTX
        ) as resp:
            raw = resp.read(32_768).decode("utf-8", errors="replace")
        # Strip tags — keep visible text only
        text = re.sub(r"<[^>]+>", " ", raw)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:MAX_CONTENT]
    except Exception:
        return None


def _build_prompt(domain: str, protected_brand: str, text: str) -> str:
    return f"""You are a cybersecurity analyst specialising in brand protection
and phishing detection for financial institutions.

Protected brand: {protected_brand}
Suspicious domain: {domain}
Page content (first {MAX_CONTENT} characters):

{text}

Analyse whether this domain is impersonating the protected brand.
Consider: login forms, logos, brand colours, financial language,
credential harvesting indicators, and registration recency signals.

Respond in this exact JSON format with no other text:
{{
  "classification": "PHISHING" | "SUSPICIOUS" | "PARKED" | "LEGITIMATE" | "UNRELATED",
  "confidence": "HIGH" | "MEDIUM" | "LOW",
  "indicators": ["indicator1", "indicator2"],
  "summary": "one sentence plain English summary",
  "recommended_action": "IMMEDIATE_REVIEW" | "MONITOR" | "NO_ACTION"
}}"""


def classify(
    domain: str,
    protected_brand: str,
    url: Optional[str] = None,
) -> dict:
    """
    Fetch the domain homepage and classify it using the local LLM.

    Returns a dict with keys:
        fetched        bool
        classification str
        confidence     str
        indicators     list[str]
        summary        str
        recommended_action str
        raw_text_len   int
    """
    target_url = url or f"https://{domain}"
    text       = _fetch_text(target_url)

    if not text:
        # Try HTTP fallback
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

    prompt   = _build_prompt(domain, protected_brand, text)
    result   = llm.generate_json(prompt)

    # Ensure all expected keys exist with safe defaults
    return {
        "fetched":            True,
        "classification":     result.get("classification",     "UNKNOWN"),
        "confidence":         result.get("confidence",         "LOW"),
        "indicators":         result.get("indicators",         []),
        "summary":            result.get("summary",            ""),
        "recommended_action": result.get("recommended_action", "MONITOR"),
        "raw_text_len":       len(text),
    }
