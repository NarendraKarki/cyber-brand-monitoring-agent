"""Brand & Domain Monitor — content status check (v1.1).

Single, polite HTTP fetch against HIGH-tier resolving candidates only,
to distinguish a parked/placeholder domain from one serving real
content. This is the same action a browser takes when a human visits
a URL — one request, no crawling, no form submission, no login
attempts. Modelled on the first content-check step used by reputable
commercial brand-monitoring vendors before a finding is escalated for
human review.

Raw HTML is never stored. Only a lightweight classification and a
handful of metadata fields are kept in the report.
"""

import re
import urllib.request
import urllib.error

from . import config

PARKING_SIGNATURES = [
    r"domain may be for sale",
    r"buy this domain",
    r"this domain is for sale",
    r"checkout the full domain details",
    r"sedoparking",
    r"parkingcrew",
    r"bodis\.com",
    r"godaddy.{0,40}parked",
    r"this web page is parked",
]

_PARKING_RE = re.compile("|".join(PARKING_SIGNATURES), re.IGNORECASE)

MAX_CONTENT_BYTES = 200_000


def _extract_title(html: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:200]
    return None


def check_content_status(domain: str) -> dict:
    """Fetch the homepage once over HTTPS (falling back to HTTP if
    HTTPS fails) and classify it. A single request per scheme only —
    no crawling, no following of internal links, no form interaction.

    Errors from each attempted scheme are recorded, not silently
    discarded, so a COULD_NOT_FETCH result always explains why."""
    attempt_errors = {}

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        request = urllib.request.Request(
            url, headers={"User-Agent": "brand-domain-monitor/0.1 (research)"}
        )
        try:
            with urllib.request.urlopen(
                request, timeout=config.REQUEST_TIMEOUT_SECONDS
            ) as response:
                status_code = response.status
                raw_bytes = response.read(MAX_CONTENT_BYTES)
                html = raw_bytes.decode("utf-8", errors="replace")

                is_parked = bool(_PARKING_RE.search(html))
                title = _extract_title(html)

                classification = "PARKED" if is_parked else "HAS_CONTENT"
                recommendation = (
                    "Likely no action needed — parking placeholder, not active content."
                    if is_parked else
                    "Recommend human review — domain is serving live content."
                )

                return {
                    "domain": domain,
                    "fetch_scheme": scheme,
                    "http_status": status_code,
                    "page_title": title,
                    "content_length_bytes": len(raw_bytes),
                    "classification": classification,
                    "matched_parking_signature": is_parked,
                    "recommendation": recommendation,
                }

        except urllib.error.HTTPError as e:
            # A real HTTP response was received, just an error status
            # (e.g. 403, 500) — this IS data, not a failure to fetch.
            attempt_errors[scheme] = f"HTTP {e.code}: {e.reason}"
            return {
                "domain": domain,
                "fetch_scheme": scheme,
                "http_status": e.code,
                "page_title": None,
                "content_length_bytes": None,
                "classification": "HAS_CONTENT",
                "matched_parking_signature": False,
                "recommendation": (
                    f"Server responded with HTTP {e.code} — recommend "
                    "human review (site exists but returned an error "
                    "status; could be access-restricted or misconfigured)."
                ),
            }
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            attempt_errors[scheme] = str(e)
            continue  # try the next scheme

    return {
        "domain": domain,
        "fetch_scheme": None,
        "http_status": None,
        "page_title": None,
        "content_length_bytes": None,
        "classification": "COULD_NOT_FETCH",
        "matched_parking_signature": False,
        "recommendation": "Could not retrieve content — recommend manual check.",
        "fetch_errors": attempt_errors,
    }
