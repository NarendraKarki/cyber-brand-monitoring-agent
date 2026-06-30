"""Brand & Domain Monitor — configuration.

Defines the brand/domain being protected and the rules used to
generate plausible lookalike (typosquat) variants for it.

Following the cyber_threat_intel convention: standard library only,
no third-party dependencies for the core lookup logic.
"""

# ── Target brand to protect ─────────────────────────────────────────
# IANA-reserved domain — safe, unambiguous test target for v1.
# No authorization questions, no risk of touching real infrastructure.
PROTECTED_DOMAIN = "example.com"

# ── Lookalike generation rules ──────────────────────────────────────
# Common keyboard-adjacent substitutions used in real typosquatting.
# Source: well-documented homoglyph/typo patterns (not exhaustive —
# v1 favours precision over recall, expand later if false negatives
# become a problem in practice).
HOMOGLYPH_SUBSTITUTIONS = {
    "o": ["0"],
    "i": ["1", "l"],
    "l": ["1", "i"],
    "e": ["3"],
    "a": ["4"],
    "s": ["5"],
}

# TLD variants worth checking alongside the original TLD.
COMMON_TLD_VARIANTS = [
    # Legacy / high-volume (kept for baseline coverage)
    ".com", ".net", ".org", ".co", ".info", ".biz",
    # Consistently flagged across multiple independent abuse reports
    # (Spamhaus, Interisle, CSC) as disproportionately phishing-heavy
    ".xyz", ".top", ".xin", ".bond", ".cfd", ".click", ".icu", ".cyou",
    # ccTLDs noted in Interisle Phishing Landscape report as showing
    # recent phishing campaign spikes
    ".ru", ".es",
]

# Certificate transparency log query endpoint (crt.sh, public, free,
# no API key required, no authentication, read-only).
CRTSH_QUERY_URL = "https://crt.sh/?q={domain}&output=json"

# Be a polite, rate-limited client — crt.sh is a free public service
# maintained by volunteers, not a service to hammer.
REQUEST_TIMEOUT_SECONDS = 10
REQUEST_DELAY_SECONDS = 1.0

# Full IANA root zone TLD list — for a thorough, one-time pre-launch
# brand sweep (as opposed to COMMON_TLD_VARIANTS, which is a curated,
# evidence-based subset for routine/ongoing monitoring). Cached
# locally since the full list rarely changes and there's no reason
# to re-fetch 1,500+ TLDs from IANA on every run.
IANA_TLD_LIST_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
IANA_TLD_CACHE_PATH = "tld_cache/iana_tlds.txt"
IANA_TLD_CACHE_MAX_AGE_DAYS = 30
