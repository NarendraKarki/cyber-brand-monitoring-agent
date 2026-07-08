# Cyber Domain and Brand Monitoring AI Agent

**Module 7 of 57 — AI Security Platform**

A local, open-source AI agent that scans 1,480 top-level domains for lookalike registrations targeting your organisation. Automatically. Locally. At zero cost.

---

## What It Does

Two-tier scanning pipeline:

**Tier 1 — DNS Resolution Sweep**
Generates character substitution and TLD variants of your protected domain, then resolves each one to identify active registrations.

**Tier 2 — Deep LLM Analysis**
For each resolving domain:
- Queries Certificate Transparency logs (crt.sh) for certificate history
- Fetches and classifies page content using local Ollama/Llama3
- Synthesises all signals into a risk narrative
- Produces risk tier: HIGH / MEDIUM / LOW

All LLM inference runs locally via Ollama. No data leaves your environment.

---

## Output

Three report formats generated after each scan:

- **JSON** — machine-readable, suitable for integration
- **Text** — plain ASCII, terminal-friendly
- **HTML** — colour-coded, open in browser, suitable for screenshots and reporting

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start Ollama with Llama3
ollama run llama3

# Run scan (curated 16 TLDs — fast)
python run.py --brand yourdomain.com

# Run full scan (all 1,480 IANA TLDs — thorough)
python run.py --brand yourdomain.com --mode full

# Open HTML report
open reports/scan_yourdomain_*.html
```

---

## Response Workflow

When the agent flags a HIGH risk domain:

1. **Verify manually** — open the domain, screenshot it, do not click anything
2. **Report to Google Safe Browsing** — safebrowsing.google.com/safebrowsing/report_phish
3. **Report to the domain registrar** — WHOIS lookup, submit abuse report with evidence
4. **Report to the hosting provider** — separate abuse report via IP lookup
5. **Notify your national cyber security authority** — search "[country] CERT" for the right channel
6. **Block at your gateway immediately** — do not wait for takedown
7. **UDRP filing if registrar is unresponsive** — last resort, GBP 8,000-12,000 per filing

---

## Architecture

```
run.py
└── domain_monitor/
    ├── config.py          — protected domain, TLD lists, settings
    ├── sources.py         — DNS resolution + Certificate Transparency queries
    ├── content_check.py   — LLM page content classification
    ├── agent.py           — scan orchestration + LLM risk synthesis
    ├── report.py          — text, HTML and JSON report generation
    └── llm.py             — Ollama/Llama3 wrapper with prompt injection defence
```

---

## Security

- All external content passes through `_sanitise()` before LLM prompt embedding
- Defends against ASI01 indirect prompt injection — a malicious lookalike domain could embed instructions in its page content designed to manipulate the classifying model
- No external API calls — all inference is local
- SAST clean — zero issues (Bandit)

---

## References and Citations

| Claim | Source |
|---|---|
| 1,480 IANA-registered TLDs | [IANA Root Zone Database](https://www.iana.org/domains/root/db) |
| Certificate Transparency public logs | [RFC 6962 — Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962) |
| crt.sh Certificate Transparency search | [crt.sh — Sectigo](https://crt.sh) |
| UDRP filing costs GBP 8,000-12,000 | [ICANN UDRP Policy](https://www.icann.org/resources/pages/udrp-2012-02-25-en) |
| Google Safe Browsing reporting | [Google Safe Browsing](https://safebrowsing.google.com/safebrowsing/report_phish/) |
| NCSC phishing reporting (UK) | [NCSC Report](https://www.ncsc.gov.uk/section/about-this-website/report-scam-website) |
| NCSC Bahrain incident reporting | [NCSC Bahrain](https://www.ncsc.gov.bh) |
| CERT-SA incident reporting (Saudi Arabia) | [CERT-SA](https://cert.gov.sa) |
| ASI01 Indirect Prompt Injection | [OWASP Agentic AI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |

---

## Part of the AI Security Platform

This agent is Module 7 of a 57-agent AI security platform being built to cover:
- Cyber Threat Intelligence
- Domain and Brand Monitoring
- Social Media Monitoring
- Vulnerability Management
- Governance and Compliance
- Threat Modelling
- Security Operations

**GitHub:** [github.com/NarendraKarki](https://github.com/NarendraKarki)

---

## Author

Narendra Karki — CISSP · CISM · CISA · CAISP

*All LLM inference is local. No data leaves your environment.*
