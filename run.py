"""
run.py
Cyber Domain and Brand Monitoring AI Agent
Entry point — run from project root:
  python run.py
  python run.py --brand timesof.uk --mode curated
  python run.py --brand timesof.uk --mode full
"""

import argparse
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from domain_monitor import agent, report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cyber Domain and Brand Monitoring AI Agent"
    )
    parser.add_argument("--brand", default=None,
        help="Protected domain to scan (default: from config.py)")
    parser.add_argument("--mode", choices=["curated", "full"], default="curated",
        help="curated = fast | full = all 1480 IANA TLDs")
    parser.add_argument("--max-tier2", type=int, default=10,
        help="Max domains to deep-analyse in Tier 2 (default: 10)")
    parser.add_argument("--output-dir", default="reports",
        help="Directory to save reports (default: reports/)")
    return parser.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    scan_result = agent.run_scan(
        protected_brand=args.brand,
        mode=args.mode,
        max_tier2=args.max_tier2,
    )

    ts    = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d_%H%M%S")
    brand = scan_result.get("protected_brand", "unknown").replace(".", "_")

    # JSON report
    json_path = os.path.join(args.output_dir, f"scan_{brand}_{ts}.json")
    report.generate_json(scan_result, filepath=json_path)
    print(f"  JSON report saved: {json_path}")

    # Text report
    txt_path = os.path.join(args.output_dir, f"scan_{brand}_{ts}.txt")
    report.save_text(scan_result, filepath=txt_path)
    print(f"  Text report saved: {txt_path}")

    # HTML report
    html_path = os.path.join(args.output_dir, f"scan_{brand}_{ts}.html")
    report.save_html(scan_result, filepath=html_path)
    print(f"  HTML report saved: {html_path}")
    print(f"  Open in browser:   {os.path.abspath(html_path)}")

    # Print to terminal
    report.print_report(scan_result)

    high_count = scan_result.get("summary", {}).get("high_risk", 0)
    if high_count > 0:
        print(f"  WARNING: {high_count} HIGH risk finding(s) — immediate review required")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
