import argparse
import json
from .models import Assessment
from .scanner import parse_ports, scan_tcp, ports_to_findings
from .headers import review_headers
from .reporting import write_reports

def main():
    parser = argparse.ArgumentParser(description="Scoped VAPT assessment toolkit")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="TCP connect scan against an authorised host")
    scan.add_argument("--target", required=True)
    scan.add_argument("--ports", default="22,80,443,8080")
    scan.add_argument("--timeout", type=float, default=0.5)
    scan.add_argument("--output", default="reports/generated/scan-report")
    headers = sub.add_parser("headers", help="Review HTTP security headers")
    headers.add_argument("--url", required=True)
    headers.add_argument("--output", default="reports/generated/header-report")
    args = parser.parse_args()
    if args.command == "scan":
        results = scan_tcp(args.target, parse_ports(args.ports), args.timeout)
        findings = ports_to_findings(results)
        assessment = Assessment.create(args.target, findings, [
            "TCP connect checks only; no exploit attempts were performed.",
            "A closed_or_filtered result does not distinguish a closed port from a filtered port."
        ])
        print(json.dumps(results, indent=2))
    else:
        meta, findings = review_headers(args.url)
        assessment = Assessment.create(meta["final_url"], findings, [
            f"HTTP status code: {meta['status_code']}",
            "Header presence alone does not establish that a configuration is secure."
        ])
        print(json.dumps(meta, indent=2))
    json_path, md_path = write_reports(assessment, args.output)
    print(f"Reports written: {json_path} and {md_path}")

if __name__ == "__main__":
    main()
