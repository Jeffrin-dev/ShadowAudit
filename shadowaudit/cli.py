"""Command-line interface for ShadowAudit."""

from __future__ import annotations

import argparse
import json

from shadowaudit.core.policy import PolicyEngine
from shadowaudit.reports.gdpr_report import generate_gdpr_report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shadowaudit", description="ShadowAudit command-line utilities")
    subparsers = parser.add_subparsers(dest="command")

    policy_parser = subparsers.add_parser("policy", help="Policy operations")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command")

    policy_check_parser = policy_subparsers.add_parser("check", help="Validate a policy YAML config file")
    policy_check_parser.add_argument("config", help="Path to policy YAML file")

    report_parser = subparsers.add_parser("report", help="Generate compliance reports")
    report_parser.add_argument("--format", choices=["gdpr"], required=True, help="Report format")
    report_parser.add_argument("--from", dest="from_date", required=True, help="Start date (YYYY-MM-DD)")
    report_parser.add_argument("--to", dest="to_date", required=True, help="End date (YYYY-MM-DD)")

    proxy_parser = subparsers.add_parser("proxy", help="Run a local HTTP proxy")
    proxy_parser.add_argument("--port", type=int, default=8080, help="Local listening port")
    proxy_parser.add_argument("--target", default="https://api.openai.com", help="Upstream API base URL")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "policy" and args.policy_command == "check":
        try:
            engine = PolicyEngine.from_file(args.config)
        except Exception as exc:  # pragma: no cover - CLI guard.
            print(f"INVALID: {exc}")
            return 1

        print(f"VALID: loaded {len(engine.policies)} policies from {args.config}")
        return 0

    if args.command == "report" and args.format == "gdpr":
        report = generate_gdpr_report(args.from_date, args.to_date)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    if args.command == "proxy":
        from shadowaudit.sdk.proxy import run_proxy_server

        run_proxy_server(port=args.port, target=args.target)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
