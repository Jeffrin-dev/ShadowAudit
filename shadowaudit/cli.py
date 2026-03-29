"""Command-line interface for ShadowAudit."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from dataclasses import asdict

from shadowaudit.core.audit import AuditLogger
from shadowaudit.core.models import AuditEvent
from shadowaudit.core.policy import PolicyEngine
from shadowaudit.core.scanner import PIIScanner
from shadowaudit.core.secrets import SecretsDetector
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

    scan_parser = subparsers.add_parser("scan", help="Scan input text for PII entities")
    scan_parser.add_argument("text", nargs="+", help="Text to scan")

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

    if args.command == "scan":
        text = " ".join(args.text)
        scanner = PIIScanner(fast_mode=True)
        secrets_detector = SecretsDetector()
        scan_result = scanner.scan(text)
        scan_result.secrets_found = secrets_detector.detect(text)
        scan_result.action_taken = "detected" if (scan_result.detected_entities or scan_result.secrets_found) else "clean"

        audit_event = AuditEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            request_id=scan_result.request_id,
            scan_result=scan_result,
            policy_applied="none",
            model_target="cli",
            response_clean=True,
        )
        AuditLogger("audit.log").append(audit_event)

        payload = scan_result.model_dump() if hasattr(scan_result, "model_dump") else asdict(scan_result)
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
