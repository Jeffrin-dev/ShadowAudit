"""Command-line interface for ShadowAudit."""

from __future__ import annotations

import argparse

from shadowaudit.core.policy import PolicyEngine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shadowaudit", description="ShadowAudit command-line utilities")
    subparsers = parser.add_subparsers(dest="command")

    policy_parser = subparsers.add_parser("policy", help="Policy operations")
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command")

    policy_check_parser = policy_subparsers.add_parser("check", help="Validate a policy YAML config file")
    policy_check_parser.add_argument("config", help="Path to policy YAML file")

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

    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
