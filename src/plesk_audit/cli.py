from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from plesk_audit.config import PROFILES, ConfigError
from plesk_audit.runner import collect, external


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="plesk-audit", description="Read-only AlmaLinux/Plesk audit"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("collect", help="Collect local audit evidence")
    cmd.add_argument("--config", type=Path, required=True)
    cmd.add_argument(
        "--output", type=Path, default=None, help="report root (default: output.directory)"
    )
    cmd.add_argument("--profile", choices=PROFILES, default=None)
    cmd.add_argument("--verbose", action="store_true", help="log collector progress to stderr")
    ext = sub.add_parser(
        "external",
        help="Opt-in external validation of allow-listed targets (sends network traffic)",
    )
    ext.add_argument("--config", type=Path, required=True)
    ext.add_argument(
        "--output", type=Path, default=None, help="report root (default: output.directory)"
    )
    ext.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="confirm written authorization to probe every configured target",
    )
    ext.add_argument("--verbose", action="store_true", help="log progress to stderr")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if args.command == "external" and not args.confirm_authorized:
        print(
            "external validation sends network traffic to the configured targets; "
            "re-run with --confirm-authorized once written authorization is in place",
            file=sys.stderr,
        )
        return 2
    if args.command in ("collect", "external"):
        try:
            if args.command == "collect":
                run_dir = collect(args.config, args.output, args.profile)
            else:
                run_dir = external(args.config, args.output)
        except ConfigError as exc:
            print(f"configuration error: {exc}", file=sys.stderr)
            return 2
        except FileExistsError:
            print("refusing to overwrite an existing report directory", file=sys.stderr)
            return 1
        print(f"reports written to {run_dir}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
