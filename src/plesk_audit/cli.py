from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from plesk_audit.config import PROFILES, ConfigError
from plesk_audit.runner import collect


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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if args.command == "collect":
        try:
            run_dir = collect(args.config, args.output, args.profile)
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
