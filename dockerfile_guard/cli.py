"""Command Line Interface for dockerfile-guard."""

import argparse
import json
import os
from pathlib import Path
import sys
from typing import List, Optional

from dockerfile_guard import __version__
from dockerfile_guard.formatter import Formatter
from dockerfile_guard.linter import Linter
from dockerfile_guard.rules import ALL_RULES, Severity


def safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or "utf-8"
        print(text.encode(enc, errors="replace").decode(enc))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dockerfile-guard",
        description="A fast static analyzer and optimization advisor for Dockerfiles.",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # scan command
    scan_p = subparsers.add_parser("scan", help="Scan a Dockerfile for security and optimization issues")
    scan_p.add_argument(
        "path",
        nargs="?",
        default="Dockerfile",
        help="Path to Dockerfile or directory containing Dockerfile (default: ./Dockerfile)",
    )
    scan_p.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text)",
    )
    scan_p.add_argument(
        "-o",
        "--output",
        help="Save output to specified file path instead of stdout",
    )
    scan_p.add_argument(
        "--ignore",
        help="Comma-separated list of rule IDs to ignore (e.g. 'OPT004,SEC001')",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=["error", "warning", "info"],
        help="Exit with non-zero code if issues of specified severity or higher are found",
    )
    scan_p.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Minimum required health score (0-100). Fails if score is below this threshold.",
    )

    # rules command
    subparsers.add_parser("rules", help="List all available linting and security rules")

    # init command
    init_p = subparsers.add_parser("init", help="Create default configuration file")
    init_p.add_argument(
        "-o",
        "--output",
        default=".dockerfile-guard.json",
        help="Output config file path (default: .dockerfile-guard.json)",
    )

    return parser


def handle_rules(args: argparse.Namespace) -> int:
    safe_print("\nDockerfile Guard Available Rules:")
    safe_print("=" * 70)
    for rule in ALL_RULES:
        safe_print(f"[{rule.severity.value}] {rule.rule_id} - {rule.title}")
        safe_print(f"  Description: {rule.description}")
        safe_print("")
    safe_print(f"Total Rules: {len(ALL_RULES)}\n")
    return 0


def handle_init(args: argparse.Namespace) -> int:
    config_dict = {
        "ignored_rules": [],
        "min_score": 80,
        "fail_on": "warning",
    }
    target = Path(args.output)
    if target.exists():
        print(f"Error: Config file '{target}' already exists.", file=sys.stderr)
        return 1

    target.write_text(json.dumps(config_dict, indent=2), encoding="utf-8")
    safe_print(f"Created configuration file at '{target}'")
    return 0


def handle_scan(args: argparse.Namespace) -> int:
    target_path = Path(args.path)

    # If directory given, look for Dockerfile inside
    if target_path.is_dir():
        candidate = target_path / "Dockerfile"
        if candidate.is_file():
            target_path = candidate
        else:
            print(f"Error: No Dockerfile found in directory '{target_path}'", file=sys.stderr)
            return 1

    if not target_path.is_file():
        print(f"Error: Dockerfile not found at '{target_path}'", file=sys.stderr)
        return 1

    # Load optional config file if exists
    ignored: List[str] = []
    min_score = args.min_score
    fail_on = args.fail_on

    cfg_candidate = target_path.parent / ".dockerfile-guard.json"
    if cfg_candidate.is_file():
        try:
            cfg_data = json.loads(cfg_candidate.read_text(encoding="utf-8"))
            ignored.extend(cfg_data.get("ignored_rules", []))
            if not min_score:
                min_score = cfg_data.get("min_score", 0)
            if not fail_on:
                fail_on = cfg_data.get("fail_on")
        except Exception:
            pass

    if args.ignore:
        ignored.extend([x.strip() for x in args.ignore.split(",") if x.strip()])

    linter = Linter(ignored_rules=ignored)
    result = linter.lint_file(str(target_path))

    # Format output
    if args.format == "json":
        output = Formatter.format_json(result)
    elif args.format == "markdown":
        output = Formatter.format_markdown(result)
    else:
        output = Formatter.format_terminal(result)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        safe_print(f"Report written to '{args.output}'")
    else:
        safe_print(output)

    # Check exit condition
    should_fail = False

    if min_score > 0 and result.score < min_score:
        safe_print(f"FAILED: Health score {result.score} is below minimum threshold of {min_score}")
        should_fail = True

    if fail_on:
        lvl = fail_on.lower()
        if lvl == "error" and result.error_count > 0:
            should_fail = True
        elif lvl == "warning" and (result.error_count > 0 or result.warning_count > 0):
            should_fail = True
        elif lvl == "info" and len(result.issues) > 0:
            should_fail = True

    return 1 if should_fail else 0


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "rules":
        return handle_rules(args)
    elif args.command == "init":
        return handle_init(args)
    elif args.command == "scan":
        return handle_scan(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
