"""
main.py

CLI entry point for SecretGuard: Source Code Secret & API Key Scanner.

Usage:
    python main.py <path> [--json report.json] [--no-color]

Examples:
    python main.py .
    python main.py ./my_project --json results.json
   
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.reporter import print_console_report, write_json_report
from src.scanner import scan_directory


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="secretguard",
        description="Scan a source code directory for hardcoded secrets and API keys.",
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to the project directory to scan.",
    )
    parser.add_argument(
        "--json",
        type=str,
        metavar="FILE",
        default=None,
        help="Also write a JSON report to this file path.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in console output.",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with a non-zero status code if any Critical-severity finding is present. Useful in CI.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Run the SecretGuard CLI.

    Args:
        argv: Optional argument list (defaults to `sys.argv[1:]`).
            Exposed as a parameter mainly so this can be exercised in
            tests without spawning a subprocess.

    Returns:
        Process exit code: 0 on a clean/successful scan, 1 on a
        usage/path error, or 2 when `--fail-on-critical` is set and a
        Critical finding was found.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    target_path = Path(args.path).resolve()

    if not target_path.exists():
        print(f"Error: path does not exist: {target_path}", file=sys.stderr)
        return 1
    if not target_path.is_dir():
        print(f"Error: path is not a directory: {target_path}", file=sys.stderr)
        return 1

    summary = scan_directory(target_path)
    print_console_report(summary, use_color=not args.no_color)

    if args.json:
        json_path = Path(args.json)
        write_json_report(summary, json_path)
        print(f"\nJSON report written to: {json_path}")

    if args.fail_on_critical and summary.has_critical_findings():
        print("\nFAILED: Critical-severity secrets detected.", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())