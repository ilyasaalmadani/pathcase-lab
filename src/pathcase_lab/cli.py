"""Command-line entry point for pathcase-lab."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .core import audit_tree, probe_filesystem


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pathcase",
        description="Find portable filename hazards and measure filesystem name behavior.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit", help="Read-only audit of a directory tree")
    audit.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current directory)")
    audit.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Exclude a relative POSIX path glob; repeatable")
    audit.add_argument("--json", action="store_true", help="Print stable JSON")
    probe = commands.add_parser("probe", help="Measure behavior in a temporary directory")
    probe.add_argument("--parent", default=".", help="Existing directory on the filesystem to probe")
    probe.add_argument("--json", action="store_true", help="Print stable JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "audit":
            report = audit_tree(Path(arguments.path), arguments.exclude)
        else:
            report = probe_filesystem(Path(arguments.parent))
    except (OSError, ValueError) as exc:
        print(f"pathcase: {exc}", file=sys.stderr)
        return 2

    if arguments.json:
        print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    elif arguments.command == "audit":
        for finding in report["findings"]:
            paths = ", ".join(json.dumps(path, ensure_ascii=True) for path in finding["paths"])
            print(f"{finding['code']}: {paths} — {finding['message']}")
        for error in report["errors"]:
            print(f"scan_error: {json.dumps(error['path'])} — {error['error']}", file=sys.stderr)
        print(f"Scanned {report['scanned_entries']} entries in {report['scanned_directories']} directories; {len(report['findings'])} findings.")
    else:
        for case in report["cases"]:
            names = ", ".join(json.dumps(name, ensure_ascii=True) for name in case["requested"])
            print(f"{case['id']}: {case['result']} ({names})")
        print("Probe files removed.")

    if arguments.command == "audit":
        if report["errors"]:
            return 2
        if report["findings"]:
            return 1
    return 0
