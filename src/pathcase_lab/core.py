"""Read-only path audit and isolated filesystem probes.

The audit key is deliberately conservative. It finds names that deserve a
cross-platform test; it does not emulate a particular filesystem.
"""

from __future__ import annotations

import errno
import fnmatch
import os
import platform
import tempfile
import unicodedata
from pathlib import Path
from typing import Sequence


SCHEMA_VERSION = 1
WINDOWS_FORBIDDEN = set('<>:"/\\|?*')
WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL"}
WINDOWS_DEVICES.update(f"COM{digit}" for digit in "123456789¹²³")
WINDOWS_DEVICES.update(f"LPT{digit}" for digit in "123456789¹²³")

PROBE_PAIRS = (
    ("ascii_case", "Atlas.txt", "atlas.txt"),
    ("canonical_unicode", "café.txt", "cafe\u0301.txt"),
    ("unicode_casefold", "Straße.txt", "STRASSE.txt"),
    ("trailing_period", "report.txt", "report.txt."),
    ("trailing_space", "notes.txt", "notes.txt "),
    ("leading_space", "plan.txt", " plan.txt"),
)


def _portable_key(name: str) -> str:
    """Candidate collision key, not an OS-specific filename comparison."""
    normalized = unicodedata.normalize("NFC", name)
    return normalized.lstrip(" ").rstrip(" .").casefold()


def _excluded(relative: str, patterns: Sequence[str]) -> bool:
    parts = relative.split("/")
    if ".git" in parts:
        return True
    for pattern in patterns:
        if fnmatch.fnmatchcase(relative, pattern):
            return True
        if pattern.endswith("/**") and relative == pattern[:-3]:
            return True
    return False


def _finding(code: str, path: str, message: str) -> dict:
    return {"code": code, "paths": [path], "message": message}


def _component_findings(name: str, relative: str) -> list[dict]:
    findings: list[dict] = []
    forbidden = sorted({ord(char) for char in name if char in WINDOWS_FORBIDDEN or ord(char) < 32})
    if forbidden:
        points = ", ".join(f"U+{point:04X}" for point in forbidden)
        findings.append(_finding("windows_forbidden_character", relative, f"Windows forbids {points} in a name."))
    base = name.split(".", 1)[0].rstrip(" ").upper()
    if base in WINDOWS_DEVICES:
        findings.append(_finding("windows_reserved_device", relative, f"{base} is a reserved Windows device name."))
    if name.startswith(" "):
        findings.append(_finding("windows_leading_space", relative, "Windows may remove a leading ASCII space."))
    if name.endswith((" ", ".")):
        findings.append(_finding("windows_trailing_dot_or_space", relative, "Windows shell paths do not preserve a trailing ASCII space or period."))
    return findings


def audit_tree(root: Path, excludes: Sequence[str] = ()) -> dict:
    """Audit sibling names without following symlinks or modifying the tree."""
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")
    findings: list[dict] = []
    errors: list[dict] = []
    scanned_directories = 0
    scanned_entries = 0

    def walk(directory: Path) -> None:
        nonlocal scanned_directories, scanned_entries
        relative_dir = directory.relative_to(root).as_posix()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            errors.append({"path": relative_dir, "error": errno.errorcode.get(exc.errno, type(exc).__name__)})
            return
        scanned_directories += 1
        visible = []
        for entry in entries:
            relative = entry.name if directory == root else f"{relative_dir}/{entry.name}"
            if _excluded(relative, excludes):
                continue
            visible.append((entry, relative))
            scanned_entries += 1
            findings.extend(_component_findings(entry.name, relative))

        buckets: dict[str, list[tuple[os.DirEntry[str], str]]] = {}
        for item in visible:
            buckets.setdefault(_portable_key(item[0].name), []).append(item)
        for key, members in sorted(buckets.items()):
            if len(members) > 1:
                paths = sorted(relative for _, relative in members)
                findings.append({
                    "code": "portable_name_collision",
                    "paths": paths,
                    "message": "Sibling names share the conservative NFC + casefold + Windows trim key.",
                    "comparison_key": key,
                })

        for entry, relative in visible:
            try:
                if entry.is_dir(follow_symlinks=False):
                    walk(Path(entry.path))
            except OSError as exc:
                errors.append({"path": relative, "error": errno.errorcode.get(exc.errno, type(exc).__name__)})

    walk(root)
    findings.sort(key=lambda item: (item["paths"][0], item["code"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "root": str(root),
        "policy": "NFC + Unicode casefold + Windows ASCII edge trim (candidate collisions)",
        "unicode_version": unicodedata.unidata_version,
        "scanned_directories": scanned_directories,
        "scanned_entries": scanned_entries,
        "findings": findings,
        "errors": errors,
    }


def _create_exclusive(path: Path, marker: bytes) -> str | None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            os.write(descriptor, marker)
        finally:
            os.close(descriptor)
    except OSError as exc:
        return errno.errorcode.get(exc.errno, type(exc).__name__)
    return None


def probe_filesystem(parent: Path) -> dict:
    """Create isolated, exclusive files under parent and remove them afterward."""
    parent = parent.expanduser().resolve(strict=True)
    if not parent.is_dir():
        raise ValueError(f"Not a directory: {parent}")
    cases = []
    with tempfile.TemporaryDirectory(prefix="pathcase-", dir=parent) as temporary:
        for case_id, first, second in PROBE_PAIRS:
            case_dir = Path(temporary) / case_id
            case_dir.mkdir()
            first_error = _create_exclusive(case_dir / first, b"first")
            second_error = None if first_error else _create_exclusive(case_dir / second, b"second")
            observed = sorted(os.listdir(case_dir))
            if first_error:
                result = "unsupported"
            elif second_error == "EEXIST":
                result = "collision"
            elif second_error:
                result = "unsupported"
            else:
                result = "distinct"
            cases.append({
                "id": case_id,
                "requested": [first, second],
                "result": result,
                "first_error": first_error,
                "second_error": second_error,
                "observed_names": observed,
                "spelling_preserved": observed == sorted([first, second]) if result == "distinct" else None,
            })
    return {
        "schema_version": SCHEMA_VERSION,
        "parent": str(parent),
        "platform": platform.system(),
        "unicode_version": unicodedata.unidata_version,
        "cases": cases,
    }
