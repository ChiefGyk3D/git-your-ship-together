#!/usr/bin/env python3
"""Expand Markdown globs, run rumdl, and bound GitHub annotations."""

from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

MAX_ANNOTATIONS = 50
MAX_FILES = 10_000
MAX_PATTERNS = 100
RULE = re.compile(r"\b(MD\d{3})\b")
ANNOTATION = re.compile(r"^::(?:error|warning) (?P<properties>[^:]*)::(?P<message>.*)$")


class InputError(Exception):
    """A caller input cannot safely name the requested files."""


def command_escape(value: str, *, property_value: bool = False) -> str:
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def inside(root: Path, path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise InputError(f"{label} must be a regular file inside the repository") from exc
    if not resolved.is_file():
        raise InputError(f"{label} must be a regular file inside the repository")
    return resolved


def relative_input(root: Path, value: str, label: str) -> Path:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts or "\\" in value or "\x00" in value:
        raise InputError(f"{label} must be a repository-relative path without traversal")
    return inside(root, root / pure, label)


def expand(root: Path, value: str) -> list[str]:
    patterns = [line.strip() for line in value.splitlines() if line.strip()]
    if not patterns:
        raise InputError("globs must contain at least one non-empty pattern")
    if len(patterns) > MAX_PATTERNS:
        raise InputError(f"globs contains more than {MAX_PATTERNS} patterns")
    found: set[str] = set()
    for pattern in patterns:
        pure = PurePosixPath(pattern)
        if pure.is_absolute() or ".." in pure.parts or "\\" in pattern or "\x00" in pattern:
            raise InputError(f"glob {pattern!r} must stay inside the repository")
        try:
            matches = glob.glob(pattern, root_dir=root, recursive=True, include_hidden=True)
        except (OSError, re.error) as exc:
            raise InputError(f"glob {pattern!r} is invalid") from exc
        for name in matches:
            path = inside(root, root / name, f"glob match {name!r}")
            found.add(path.relative_to(root).as_posix())
            if len(found) > MAX_FILES:
                raise InputError(f"globs matched more than {MAX_FILES} files")
    if not found:
        raise InputError("globs matched no regular files: nothing to lint is not a pass")
    return sorted(found)


def properties(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in value.split(","):
        key, separator, item_value = item.partition("=")
        if separator:
            result[key.strip()] = item_value.strip()
    return result


def normalize(line: str, level: str) -> str | None:
    match = ANNOTATION.fullmatch(line)
    if not match:
        return None
    props = properties(match["properties"])
    rule = RULE.search(f"{props.get('title', '')} {match['message']}")
    path = props.get("file", "")
    line_number = props.get("line", "")
    if not rule or not path or not line_number.isdigit() or int(line_number) < 1:
        return None
    column = props.get("col", "")
    message = RULE.sub("", match["message"], count=1).lstrip(" :-")
    message = " ".join(message.split())[:300] or "Markdown lint finding"
    metadata = [
        f"file={command_escape(path, property_value=True)}",
        f"line={line_number}",
    ]
    if column.isdigit() and int(column) > 0:
        metadata.append(f"col={column}")
    metadata.append(f"title={rule.group(1)}")
    return f"::{level} {','.join(metadata)}::{rule.group(1)}: {command_escape(message)}"


def write_findings(count: int) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"findings={count}\n")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--rumdl", type=Path, required=True)
    parser.add_argument("--globs", required=True)
    parser.add_argument("--config", default="")
    parser.add_argument("--default-config", type=Path, required=True)
    parser.add_argument("--fail-on-findings", choices=("true", "false"), required=True)
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            raise InputError("root is not a directory")
        files = expand(root, args.globs)
        config = (
            relative_input(root, args.config, "config")
            if args.config
            else inside(args.default_config.parent.resolve(), args.default_config, "built-in config")
        )
    except (InputError, OSError) as exc:
        print(f"::error title=markdown lint input::{command_escape(str(exc))}")
        return 2

    command = [
        str(args.rumdl),
        "check",
        "--config",
        str(config),
        "--output-format",
        "github",
        "--",
        *files,
    ]
    try:
        done = subprocess.run(command, cwd=root, capture_output=True, text=True, timeout=600, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"::error title=markdown lint::rumdl failed to run ({type(exc).__name__})")
        return 2

    level = "error" if args.fail_on_findings == "true" else "warning"
    annotations = [item for line in done.stdout.splitlines() if (item := normalize(line, level)) is not None]
    if done.returncode not in (0, 1) or (done.returncode == 1 and not annotations):
        print(f"::error title=markdown lint::rumdl failed with exit {done.returncode} and no usable findings")
        return 2
    for item in annotations[:MAX_ANNOTATIONS]:
        print(item)
    if len(annotations) > MAX_ANNOTATIONS:
        print(f"::notice title=markdown lint::{len(annotations) - MAX_ANNOTATIONS} more finding(s) omitted")
    write_findings(len(annotations))
    if annotations:
        print(f"rumdl found {len(annotations)} Markdown issue(s)")
        return 1 if args.fail_on_findings == "true" else 0
    print(f"rumdl checked {len(files)} file(s), no findings")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
