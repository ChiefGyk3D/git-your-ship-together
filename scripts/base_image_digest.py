#!/usr/bin/env python3
"""The two pure steps of the base-image digest check: read the pins, compare the scans.

Stdlib only. The workflow `base-image-digest.yml` carries a byte-identical copy of this file
(tests/test_base_image_digest.py holds the two together) and does the networked part (resolve the
current digest of each tag, scan both digests with Trivy) around it.

    python3 -I base_image_digest.py list DOCKERFILE [--allow-unpinned]
        Print a JSON array of the external base images the file pins:
        [{"line": 4, "image": "python:3.14-slim", "repo": "python", "tag": "3.14-slim",
          "digest": "sha256:..."}]. A FROM that is not a plain, resolvable, pinned external image
        is a failure (exit 1, `FAIL` lines on stdout); so is a file with no external image at all.

    python3 -I base_image_digest.py diff PINNED.json CURRENT.json
        Both are `trivy image --format json` reports. Print the findings the pinned digest has that
        the current digest does not, and exit 1 if there is one: the bump would fix it. A finding in
        both is not a reason to bump, so it never fails. A finding with no fixed version is not
        actionable either, and is skipped even if the report carries it.

Dockerfile text and Trivy reports are data. Values taken from them are printed JSON-escaped.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

MAX_BYTES = 8 << 20
NAME = r"(?:[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]{1,5})?/)?[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*"
IMAGE = re.compile(rf"(?P<repo>{NAME})(?::(?P<tag>[A-Za-z0-9_][A-Za-z0-9._-]{{0,127}}))?(?:@(?P<digest>sha256:[0-9a-f]{{64}}))?")
ARG_LINE = re.compile(r"ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?", re.IGNORECASE)
VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def q(value: object) -> str:
    text = value if isinstance(value, str) else repr(value)
    return json.dumps(text[:200], ensure_ascii=True)


def logical_lines(text: str) -> list[tuple[int, str]]:
    """(first line number, instruction) with continuations joined and comment lines dropped."""
    out: list[tuple[int, str]] = []
    pending, start = "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("#"):  # a comment, also in the middle of a continued instruction
            continue
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        full = (pending + line).strip()
        pending = ""
        if full:
            out.append((start, full))
    if pending.strip():
        out.append((start, pending.strip()))
    return out


def substitute(value: str, args: dict[str, str]) -> str:
    return VAR.sub(lambda m: args.get(m.group(1) or m.group(2), m.group(0)), value)


def pins(text: str, allow_unpinned: bool = False) -> tuple[list[dict[str, object]], list[str]]:
    problems: list[str] = []
    found: list[dict[str, object]] = []
    args: dict[str, str] = {}
    stages: set[str] = set()
    seen_from = False
    for number, line in logical_lines(text):
        word, _, rest = line.partition(" ")
        word = word.upper()
        if word == "ARG" and not seen_from:
            m = ARG_LINE.fullmatch(line)
            if m and m.group(2) is not None:
                args[m.group(1)] = m.group(2).strip().strip("\"'")
            continue
        if word != "FROM":
            continue
        seen_from = True
        tokens = rest.split()
        while tokens and tokens[0].startswith("--"):
            tokens.pop(0)
        if not tokens:
            problems.append(f"line {number}: FROM names no image")
            continue
        raw_image = tokens[0]
        if len(tokens) >= 3 and tokens[1].upper() == "AS":
            stages.add(tokens[2].lower())
        elif len(tokens) != 1:
            problems.append(f"line {number}: cannot read this FROM ({q(line)})")
            continue
        if raw_image.lower() == "scratch" or raw_image.lower() in stages:
            continue
        image = substitute(raw_image, args)
        if "$" in image:
            problems.append(f"line {number}: {q(raw_image)} uses a variable with no default set by an ARG before the first FROM")
            continue
        m = IMAGE.fullmatch(image)
        if not m:
            problems.append(f"line {number}: {q(image)} is not an image reference this check can follow")
            continue
        if not m["digest"]:
            if not allow_unpinned:
                problems.append(f"line {number}: {q(image)} is not pinned by digest (@sha256:...)")
            continue
        if not m["tag"]:
            problems.append(f"line {number}: {q(image)} pins a digest but names no tag, so there is no tag to follow")
            continue
        entry = {
            "line": number,
            "image": f"{m['repo']}:{m['tag']}",
            "repo": m["repo"],
            "tag": m["tag"],
            "digest": m["digest"],
        }
        if not any(e["image"] == entry["image"] and e["digest"] == entry["digest"] for e in found):
            found.append(entry)
    if not found and not problems:
        problems.append("no external base image pinned by digest was found; there is nothing to check")
    return found, problems


def findings(report: object) -> dict[tuple[str, str], dict[str, str]]:
    """(advisory id, package) -> finding, for the fixable ones in a Trivy JSON report."""
    if not isinstance(report, dict):
        raise ValueError("a Trivy report is a JSON object")
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError("the report has no Results list (an empty list is fine, a missing one means the scan failed)")
    out: dict[tuple[str, str], dict[str, str]] = {}
    for result in results:
        vulns = result.get("Vulnerabilities") if isinstance(result, dict) else None
        for vuln in vulns or []:
            if not isinstance(vuln, dict):
                continue
            ident, pkg, fixed = vuln.get("VulnerabilityID"), vuln.get("PkgName"), vuln.get("FixedVersion")
            if not (isinstance(ident, str) and isinstance(pkg, str) and isinstance(fixed, str) and fixed):
                continue
            out[(ident, pkg)] = {
                "id": ident,
                "pkg": pkg,
                "installed": str(vuln.get("InstalledVersion", "")),
                "fixed": fixed,
                "severity": str(vuln.get("Severity", "")),
            }
    return out


def fixed_by_bump(pinned: object, current: object) -> list[dict[str, str]]:
    now = findings(current)
    return [f for key, f in sorted(findings(pinned).items()) if key not in now]


def load_json(path: Path) -> object:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError(f"{q(str(path))} is not a regular file of at most {MAX_BYTES} bytes")
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list")
    p_list.add_argument("dockerfile", type=Path)
    p_list.add_argument("--allow-unpinned", action="store_true")
    p_diff = sub.add_parser("diff")
    p_diff.add_argument("pinned", type=Path)
    p_diff.add_argument("current", type=Path)
    args = parser.parse_args(argv)

    if args.cmd == "list":
        try:
            if not args.dockerfile.is_file() or args.dockerfile.stat().st_size > MAX_BYTES:
                raise ValueError("not a regular file of reasonable size")
            text = args.dockerfile.read_text(encoding="utf-8")
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            print(f"FAIL cannot read {q(str(args.dockerfile))} ({type(exc).__name__}: {q(str(exc))})")
            return 1
        found, problems = pins(text, args.allow_unpinned)
        for problem in problems:
            print(f"FAIL {problem}")
        if problems:
            return 1
        print(json.dumps(found))
        return 0

    try:
        fixed = fixed_by_bump(load_json(args.pinned), load_json(args.current))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        print(f"FAIL cannot compare the reports ({type(exc).__name__}: {q(str(exc))})")
        return 1
    for f in fixed:
        print(f"FIXED {q(f['id'])} {f['severity'] or '?'} {q(f['pkg'])} {q(f['installed'])} -> {q(f['fixed'])}")
    if fixed:
        return 1
    print("ok   the current digest fixes nothing the pinned one has")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
