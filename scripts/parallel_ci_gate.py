#!/usr/bin/env python3
"""The CI gate: green only when every needed job succeeded, or was skipped on purpose.

Standard library only; `parallel-ci.yml` and `ci-gate.yml` each carry a byte-identical copy of this file
(tests/test_ci_gate.py holds them together).

Environment:
    NEEDS        JSON object, job id -> {"result": ...} or job id -> "result" (toJSON(needs) works as is)
    DELIBERATE   JSON list of job ids that are allowed to be skipped (default [])

Usage:
    python3 -I parallel_ci_gate.py [--output FILE]

A job passes only if its result is exactly `success`. A `skipped` job passes only if it is named in
DELIBERATE; `failure`, `cancelled`, an unknown result, a job with no result and a skip nobody asked for all
fail. No jobs at all fails (a gate over nothing is not a gate), and so does a DELIBERATE entry that names no
needed job (a typo there would otherwise let a real skip through unnoticed). Exit 0 green, 1 not green.
`result=success|failure` is appended to --output (the step's $GITHUB_OUTPUT) before exiting.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

JOB_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,99}")


def q(value: object) -> str:
    text = value if isinstance(value, str) else repr(value)
    return json.dumps(text[:100], ensure_ascii=True)


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def results_of(text: str) -> dict[str, str | None]:
    """job id -> result string (None when the job carries none)."""
    needs = json.loads(text, object_pairs_hook=reject_duplicates)
    if not isinstance(needs, dict):
        raise ValueError("NEEDS must be a JSON object")
    out: dict[str, str | None] = {}
    for job, value in needs.items():
        if not JOB_ID.fullmatch(job):
            raise ValueError(f"job id {q(job)} is not a plain job id")
        if isinstance(value, dict):
            value = value.get("result")
        out[job] = value if isinstance(value, str) else None
    return out


def deliberate_of(text: str) -> set[str]:
    skips = json.loads(text, object_pairs_hook=reject_duplicates)
    if not isinstance(skips, list) or not all(isinstance(s, str) and JOB_ID.fullmatch(s) for s in skips):
        raise ValueError("DELIBERATE must be a JSON list of job ids")
    return set(skips)


def judge(results: dict[str, str | None], deliberate: set[str]) -> list[str]:
    """One line per reason the gate is not green; empty when it is."""
    problems: list[str] = []
    if not results:
        problems.append("no needed jobs: a gate over nothing is not a gate")
    for name in sorted(deliberate - set(results)):
        problems.append(f"deliberate skip {q(name)} names no needed job")
    for job, result in results.items():
        if result == "success":
            continue
        if result == "skipped" and job in deliberate:
            continue
        if result == "skipped":
            problems.append(f"{q(job)} was skipped and nothing said it should be")
        else:
            problems.append(f"{q(job)} is {q(result)}")
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    results: dict[str, str | None] = {}
    deliberate: set[str] = set()
    try:
        results = results_of(os.environ.get("NEEDS", ""))
        deliberate = deliberate_of(os.environ.get("DELIBERATE") or "[]")
        problems = judge(results, deliberate)
    except (ValueError, RecursionError) as exc:
        problems = [f"cannot read the gate's inputs ({type(exc).__name__}: {q(str(exc))})"]
        results = {}
        deliberate = set()
    for job, result in results.items():
        passed = result == "success" or (result == "skipped" and job in deliberate)
        print(f"{'ok  ' if passed else 'FAIL'} {q(job)}: {q(result)}")
    for problem in problems:
        print(f"::error title=CI gate::{problem}")
    if args.output:
        with args.output.open("a", encoding="utf-8") as handle:
            handle.write(f"result={'failure' if problems else 'success'}\n")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
