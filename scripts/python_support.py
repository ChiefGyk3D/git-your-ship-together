#!/usr/bin/env python3
"""The supported CPython versions and their security-support end dates.

`.github/python-support.json` is the one list. This module reads it and answers
two questions with an injectable clock (`today` is always a parameter, never
read inside a check, so a test names the date it means):

* `expired(today)` - versions still listed whose security support ended before
  `today`, plus grace entries whose deadline passed.
* `versions()` - the listed versions, oldest first, as the strings a workflow
  matrix takes.

Run it as a script to gate a build: it exits 1 and names each expired version.
`--today YYYY-MM-DD` replaces the clock (for dry runs); the default is the date
on this machine.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

SUPPORT_FILE = Path(__file__).resolve().parent.parent / ".github" / "python-support.json"


def load(path: Path = SUPPORT_FILE) -> dict:
    return json.loads(path.read_text())


def versions(data: dict | None = None) -> list[str]:
    data = data or load()
    return [entry["version"] for entry in data["versions"]]


def minor(version: str) -> int:
    return int(version.split(".")[1])


def expired(today: date, data: dict | None = None) -> list[str]:
    """Messages for every listed version past its security end and every lapsed grace entry."""
    data = data or load()
    problems = []
    for entry in data["versions"]:
        end = date.fromisoformat(entry["security_end"])
        if today > end:
            problems.append(
                f"Python {entry['version']} is past its security-support end ({end}); drop it from {SUPPORT_FILE.name}"
            )
    for entry in data.get("grace", []):
        until = date.fromisoformat(entry["until"])
        if today > until:
            problems.append(f"the grace for Python {entry['version']} ended {until}: {entry['reason']}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--today", type=date.fromisoformat, default=None, help="YYYY-MM-DD, default the local date")
    args = parser.parse_args(argv)
    problems = expired(args.today or date.today())
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
