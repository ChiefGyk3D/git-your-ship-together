#!/usr/bin/env python3
"""Copy scripts/project_sync.py into .github/workflows/project-sync.yml, between the heredoc markers.

A reusable workflow cannot check out its own commit, so the script travels
inside the workflow file. tests/test_project_sync.py fails when the two differ;
run this to make them agree. `--check` writes nothing and exits 1 on a difference.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "project_sync.py"
WORKFLOW = ROOT / ".github" / "workflows" / "project-sync.yml"
PATTERN = re.compile(r"(?P<head>^( +)python3 - <<'PROJECT_SYNC_PY'\n)(?P<body>.*?)(?P<tail>^ +PROJECT_SYNC_PY\n)", re.M | re.S)


def render(text: str) -> str:
    m = PATTERN.search(text)
    if not m:
        raise SystemExit("project-sync.yml has no PROJECT_SYNC_PY heredoc")
    indent = m.group(2)
    body = "".join((indent + line if line.strip() else line) + "\n" for line in SCRIPT.read_text().rstrip("\n").split("\n"))
    return text[: m.start("body")] + body + text[m.start("tail") :]


def main(argv: list[str]) -> int:
    current = WORKFLOW.read_text()
    wanted = render(current)
    if wanted == current:
        return 0
    if "--check" in argv:
        print("project-sync.yml's inline script differs from scripts/project_sync.py", file=sys.stderr)
        return 1
    WORKFLOW.write_text(wanted)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
