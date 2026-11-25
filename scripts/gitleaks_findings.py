#!/usr/bin/env python3
"""Print only the safe location fields from redacted gitleaks JSON reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path

LIMIT = 100


def escaped(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


def main(paths: list[str]) -> int:
    findings: list[dict[str, object]] = []
    for name in paths:
        path = Path(name)
        if not path.is_file():
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(report, list):
            raise ValueError(f"{path}: expected a JSON list")
        findings.extend(item for item in report if isinstance(item, dict))

    shown = LIMIT if len(findings) <= LIMIT else LIMIT - 1
    for finding in findings[:shown]:
        fields = (
            f"RuleID={escaped(finding.get('RuleID', ''))}",
            f"File={escaped(finding.get('File', ''))}",
            f"StartLine={escaped(finding.get('StartLine', ''))}",
            f"Entropy={escaped(finding.get('Entropy', ''))}",
        )
        commit = finding.get('Commit')
        suffix = f" Commit={escaped(str(commit)[:7])}" if commit else ""
        print(" ".join(fields) + suffix)
    if len(findings) > shown:
        print(f"... {len(findings) - shown} more findings not shown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
