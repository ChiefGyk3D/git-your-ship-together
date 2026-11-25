#!/usr/bin/env python3
"""Print only safe location fields from Semgrep SARIF reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path

LIMIT = 100


def escaped(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


def main(paths: list[str]) -> int:
    findings: list[tuple[object, object, object, object]] = []
    for name in paths:
        path = Path(name)
        if not path.is_file():
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ValueError(f"{path}: expected a SARIF object")
        for run in report.get("runs", []):
            if not isinstance(run, dict):
                continue
            for result in run.get("results", []):
                if not isinstance(result, dict):
                    continue
                location = next((item for item in result.get("locations", []) if isinstance(item, dict)), {})
                physical = location.get("physicalLocation", {}) if isinstance(location, dict) else {}
                artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
                region = physical.get("region", {}) if isinstance(physical, dict) else {}
                findings.append(
                    (
                        result.get("ruleId", ""),
                        artifact.get("uri", "") if isinstance(artifact, dict) else "",
                        region.get("startLine", "") if isinstance(region, dict) else "",
                        result.get("level", ""),
                    )
                )

    shown = LIMIT if len(findings) <= LIMIT else LIMIT - 1
    for rule_id, file, start_line, severity in findings[:shown]:
        print(
            f"RuleID={escaped(rule_id)} File={escaped(file)} "
            f"StartLine={escaped(start_line)} Severity={escaped(severity)}"
        )
    if len(findings) > shown:
        print(f"... {len(findings) - shown} more findings not shown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
