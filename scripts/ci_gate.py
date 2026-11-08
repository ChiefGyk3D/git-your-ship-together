#!/usr/bin/env python3
"""The `CI green` verdict for a caller's own aggregate job, with deliberate skips.

A job counts as passed only when its result is `success`. One exception, and
only one: a job the caller lists in GATE_SKIPPABLE may be `skipped` when the
classifier job (GATE_CLASSIFIER) itself succeeded and reported `docs-only=true`.
A skip for any other reason (a failed upstream job, a typo in an `if:`, a
classifier that did not run or said false) fails the gate, as do `failure`,
`cancelled` and a job that is missing.

Inputs, all through the environment:

  GATE_NEEDS       ${{ toJSON(needs) }} of the aggregate job
  GATE_REQUIRED    space-separated job ids that must be present in it (so a job cannot be
                   dropped from `needs:` and merge unchecked); empty means no such check
  GATE_SKIPPABLE   space-separated job ids that a docs-only change may skip
  GATE_CLASSIFIER  the job id of the classify-changes step's job; needed when GATE_SKIPPABLE is set
"""

from __future__ import annotations

import json
import os
import sys


def verdict(needs: dict, required: list[str], skippable: list[str], classifier: str) -> tuple[list[str], list[str]]:
    """Returns (problems, notes). No problems means green."""
    problems: list[str] = []
    notes: list[str] = []
    for job in required:
        if job not in needs:
            problems.append(f"{job}: required but not in needs")
    if skippable:
        if not classifier or classifier not in needs:
            problems.append("classifier: skippable jobs are named but the classifier job is not in needs")
        if classifier in skippable:
            problems.append(f"{classifier}: the classifier cannot skip itself")
    cls = needs.get(classifier) if classifier else None
    skip_allowed = (
        isinstance(cls, dict)
        and cls.get("result") == "success"
        and (cls.get("outputs") or {}).get("docs-only") == "true"
    )
    for job, info in needs.items():
        result = info.get("result") if isinstance(info, dict) else None
        if result == "success":
            continue
        if result == "skipped" and job in skippable and skip_allowed:
            notes.append(f"{job}: skipped on purpose (docs only: {(cls.get('outputs') or {}).get('reason', '')})")
            continue
        problems.append(f"{job}: {result}")
    return problems, notes


def main() -> int:
    raw = os.environ.get("GATE_NEEDS", "")
    try:
        if not raw.strip():
            raise ValueError("the `needs` input is empty; pass `needs: ${{ toJSON(needs) }}` from the calling job")
        needs = json.loads(raw)
        if not isinstance(needs, dict) or not needs:
            raise ValueError("the `needs` input must be a non-empty JSON object (`toJSON(needs)`)")
    except ValueError as err:
        print(f"::error title=ci-gate::cannot read the needs of this job: {err}")
        return 1
    problems, notes = verdict(
        needs,
        os.environ.get("GATE_REQUIRED", "").split(),
        os.environ.get("GATE_SKIPPABLE", "").split(),
        os.environ.get("GATE_CLASSIFIER", "").strip(),
    )
    for job, info in sorted(needs.items()):
        print(f"{job}: {info.get('result') if isinstance(info, dict) else info!r}")
    for note in notes:
        print(f"::notice title=ci-gate::{note}")
    if problems:
        print("::error title=ci-gate::not green: " + "; ".join(problems))
        return 1
    print("every needed job passed or was deliberately skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
