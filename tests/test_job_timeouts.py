"""Every job in every workflow has an explicit time cap, and none is above 90 minutes by accident.

Issue #247: fixture jobs twice sat idle for 20 to 35 minutes before the platform cap, each costing a re-run. A job
with no `timeout-minutes` runs to GitHub's 360 minute default; one with a cap a few times its normal runtime fails fast.

What is held still here:
- a job that runs steps has `timeout-minutes`: a positive integer, or `${{ inputs.NAME }}` where NAME is a number
  input of that workflow with an integer default (so the default a caller inherits is checked too);
- a job that calls a local reusable workflow which has a timeout input sets that input to an integer in its `with`
  (a calling job cannot carry `timeout-minutes` itself; GitHub rejects it);
- nothing exceeds MAX_MINUTES unless it is on ALLOWED_ABOVE_MAX with a written reason.
The failing shapes (missing, zero, a bool, a string, 91, an expression naming no input, a caller that leaves the
default) are fed to the same function in `test_the_guard_bites`, so the guard cannot go quiet unnoticed. The measured
runtimes behind the values are in docs/wiki/Job-timeouts.md.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from test_workflows import WORKFLOW_FILES, WORKFLOWS, jobs, load, triggers

MAX_MINUTES = 90

# (workflow file, job id) -> why a value above MAX_MINUTES (or one that cannot be read as a number here) is allowed.
ALLOWED_ABOVE_MAX = {
    ("parallel-ci.yml", "checks"): (
        "the cap comes from the caller's JSON plan (`matrix.timeout`, default 15); the plan validator accepts 1 to 360 "
        "because a caller's check can be a long suite, and the planner rejects anything else"
    ),
}

INPUT_EXPR = re.compile(r"^\$\{\{\s*inputs\.([A-Za-z0-9_-]+)\s*\}\}$")
TIMEOUT_INPUTS = ("timeout-minutes", "build-timeout-minutes")


def call_inputs(doc: dict) -> dict:
    on = triggers(doc)
    if not isinstance(on, dict):  # `on: pull_request` or `on: [push]`
        return {}
    return (on.get("workflow_call") or {}).get("inputs") or {}


def is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def check_number(where: str, value, inputs: dict, allowed: bool) -> list[str]:
    """Problems with one `timeout-minutes` value, as strings (empty when fine)."""
    if isinstance(value, str):
        m = INPUT_EXPR.match(value.strip())
        if not m:
            return [] if allowed else [f"{where}: {value!r} is not an integer or an `inputs.<name>` expression"]
        spec = inputs.get(m.group(1))
        if spec is None:
            return [f"{where}: {value!r} names an input this workflow does not declare"]
        default = spec.get("default")
        if spec.get("type") != "number" or not is_int(default) or default < 1:
            return [f"{where}: input {m.group(1)!r} must be a number input with a positive integer default"]
        value = default
    if not is_int(value) or value < 1:
        return [f"{where}: {value!r} must be a positive integer"]
    if value > MAX_MINUTES and not allowed:
        return [f"{where}: {value} minutes is above {MAX_MINUTES}; lower it or add an ALLOWED_ABOVE_MAX entry"]
    return []


def problems_in(name: str, doc: dict, callee_inputs) -> list[str]:
    """All timeout problems of one workflow.

    `callee_inputs(uses)` returns the called workflow's inputs, or None when it is not a local workflow.
    """
    out: list[str] = []
    inputs = call_inputs(doc)
    for job_id, job in jobs(doc).items():
        where = f"{name}: job {job_id!r}"
        allowed = (name, job_id) in ALLOWED_ABOVE_MAX
        if "uses" in job:
            theirs = callee_inputs(job["uses"])
            if theirs is None:
                continue  # not a workflow of this repository; its owner caps it
            wanted = [k for k in TIMEOUT_INPUTS if k in theirs]
            given = job.get("with") or {}
            for key in wanted:
                if key not in given:
                    out.append(f"{where}: calls {job['uses']} without setting `{key}`; it would inherit the default")
                else:
                    out += check_number(f"{where} with.{key}", given[key], inputs, allowed)
        elif "timeout-minutes" not in job:
            out.append(f"{where}: no timeout-minutes (GitHub's default is 360 minutes)")
        else:
            out += check_number(where, job["timeout-minutes"], inputs, allowed)
    return out


def local_inputs(uses: str):
    m = re.match(r"^\./\.github/workflows/([A-Za-z0-9_.-]+\.yml)$", uses.strip())
    if not m:
        return None
    return call_inputs(load(WORKFLOWS / m.group(1)))


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_job_has_an_explicit_sane_timeout(path: Path):
    assert problems_in(path.name, load(path), local_inputs) == []


def test_the_guard_collected_the_workflows():
    count = sum(len(jobs(load(p))) for p in WORKFLOW_FILES)
    assert len(WORKFLOW_FILES) >= 25 and count >= 100, (len(WORKFLOW_FILES), count)


def test_allowlist_entries_are_real():
    for (file, job_id), reason in ALLOWED_ABOVE_MAX.items():
        assert job_id in jobs(load(WORKFLOWS / file)), f"stale allowlist entry {file}:{job_id}"
        assert len(reason) > 30, f"{file}:{job_id} needs a written reason"


def test_the_guard_bites():
    base = {"workflow_call": {"inputs": {"timeout-minutes": {"type": "number", "default": 10}}}}

    def doc(job, on=base):
        return {"on": on, "jobs": {"j": job}}

    def run(job, on=base, callee=None):
        return problems_in("x.yml", doc(job, on), lambda uses: callee)

    assert run({"timeout-minutes": 5}) == []
    assert run({"timeout-minutes": "${{ inputs.timeout-minutes }}"}) == []
    assert run({}) and "no timeout-minutes" in run({})[0]
    assert run({"timeout-minutes": 0})
    assert run({"timeout-minutes": True})
    assert run({"timeout-minutes": "10"})
    assert run({"timeout-minutes": MAX_MINUTES + 1})
    assert run({"timeout-minutes": MAX_MINUTES}) == []
    assert run({"timeout-minutes": "${{ inputs.nope }}"})
    big = {"workflow_call": {"inputs": {"timeout-minutes": {"type": "number", "default": 120}}}}
    assert run({"timeout-minutes": "${{ inputs.timeout-minutes }}"}, on=big)
    nodefault = {"workflow_call": {"inputs": {"timeout-minutes": {"type": "number"}}}}
    assert run({"timeout-minutes": "${{ inputs.timeout-minutes }}"}, on=nodefault)
    # a caller that leaves the callee's default in place, sets a bad value, or sets a good one
    callee = {"timeout-minutes": {"type": "number", "default": 30}}
    assert run({"uses": "./.github/workflows/y.yml"}, callee=callee)
    assert run({"uses": "./.github/workflows/y.yml", "with": {"timeout-minutes": 500}}, callee=callee)
    assert run({"uses": "./.github/workflows/y.yml", "with": {"timeout-minutes": 5}}, callee=callee) == []
    assert run({"uses": "./.github/workflows/y.yml"}, callee={}) == []  # a callee with no such input
    assert run({"uses": "owner/repo/.github/workflows/y.yml@abc"}, callee=None) == []
