"""The documented security-only caller carries a `CI green` gate (issue #337).

`security.yml` has no gate job, so a repository whose only GYST caller is the security one had no check branch
protection could require. The README caller example now ends in a `gate` job that calls `ci-gate.yml` over `security`.
These tests read that example, prove it is shaped so a red or skipped scan is a red gate, and prove the weekly audit
derives `gate / CI green` from it.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest
import yaml
from test_audit_baseline import PIN, SHARED, audit
from test_workflows import README, REPO

SECTION = "### Security\n"
GATE_SCRIPT = REPO / "scripts" / "parallel_ci_gate.py"


def example() -> dict:
    text = README.read_text()
    body = text.split(SECTION, 1)[1]
    block = re.search(r"```yaml\n(.*?)```", body, re.S)
    assert block, "the Security section has no caller example"
    return yaml.safe_load(block.group(1))


def jobs_of(doc: dict) -> dict:
    return doc["jobs"]


def gate_result(needs: dict) -> int:
    env = {"PATH": "/usr/bin:/bin", "NEEDS": json.dumps(needs)}
    done = subprocess.run(
        [sys.executable, "-I", str(GATE_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    return done.returncode


def test_the_readme_example_has_a_gate_job_over_the_security_job():
    jobs = jobs_of(example())
    assert set(jobs) == {"security", "gate"}
    gate = jobs["gate"]
    assert gate["uses"].startswith("ChiefGyk3D/git-your-ship-together/.github/workflows/ci-gate.yml@")
    assert gate["needs"] == ["security"]
    assert gate["permissions"] == {}, "the gate holds no token"
    assert gate["with"] == {"needs-json": "${{ toJSON(needs) }}"}


def test_the_gate_runs_even_when_the_scan_failed_or_was_cancelled():
    # Without `always()` a failed `security` leaves the gate skipped, and branch protection reads skipped as passed.
    assert str(jobs_of(example())["gate"]["if"]).replace(" ", "") == "always()"


def test_a_red_cancelled_or_skipped_scan_is_a_red_gate_and_only_success_is_green():
    # What `toJSON(needs)` hands the gate for the example's one needed job.
    assert gate_result({"security": {"result": "success"}}) == 0
    for result in ("failure", "cancelled", "skipped"):
        assert gate_result({"security": {"result": result}}) != 0, result


def test_the_example_still_names_the_gate_in_prose_and_the_section_explains_why():
    section = README.read_text().split("#### A security-only repository still needs a `CI green` gate", 1)
    assert len(section) == 2, "the explanation is missing"
    text = section[1].split("Inputs of `security.yml`:", 1)[0]
    assert "gate / CI green" in text and "always()" in text and "branch protection" in text


def caller_text(gate_uses: str) -> str:
    return (
        "name: Security\non: [push]\npermissions:\n  contents: read\njobs:\n  security:\n"
        f"    uses: {SHARED}security.yml@{PIN} # v1.0.0\n"
        f"  gate:\n    if: always()\n    needs: [security]\n    uses: {gate_uses}\n"
    )


def test_the_audit_derives_gate_check_from_a_ci_gate_call_and_not_from_the_scan_job():
    text = caller_text(f"{SHARED}ci-gate.yml@{PIN} # v1.0.0")
    assert audit.expected_gates(text) == {"gate / CI green"}


@pytest.mark.parametrize("other", ["security.yml", "ci-gate-extra.yml", "my-ci-gate.yml.txt", "ci-gates.yml"])
def test_the_audit_does_not_invent_a_gate_for_a_workflow_that_is_not_ci_gate(other):
    text = caller_text(f"{SHARED}{other}@{PIN} # v1.0.0")
    assert audit.expected_gates(text) == set()


def test_a_security_only_caller_without_the_gate_has_no_expected_check():
    text = caller_text(f"{SHARED}security.yml@{PIN} # v1.0.0")
    assert audit.expected_gates(text) == set(), "security.yml alone produces no gate, which is the defect of #337"
