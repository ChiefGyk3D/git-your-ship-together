"""scripts/parallel_ci_gate.py and the two workflows that inline it: the gate fails on anything but a real pass.

The gate is the one check branch protection reads, so the cases that matter are the quiet ones: a job that
was skipped because something upstream failed, a cancelled job, a result nobody expected, a typo in the list of
deliberate skips. Every refusal has a passing twin, so a gate that fails everything cannot pass this file.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "parallel_ci_gate.py"
WORKFLOWS = REPO / ".github" / "workflows"
GATE_WORKFLOWS = ["parallel-ci.yml", "ci-gate.yml"]


def run(needs, deliberate=None, tmp_path: Path | None = None):
    env = {"PATH": "/usr/bin:/bin", "NEEDS": needs if isinstance(needs, str) else json.dumps(needs)}
    if deliberate is not None:
        env["DELIBERATE"] = deliberate if isinstance(deliberate, str) else json.dumps(deliberate)
    out = (tmp_path / "out") if tmp_path else None
    args = [sys.executable, "-I", str(SCRIPT)] + (["--output", str(out)] if out else [])
    done = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    return done, (out.read_text() if out and out.exists() else "")


def green(needs, deliberate=None):
    done, _ = run(needs, deliberate)
    return done.returncode == 0


def test_every_job_successful_is_green():
    assert green({"a": {"result": "success"}, "b": {"result": "success"}})


def test_a_plain_map_of_results_is_read_too():
    assert green({"a": "success"})
    assert not green({"a": "failure"})


@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "", "pending", "SUCCESS", "Success", "ok"])
def test_anything_but_success_is_red(result):
    assert not green({"a": {"result": "success"}, "b": {"result": result}})


def test_a_job_with_no_result_is_red():
    assert not green({"a": {"outputs": {}}})
    assert not green({"a": None})
    assert not green({"a": 1})


def test_a_deliberate_skip_is_green_and_an_undeclared_one_is_not():
    needs = {"a": {"result": "success"}, "b": {"result": "skipped"}}
    assert green(needs, ["b"])
    assert not green(needs, [])
    assert not green(needs)
    assert not green(needs, ["a"])  # the wrong job named: b's skip is still unexplained (and a was not skipped)


def test_a_deliberate_skip_does_not_excuse_a_failure_or_a_cancellation():
    for result in ("failure", "cancelled"):
        assert not green({"a": {"result": result}}, ["a"])


def test_a_deliberate_skip_that_names_no_needed_job_is_red():
    """A typo there would otherwise leave the real skip unexplained, or hide that the skip list is stale."""
    assert not green({"a": {"result": "success"}}, ["typo"])


def test_a_gate_over_nothing_is_red():
    assert not green({})
    assert not green({}, [])


@pytest.mark.parametrize(
    "needs", ["", "not json", "[]", '"success"', "null", "1", '{"a": ', '{"a": "success", "a": "success"}']
)
def test_unreadable_needs_are_red(needs):
    assert not green(needs)


@pytest.mark.parametrize("deliberate", ["not json", "{}", '"a"', '["a", 1]', '["a b"]', '["a", "a"', '["bad\\nid"]'])
def test_unreadable_deliberate_skips_are_red(deliberate):
    assert not green({"a": {"result": "success"}}, deliberate)


def test_an_empty_deliberate_value_means_none():
    assert green({"a": {"result": "success"}}, "")


def test_a_job_id_that_is_not_a_plain_id_is_red_and_is_never_echoed_raw():
    forged = "a\n::error::forged"
    done, _ = run({forged: {"result": "success"}})
    assert done.returncode == 1
    assert "\n::error::forged" not in done.stdout
    assert "forged" not in done.stdout or '"' in done.stdout  # at most inside a JSON-quoted string


def test_the_failure_is_named_and_printed_as_an_error_annotation():
    done, _ = run({"build": {"result": "failure"}, "ok": {"result": "success"}})
    assert done.returncode == 1
    assert '::error title=CI gate::"build" is "failure"' in done.stdout
    assert "ok" in done.stdout


def test_the_verdict_is_written_to_the_output_file(tmp_path):
    done, out = run({"a": {"result": "success"}}, tmp_path=tmp_path)
    assert done.returncode == 0 and out == "result=success\n"
    bad = tmp_path / "bad"
    bad.mkdir()
    done, out = run({"a": {"result": "failure"}}, tmp_path=bad)
    assert done.returncode == 1 and out == "result=failure\n"


def test_an_unreadable_input_still_writes_a_failure(tmp_path):
    done, out = run("not json", tmp_path=tmp_path)
    assert done.returncode == 1 and out == "result=failure\n"


# --- the workflows -------------------------------------------------------------------------------------------


def inlined(path: Path, job: str) -> str:
    """The script a job's gate step feeds to `python3 -I -` through a quoted heredoc."""
    steps = yaml.safe_load(path.read_text())["jobs"][job]["steps"]
    body = next(s["run"] for s in steps if s.get("id") == "gate")
    lines = body.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("python3 -I - ") and line.endswith("<<'PY'"))
    end = max(i for i, line in enumerate(lines) if line == "PY")
    return "\n".join(lines[start + 1 : end]) + "\n"


@pytest.mark.parametrize("name", GATE_WORKFLOWS)
def test_the_inlined_gate_is_the_script_byte_for_byte(name):
    assert inlined(WORKFLOWS / name, "ci-green") == SCRIPT.read_text()


@pytest.mark.parametrize("name", GATE_WORKFLOWS)
def test_the_gate_job_is_named_ci_green_and_holds_nothing(name):
    job = yaml.safe_load((WORKFLOWS / name).read_text())["jobs"]["ci-green"]
    assert job["name"] == "CI green"
    assert job["permissions"] == {}
    assert "continue-on-error" not in (WORKFLOWS / name).read_text()


def test_the_gate_workflow_asks_for_no_token_scope_at_any_level():
    # A caller grants the gate `permissions: {}`. GitHub rejects the whole run as a startup_failure (no check run,
    # no job) when the called workflow requests more than the caller grants, and the requirement is read from the
    # workflow's top level too, not only from its jobs. ci-gate.yml holds nothing, so it must request nothing.
    doc = yaml.safe_load((WORKFLOWS / "ci-gate.yml").read_text())
    assert doc["permissions"] == {}
    assert all(job.get("permissions") == {} for job in doc["jobs"].values())
    assert doc["jobs"], "the guard collected no job"


def test_the_gate_permission_guard_bites():
    bad = yaml.safe_load("permissions:\n  contents: read\njobs:\n  g:\n    permissions: {}\n")
    assert bad["permissions"] != {}


def test_the_parallel_gate_runs_always_and_needs_every_other_job():
    doc = yaml.safe_load((WORKFLOWS / "parallel-ci.yml").read_text())
    gate = doc["jobs"]["ci-green"]
    assert gate["if"] == "always()"
    assert set(gate["needs"]) == set(doc["jobs"]) - {"ci-green"}


def test_the_parallel_gate_excuses_only_the_checks_job_and_only_when_changes_chose_nothing():
    gate = yaml.safe_load((WORKFLOWS / "parallel-ci.yml").read_text())["jobs"]["ci-green"]
    step = next(s for s in gate["steps"] if s.get("id") == "gate")
    assert step["env"]["DELIBERATE"] == (
        "${{ (needs.changes.result == 'success' && needs.changes.outputs.count == '0') && '[\"checks\"]' || '[]' }}"
    )
    results = json.loads(
        step["env"]["NEEDS"]
        .replace("${{ needs.changes.result }}", "x")
        .replace("${{ needs.build.result }}", "x")
        .replace("${{ needs.checks.result }}", "x")
    )
    assert set(results) == {"changes", "build", "checks"}


def test_the_standalone_gate_has_no_default_excuse():
    doc = yaml.safe_load((WORKFLOWS / "ci-gate.yml").read_text())
    call = (doc.get(True) or doc.get("on"))["workflow_call"]["inputs"]
    assert call["deliberate-skips"]["default"] == "[]"
    assert call["needs-json"].get("required") is True
    step = next(s for s in doc["jobs"]["ci-green"]["steps"] if s.get("id") == "gate")
    assert step["env"] == {"NEEDS": "${{ inputs.needs-json }}", "DELIBERATE": "${{ inputs.deliberate-skips }}"}
    assert "inputs." not in step["run"], "an input must reach the script through env, not the shell text"


def test_the_ci_gate_fixture_runs_always_so_it_can_judge_a_red_job():
    jobs = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())["jobs"]
    gate = jobs["fixture-gate"]
    assert gate["if"] == "always()" and gate["needs"] == ["fixture-parallel"]
    assert gate["with"] == {"needs-json": "${{ toJSON(needs) }}"}
