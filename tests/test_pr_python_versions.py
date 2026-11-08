"""python-ci `pr-python-versions`: a reduced test matrix on pull requests, the full one everywhere else.

The default is empty, which keeps the matrix exactly `python-versions` on every event, so a caller that sets
nothing sees no change. `ci-green` already treats a skipped or smaller job set as green, so the reduced
matrix needs no change there; a test pins that it still needs `test` and fails on a failed leg.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

DOC = load(WORKFLOWS / "python-ci.yml")
INPUT = triggers(DOC)["workflow_call"]["inputs"].get("pr-python-versions")
STEP_NAME = "Check the pull request Python versions"


def test_the_input_exists_and_defaults_to_the_old_behaviour():
    assert INPUT is not None, "python-ci.yml needs a pr-python-versions input"
    assert INPUT["type"] == "string"
    assert INPUT["default"] == "", "empty keeps the full matrix on pull requests: no change for existing callers"


def test_the_matrix_picks_the_reduced_list_only_on_a_pull_request_with_the_input_set():
    expr = jobs(DOC)["test"]["strategy"]["matrix"]["python-version"]
    assert "inputs.pr-python-versions" in expr
    assert "pull_request" in expr
    assert "inputs.python-versions" in expr
    assert expr.startswith("${{ fromJSON(") and expr.endswith(") }}")
    # the empty default must fall through to python-versions
    assert "inputs.pr-python-versions != ''" in expr


def test_the_full_matrix_is_what_push_and_schedule_get():
    expr = jobs(DOC)["test"]["strategy"]["matrix"]["python-version"]
    assert "github.event_name" in expr, "the choice depends on the event, so main and the weekly run stay full"
    assert "push" not in expr and "schedule" not in expr, "name the pull request side only; everything else is full"


def test_ci_green_still_needs_test_and_fails_on_a_failed_leg():
    green = jobs(DOC)["ci-green"]
    assert "test" in green["needs"]
    assert green["if"] == "always()"
    run = next(s["run"] for s in steps_of(green) if s.get("name") == "Every job passed or was deliberately skipped")
    assert 'not in ("success", "skipped")' in run


# --- the validation step, run for real ---------------------------------------------------------------------


def validation_script():
    step = next((s for s in steps_of(jobs(DOC)["test"]) if s.get("name") == STEP_NAME), None)
    assert step is not None, f"the test job needs a '{STEP_NAME}' step"
    assert step["if"] == "inputs.pr-python-versions != ''", "no step output for a caller that opts out"
    names = [s.get("name") for s in steps_of(jobs(DOC)["test"])]
    assert names.index(STEP_NAME) < names.index("Run tests"), "fail before the tests spend time"
    run = step["run"]
    marker = "python3 - <<'PY'\n"
    body = run.split(marker, 1)[1].rsplit("\nPY", 1)[0]
    return body, step["env"]


def run_validation(event, pr, full='["3.11", "3.12", "3.13", "3.14", "3.15"]', cov="3.13", threshold=""):
    body, env_map = validation_script()
    assert set(env_map) == {"EVENT_NAME", "PR_VERSIONS", "ALL_VERSIONS", "COVERAGE_VERSION", "COVERAGE_THRESHOLD"}
    env = {
        "PATH": os.environ["PATH"],
        "EVENT_NAME": event,
        "PR_VERSIONS": pr,
        "ALL_VERSIONS": full,
        "COVERAGE_VERSION": cov,
        "COVERAGE_THRESHOLD": threshold,
    }
    return subprocess.run([sys.executable, "-I", "-c", body], env=env, capture_output=True, text=True, check=False)


def test_oldest_and_newest_is_accepted():
    assert run_validation("pull_request", '["3.11", "3.15"]').returncode == 0


@pytest.mark.parametrize(
    "pr",
    ["not json", '"3.11"', "[]", '["3.99"]', "[3.11]", '["3.11", "3.11"]', '{"a": 1}'],
)
def test_a_bad_list_is_rejected(pr):
    result = run_validation("pull_request", pr)
    assert result.returncode == 1, "a bad pr-python-versions must fail, not silently test nothing"
    assert "::error" in result.stdout


def test_a_list_is_checked_on_every_event_so_a_typo_shows_before_the_merge():
    assert run_validation("push", '["3.99"]').returncode == 1


def test_a_coverage_threshold_needs_its_leg_in_the_reduced_matrix():
    result = run_validation("pull_request", '["3.11", "3.15"]', threshold="90")
    assert result.returncode == 1
    assert "coverage-python-version" in result.stdout
    assert run_validation("pull_request", '["3.11", "3.13", "3.15"]', threshold="90").returncode == 0
    # the full matrix runs on push, so the leg exists there
    assert run_validation("push", '["3.11", "3.15"]', threshold="90").returncode == 0
    assert run_validation("pull_request", '["3.11", "3.15"]', threshold="").returncode == 0
