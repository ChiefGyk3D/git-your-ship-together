"""security.yml `advanced-security`: a private repository without GitHub Advanced Security (issue #248).

The input is explicit: `true` (the default, today's behavior) or `false`. One always-running job,
`advanced-security-check`, fails the called workflow loudly unless the value is exactly one of the two. It is a loud
failure, not a gate: no job has `needs`, so the scans run exactly as before even when the check fails (a flaky canary
there must not switch the scans off). GitHub compares strings case-insensitively, so `False` skips CodeQL and
dependency review, and the check job is what keeps that run from ever being green.
"""

from __future__ import annotations

import json
import os
import subprocess

import pytest
from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

DOC = load(WORKFLOWS / "security.yml")
INPUTS = triggers(DOC)["workflow_call"]["inputs"]
JOBS = jobs(DOC)
CHECK = "advanced-security-check"
VALIDATE = "Validate the advanced-security input"
NOTE = "Note the skipped Advanced Security features"
READERS = ["codeql", "dependency-review", "gitleaks", "semgrep"]
ON = "inputs.advanced-security != 'false'"
OFF = "inputs.advanced-security == 'false'"
INVALID = [
    "",
    " ",
    "\n",
    "True",
    "TRUE",
    "tRuE",
    "False",
    "FALSE",
    "fAlSe",
    "true ",
    " false",
    "true\n",
    "false\nfalse",
    "auto",
    "yes",
    "0",
    "1",
    "null",
    "true;false",
    "true​",  # zero-width space
    "truе",  # Cyrillic e
    "falsе",
    "ｔrue",  # full-width t
    "$(id)",
    "`id`",
    "${{ inputs.codeql }}",
    "${ADVANCED_SECURITY}",
]


def step(job: str, name: str) -> dict:
    return next(s for s in steps_of(JOBS[job]) if s.get("name") == name)


def uploads(job: str) -> list[dict]:
    return [s for s in steps_of(JOBS[job]) if "upload-sarif" in str(s.get("uses", ""))]


def test_the_input_is_explicit_and_defaults_to_todays_behavior():
    spec = INPUTS["advanced-security"]
    assert spec["type"] == "string" and spec["default"] == "true"
    assert "auto" not in spec["description"]


def test_nothing_reads_the_private_flag_or_an_auto_mode():
    text = (WORKFLOWS / "security.yml").read_text()
    assert "repository.private" not in text and "'auto'" not in text


def test_the_check_job_always_runs_and_does_no_checkout():
    job = JOBS[CHECK]
    assert "if" not in job and "needs" not in job
    assert job["permissions"] == {}, "the job performs no repository operation"
    assert job["steps"][0]["name"] == "Validate the egress policy inputs (EX-0001)"
    names = [s.get("name") for s in steps_of(job)]
    assert str(steps_of(job)[0].get("uses", "")).startswith("step-security/harden-runner@")
    assert "Egress canary (EX-0001)" in names
    assert names[-1] == VALIDATE
    assert not any("checkout" in str(s.get("uses", "")) for s in steps_of(job))


def test_the_check_job_passes_the_value_by_env_and_never_evaluates_it():
    s = step(CHECK, VALIDATE)
    assert "if" not in s and s["env"]["ADVANCED_SECURITY"] == "${{ inputs.advanced-security }}"
    assert "inputs." not in s["run"] and "eval" not in s["run"]


def test_no_other_job_has_a_validate_step():
    for name, job in JOBS.items():
        if name != CHECK:
            assert VALIDATE not in [s.get("name") for s in steps_of(job)]


def run_validate(value: str | None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ADVANCED_")}
    if value is not None:
        env["ADVANCED_SECURITY"] = value
    script = step(CHECK, VALIDATE)["run"]
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script], capture_output=True, text=True, env=env, timeout=20
    )


@pytest.mark.parametrize("good", ["true", "false"])
def test_the_validator_accepts_exactly_true_and_false(good):
    done = run_validate(good)
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("bad", [*INVALID, None])
def test_every_invalid_value_fails_the_check_job_with_a_clear_error(bad):
    done = run_validate(bad)
    assert done.returncode == 1, "an invalid value must fail the call, not pass it"
    assert "::error" in done.stdout and "advanced-security" in done.stdout
    assert "'true'" in done.stdout and "'false'" in done.stdout
    assert "uid=" not in done.stdout + done.stderr, "the value is data, never executed"


def test_no_job_has_needs_so_the_scans_always_run():
    assert not [n for n, j in JOBS.items() if "needs" in j], "a failed check job must not skip a scan"


def test_only_the_expected_jobs_read_the_input():
    readers = sorted(n for n, j in JOBS.items() if n != CHECK and "advanced-security" in json.dumps(j))
    assert readers == sorted(READERS), "a new reader of the input must be listed here and reviewed"


def test_the_check_job_is_the_only_one_added_and_the_job_count_grows_by_exactly_one():
    assert [n for n in JOBS if "advanced-security" in n] == [CHECK]
    assert len(JOBS) == 8  # codeql gitleaks dependency-audit dependency-review semgrep snyk scorecard + the check


def gated_job_runs(value: str) -> bool:
    """Evaluate the real clause: GitHub's `!=` on strings is case-insensitive."""
    assert ON in JOBS["codeql"]["if"]
    return not (value.lower() == "false")


@pytest.mark.parametrize("value", [*INVALID, "true", "false"])
def test_only_the_literal_false_skips_and_every_other_value_runs_the_scans(value):
    skips = value.lower() == "false"
    assert gated_job_runs(value) is (not skips)
    if skips and value != "false":
        assert run_validate(value).returncode == 1, "a case variant of false skips, and the check job turns the run red"
    if value in INVALID:
        assert run_validate(value).returncode == 1, "an invalid value runs the scans AND fails the check job"
        assert gated_job_runs(value) is (not skips)


def test_scan_jobs_do_not_depend_on_a_status_function():
    for name in READERS:
        assert not any(w in str(JOBS[name]["if"]) for w in ("success()", "failure()", "cancelled()"))


def test_the_job_conditions_skip_only_on_false_and_keep_their_other_clauses():
    assert JOBS["codeql"]["if"] == f"inputs.codeql && {ON}"
    assert JOBS["dependency-review"]["if"] == f"inputs.dependency-review && github.event_name == 'pull_request' && {ON}"
    assert JOBS["gitleaks"]["if"] == "inputs.gitleaks" and JOBS["semgrep"]["if"] == "inputs.semgrep"


def test_semgrep_and_gitleaks_still_run_and_still_fail_on_a_finding():
    scan = step("gitleaks", "Scan the commits (gitleaks)")
    assert "if" not in scan and "--exit-code 1" in scan["run"]
    semgrep = step("semgrep", "Scan (Semgrep)")
    assert "if" not in semgrep and "--error" in semgrep["run"]


def test_the_sarif_uploads_follow_the_input_and_keep_their_other_conditions():
    (gitleaks,) = uploads("gitleaks")
    (semgrep,) = uploads("semgrep")
    assert ON in gitleaks["if"] and "inputs.gitleaks-upload-sarif" in gitleaks["if"]
    assert "always()" in gitleaks["if"] and "hashFiles('gitleaks.sarif')" in gitleaks["if"]
    assert ON in semgrep["if"] and "always()" in semgrep["if"] and "hashFiles('semgrep.sarif')" in semgrep["if"]


def test_snyk_and_scorecard_are_unchanged():
    for job in ("snyk", "scorecard"):
        assert "advanced-security" not in str(JOBS[job])


def run_note(tmp_path):
    summary = tmp_path / "summary.md"
    summary.unlink(missing_ok=True)
    env = {**os.environ, "GITHUB_STEP_SUMMARY": str(summary)}
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step("semgrep", NOTE)["run"]],
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return summary.read_text()


@pytest.mark.parametrize("job", ["gitleaks", "semgrep"])
def test_the_note_step_runs_only_when_the_input_is_false(job):
    s = step(job, NOTE)
    assert s["if"] == OFF
    assert "inputs." not in s["run"]


def test_the_summary_says_what_was_skipped_why_and_how_to_turn_it_on(tmp_path):
    text = run_note(tmp_path)
    for word in ("dependency review", "CodeQL", "SARIF", "advanced-security: false", "advanced-security: true"):
        assert word.lower() in text.lower()
    assert "Semgrep" in text and "gitleaks" in text and "still" in text


def test_the_two_note_scripts_are_identical():
    assert step("gitleaks", NOTE)["run"] == step("semgrep", NOTE)["run"]
