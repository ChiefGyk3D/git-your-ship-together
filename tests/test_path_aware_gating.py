"""Path-aware gating of this repository's own ci.yml (issues #307, #308) and the gate's fork skip.

One rule runs through all of it: `CI green` never goes green when a skipped job should have run. A job leaves
the run for one of two reasons only, and the gate (scripts/ci_gate.py through .github/actions/ci-gate) names
both: the `changes` job (the repository's classify-changes action) said `docs-only=true`, or the pull request
is from a fork and the job is one that needs a token a fork does not get. Every other skip is a failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import ci_gate  # noqa: E402

WORKFLOWS = REPO / ".github" / "workflows"
CI = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())
JOBS = CI["jobs"]
TRIGGERS = CI.get(True) or CI["on"]  # PyYAML reads the bare key `on` as True

# The jobs that always run: the lints and the test suite (the suite reads tests/, so a tests-only change must
# still run it), the classifier itself, and the gate.
ALWAYS = {"actionlint", "zizmor", "test", "changes", "ci-green"}
# The two live jobs read these files besides the workflows, which are never docs only (`.github/**`).
LIVE = {"rescan-live", "dast-live"}
SKIP_RULE = "needs.changes.outputs.docs-only != 'true'"
FORK_RULE = "github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"


def gated() -> set[str]:
    return set(JOBS) - ALWAYS - LIVE  # the live jobs join in the next commit (#308)


def needs_of(job: dict) -> list[str]:
    n = job.get("needs", [])
    return [n] if isinstance(n, str) else list(n)


# --- the changes job -------------------------------------------------------------------------------------------


def test_changes_job_runs_the_classify_action_with_the_two_reads_it_needs_and_nothing_else():
    job = JOBS["changes"]
    assert job["permissions"] == {"contents": "read", "pull-requests": "read"}
    assert job["outputs"] == {"docs-only": "${{ steps.c.outputs.docs-only }}"}
    (classify,) = [s for s in job["steps"] if str(s.get("uses", "")).startswith("./.github/actions/classify-changes")]
    assert classify["id"] == "c"
    assert "if" not in job and "continue-on-error" not in job


def test_changes_patterns_name_only_paths_no_fixture_job_reads():
    job = JOBS["changes"]
    (classify,) = [s for s in job["steps"] if s.get("id") == "c"]
    patterns = classify["with"]["docs-only-patterns"].split()
    assert patterns == ["docs/**", "tests/**", "*.md"]


def test_changes_is_not_skipped_by_anything():
    assert "if" not in JOBS["changes"] and not needs_of(JOBS["changes"])


# --- every other job is gated, and the gate lists exactly those -----------------------------------------------


def test_the_gated_jobs_were_collected():
    assert len(gated()) > 20, "the guard collected too few jobs to mean anything"


@pytest.mark.parametrize("name", sorted(gated()))
def test_a_gated_job_needs_changes_and_skips_on_docs_only_through_the_rule(name):
    job = JOBS[name]
    assert "changes" in needs_of(job), f"{name} must need changes to read its verdict"
    condition = str(job.get("if", ""))
    assert SKIP_RULE in condition, f"{name}: the skip must come from the classifier's explicit output"


@pytest.mark.parametrize("name", sorted(ALWAYS - {"ci-green", "changes"}))
def test_the_lints_and_the_suite_never_skip(name):
    assert "if" not in JOBS[name] and "changes" not in needs_of(JOBS[name])


def test_a_job_that_keeps_the_fork_condition_keeps_it_with_the_rule_anded():
    forked = [n for n in gated() if FORK_RULE in str(JOBS[n].get("if", ""))]
    assert len(forked) >= 8, "the fork-gated jobs were not collected"
    for name in forked:
        condition = " ".join(str(JOBS[name]["if"]).split())
        assert f"({FORK_RULE}) && {SKIP_RULE}" in condition, name


def test_the_ci_gate_fixture_judges_a_green_changes_job_too():
    gate = JOBS["fixture-gate"]
    assert "always()" in gate["if"] and SKIP_RULE in gate["if"]
    assert "changes" in needs_of(gate) and "fixture-parallel" in needs_of(gate)


def ci_green_step() -> dict:
    (step,) = [s for s in JOBS["ci-green"]["steps"] if str(s.get("uses", "")).startswith("./.github/actions/ci-gate")]
    return step


def test_ci_green_is_the_strict_gate_over_every_other_job():
    job = JOBS["ci-green"]
    assert job["name"] == "CI green" and job["if"] == "always()"
    assert set(needs_of(job)) == set(JOBS) - {"ci-green"}
    assert job["permissions"] == {"contents": "read"}
    with_ = ci_green_step()["with"]
    assert with_["needs"] == "${{ toJSON(needs) }}"
    assert with_["classifier-job"] == "changes"
    assert set(with_["required-jobs"].split()) == set(JOBS) - {"ci-green"}
    assert "continue-on-error" not in (WORKFLOWS / "ci.yml").read_text()


def test_ci_green_may_skip_exactly_the_gated_jobs_and_never_the_always_set():
    with_ = ci_green_step()["with"]
    skippable = set(with_["skippable-jobs"].split())
    assert skippable == gated()
    assert not skippable & (ALWAYS | LIVE)


def test_fork_skips_are_excused_only_for_the_jobs_that_carry_the_fork_condition_or_follow_one():
    with_ = ci_green_step()["with"]
    excused = set(with_["fork-skippable-jobs"].split())
    carries = {n for n in JOBS if FORK_RULE in " ".join(str(JOBS[n].get("if", "")).split())}
    follows = {n for n in JOBS if set(needs_of(JOBS[n])) & carries and n not in carries and "changes" not in {n}}
    assert carries <= excused <= carries | follows
    assert with_["fork-pull-request"] == (
        "${{ github.event_name == 'pull_request' "
        "&& github.event.pull_request.head.repo.full_name != github.repository }}"
    )
    assert not excused & ALWAYS


def test_ci_green_checks_out_nothing_it_could_not_trust_and_keeps_no_credentials():
    steps = JOBS["ci-green"]["steps"]
    (checkout,) = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert checkout["with"]["persist-credentials"] is False


# --- the fork excuse in the gate script ------------------------------------------------------------------------


def n(**results):
    out = {}
    for name, value in results.items():
        out[name] = (
            {"result": value[0], "outputs": {"docs-only": value[1]}} if isinstance(value, tuple) else {"result": value}
        )
    return out


def verdict(needs, skippable="", fork="", fork_pr=False, classifier="changes"):
    return ci_gate.verdict(needs, [], skippable.split(), classifier, fork.split(), fork_pr)[0]


def test_a_fork_pull_request_may_skip_a_fork_job():
    assert verdict(n(changes=("success", "false"), pkg="skipped"), fork="pkg", fork_pr=True) == []


def test_a_job_the_fork_list_does_not_name_cannot_skip_on_a_fork():
    assert verdict(n(changes=("success", "false"), pkg="skipped", other="skipped"), fork="pkg", fork_pr=True)


def test_a_fork_job_skipped_when_it_is_not_a_fork_fails():
    assert verdict(n(changes=("success", "false"), pkg="skipped"), fork="pkg", fork_pr=False)


def test_a_fork_excuse_does_not_cover_failure_or_cancellation():
    for bad in ("failure", "cancelled"):
        assert verdict(n(changes=("success", "false"), pkg=bad), fork="pkg", fork_pr=True)


def test_a_fork_job_skipped_on_a_docs_only_change_follows_the_classifier_when_it_is_not_a_fork():
    assert verdict(n(changes=("success", "true"), pkg="skipped"), skippable="pkg", fork="pkg", fork_pr=False) == []


def test_the_default_gate_has_no_fork_excuse():
    assert ci_gate.verdict(n(a="success", b="skipped"), [], [], "")[0]
