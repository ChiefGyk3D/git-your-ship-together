"""Path-aware gating of this repository's own ci.yml (issues #307, #308) and the gate's fork skip.

One rule runs through all of it: `CI green` never goes green when a skipped job should have run. A job leaves
the run for one of two reasons only, and the gate (scripts/ci_gate.py through .github/actions/ci-gate) names
both: the `changes` job (the repository's classify-changes action) said `docs-only=true`, or the pull request
is from a fork and the job is one that needs a token a fork does not get. Every other skip is a failure.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import ci_gate  # noqa: E402
import classify_changes as cc  # noqa: E402
from test_docs_only_fast_path import files, run_classify  # noqa: E402

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
    return set(JOBS) - ALWAYS


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


def test_changes_patterns_are_the_narrow_list():
    job = JOBS["changes"]
    (classify,) = [s for s in job["steps"] if s.get("id") == "c"]
    patterns = classify["with"]["docs-only-patterns"].split()
    # Not `*.md`: README.md is read by tests/test_sbom.py, which a gated job runs.
    assert patterns == ["docs/**", "tests/**", "CHANGELOG.md"]


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
    assert not skippable & ALWAYS


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


# --- the live jobs and the nightly run (#308) -------------------------------------------------------------------


def test_the_live_jobs_are_gated_like_every_other_fixture_job():
    for name in sorted(LIVE):
        assert "changes" in needs_of(JOBS[name]), name
        assert str(JOBS[name]["if"]) == SKIP_RULE, name


def changes_rule() -> tuple[list, list]:
    (c,) = [s for s in JOBS["changes"]["steps"] if s.get("id") == "c"]
    with_ = c["with"]
    return (
        cc.compile_patterns(with_["docs-only-patterns"], "patterns", True),
        cc.compile_patterns(with_.get("never-skip-patterns", ""), "never-skip", False),
    )


def skips_live(*paths: str) -> bool:
    patterns, never = changes_rule()
    return cc.classify(files(*paths), patterns, never)[0]


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_dast.py",  # what dast-live runs
        "tests/test_verify_published.py",  # what rescan-live runs
        "tests/test_workflows.py",  # test_dast imports it
        "tests/test_sbom.py",  # what fixture-sbom runs
        "README.md",  # tests/test_sbom.py reads it
        "tests/fixtures/dast/baseline.json",
        "fixture/dast/server.py",
        "fixture/dast/login.context",
        ".github/workflows/dast.yml",
        ".github/workflows/verify-published.yml",
        ".github/actions/classify-changes/action.yml",
        "scripts/classify_changes.py",
        "requirements-dev.txt",
        "pyproject.toml",
    ],
)
def test_a_file_a_live_job_reads_runs_the_live_jobs_even_beside_docs(path):
    assert not skips_live(path)
    assert not skips_live("docs/a.md", path)


@pytest.mark.parametrize("path", ["docs/wiki/Home.md", "CHANGELOG.md", "tests/test_hygiene.py"])
def test_a_change_no_live_job_reads_leaves_them_out(path):
    assert skips_live(path)
    assert skips_live("docs/a.md", path)


def test_the_never_skip_list_is_what_keeps_a_live_test_from_being_skipped():
    """The negative case: the same change with the never-skip list removed would be docs only."""
    patterns, _ = changes_rule()
    assert cc.classify(files("tests/test_dast.py"), patterns, [])[0]
    assert not skips_live("tests/test_dast.py")


def test_the_run_is_scheduled_nightly_and_the_schedule_is_not_filtered_out_of_any_job():
    schedule = TRIGGERS["schedule"]
    assert len(schedule) == 1 and len(schedule[0]["cron"].split()) == 5
    day, month, weekday = schedule[0]["cron"].split()[2:]
    assert (day, month, weekday) == ("*", "*", "*"), "nightly means every day"
    for name, job in JOBS.items():
        assert "schedule" not in str(job.get("if", "")), f"{name}: a job may not opt out of the nightly run"


@pytest.mark.parametrize("event", ["schedule", "push", "workflow_dispatch"])
def test_the_classifier_is_never_docs_only_off_a_pull_request_so_the_nightly_runs_everything(tmp_path, event):
    done, out = run_classify(tmp_path, files("docs/a.md"), event=event)
    assert done.returncode == 0 and out["docs-only"] == "false"


# --- nothing a gated job reads may be on the docs-only list (the guard for the review finding) --------------------

TEST_FILE = re.compile(r"(?<![\w/.-])tests/(test_\w+\.py)")
LOCAL_IMPORT = re.compile(r"^(?:from|import) (test_\w+)", re.M)
ROOT_MD = re.compile(r"""["']([A-Za-z_]+\.md)["']""")
DOCS_DIR = re.compile(r"""["']docs["']""")


def reads_of(job: dict) -> set[str]:
    """Every repository path a gated job names in its YAML, or its pytest files read or import, as best text can say."""
    text = yaml.safe_dump(job)
    found = set(re.findall(r"(?<![\w/.-])(?:tests|docs)/[\w./*-]+", text)) | set(
        re.findall(r"(?<![\w/])[A-Z_]+\.md\b", text)
    )
    queue = [f"tests/{m}" for m in TEST_FILE.findall(text)]
    seen: set[str] = set()
    while queue:
        path = queue.pop()
        if path in seen or not (REPO / path).is_file():
            continue
        seen.add(path)
        found.add(path)
        body = (REPO / path).read_text()
        found |= set(ROOT_MD.findall(body))
        if DOCS_DIR.search(body):
            found.add("docs/x")
        queue += [f"tests/{m}.py" for m in LOCAL_IMPORT.findall(body)]
    return found


def test_no_gated_job_reads_a_path_the_docs_only_list_would_let_it_skip():
    checked = 0
    for name in sorted(gated()):
        for path in sorted(reads_of(JOBS[name])):
            if "*" in path:
                continue
            checked += 1
            assert not skips_live(path), f"{name} reads {path}, but a change to it alone would skip {name}"
    assert checked >= 5, "the guard collected too few reads to mean anything"


def test_the_read_guard_bites():
    """Negative case: a job that runs a test file the list would skip, or a file that test reads, is caught."""
    job = {"steps": [{"run": "pytest tests/test_hygiene.py"}]}
    assert "tests/test_hygiene.py" in reads_of(job) and skips_live("tests/test_hygiene.py")
    job = {"steps": [{"run": "pytest tests/test_sbom.py"}]}
    assert "README.md" in reads_of(job)
    assert skips_live("CHANGELOG.md") and "CHANGELOG.md" not in reads_of(job)


# --- concurrency on the self-callers, and the auto-merge actor gate (#313) -----------------------------------------


def self_caller(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def test_security_self_cancels_superseded_pull_request_runs_only():
    assert self_caller("security-self.yml")["concurrency"] == {
        "group": "${{ github.workflow }}-${{ github.ref }}",
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }


def test_wiki_self_caller_never_cancels_a_publish_and_cannot_collide_with_the_reusable_groups_name():
    declared = self_caller("wiki.yml")["concurrency"]
    assert declared == {"group": "${{ github.workflow }}-${{ github.ref }}", "cancel-in-progress": False}
    # wiki-publish.yml's publish job holds the literal group `wiki`; the same name here would deadlock the call.
    assert declared["group"] != "wiki"


def test_auto_merge_self_caller_has_one_run_per_pull_request_and_gates_by_actor():
    doc = self_caller("dependabot-auto-merge-self.yml")
    assert doc["concurrency"] == {
        "group": "${{ github.workflow }}-${{ github.event.pull_request.number }}",
        "cancel-in-progress": True,
    }
    assert doc["jobs"]["auto-merge"]["if"] == "github.event.pull_request.user.login == 'dependabot[bot]'"
