"""python-ci and bash-ci `skip-docs-only`: a built-in docs-only skip, so a caller needs no per-repo edit (issue #460).

The rules this file pins:

* the classifier job is inline (a reusable workflow cannot check out its own commit), a byte-identical copy of
  scripts/classify_changes.py, so it can never drift from the script the tests and the action use;
* it holds `contents: read` only, because a job may not ask for more than the caller granted and a new
  permission would stop every existing caller at startup; a private repository that wants the skip adds
  `pull-requests: read` itself, and without it the classifier fails closed (runs everything);
* only the test and distro jobs skip, and only on `docs-only == 'true'`; a failed or skipped classifier
  leaves them running, and `ci-green` waits on the classifier so its failure is never hidden;
* security scans are never touched.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

REPO = Path(__file__).resolve().parent.parent
SCRIPT = (REPO / "scripts" / "classify_changes.py").read_text()
NAMES = ["python-ci", "bash-ci"]
GATED = {"python-ci": {"test", "distro"}, "bash-ci": {"test", "distro"}}
RULE = "needs.classify.outputs.docs-only != 'true'"


def doc(name):
    return load(WORKFLOWS / f"{name}.yml")


def embedded_script(name):
    job = jobs(doc(name)).get("classify")
    assert job is not None, f"{name}.yml needs a classify job"
    step = next((s for s in steps_of(job) if s.get("id") == "classify"), None)
    assert step is not None, "the classify job needs a step with id classify"
    marker = "python3 -I - <<'PY'\n"
    assert marker in step["run"]
    return step["run"].split(marker, 1)[1].rsplit("\nPY", 1)[0] + "\n"


@pytest.mark.parametrize("name", NAMES)
def test_inputs_exist_and_keep_safe_defaults(name):
    inputs = triggers(doc(name))["workflow_call"]["inputs"]
    skip = inputs.get("skip-docs-only")
    assert skip is not None, "skip-docs-only input missing"
    assert skip["type"] == "string"
    assert skip["default"] == "auto", "auto: on for a private repository, off for a public one"
    patterns = inputs["docs-only-patterns"]["default"]
    assert "*.md" in patterns.split("\n")
    assert "**" not in patterns.replace("docs/**/*.md", ""), "the default list is markdown only"
    assert inputs["never-skip-patterns"]["default"] == ""


@pytest.mark.parametrize("name", NAMES)
def test_the_embedded_classifier_is_the_script_byte_for_byte(name):
    assert embedded_script(name) == SCRIPT


def test_the_drift_guard_bites():
    assert embedded_script("python-ci") + "# x\n" != SCRIPT


@pytest.mark.parametrize("name", NAMES)
def test_classify_job_is_read_only_pull_request_only_and_off_unless_asked(name):
    job = jobs(doc(name))["classify"]
    assert job["permissions"] == {"contents": "read"}
    cond = job["if"]
    assert "github.event_name == 'pull_request'" in cond
    assert "inputs.skip-docs-only == 'true'" in cond
    assert "inputs.skip-docs-only == 'auto'" in cond and "github.event.repository.private" in cond
    assert job["outputs"]["docs-only"] == "${{ steps.classify.outputs.docs-only }}"
    first = [s.get("name") for s in steps_of(job)]
    assert "Refuse an untrusted self-hosted runner" in first, "the self-hosted guard runs on every job"
    step = next(s for s in steps_of(job) if s.get("id") == "classify")
    assert set(step["env"]) == {
        "GH_TOKEN",
        "CC_EVENT_NAME",
        "CC_REPO",
        "CC_PR",
        "CC_HEAD_SHA",
        "CC_CHANGED_FILES",
        "CC_PATTERNS",
        "CC_NEVER_SKIP",
    }
    assert step["env"]["CC_PATTERNS"] == "${{ inputs.docs-only-patterns }}"
    assert "${{" not in step["run"], "inputs reach the script through env only"


@pytest.mark.parametrize("name", NAMES)
def test_only_test_and_distro_skip_and_only_on_a_docs_only_verdict(name):
    all_jobs = jobs(doc(name))
    gated = {j for j, body in all_jobs.items() if RULE in str(body.get("if", ""))}
    assert gated == GATED[name]
    for j in gated:
        body = all_jobs[j]
        assert "classify" in body["needs"]
        assert "!cancelled()" in body["if"], "a skipped classifier must not skip the job"


@pytest.mark.parametrize("name", NAMES)
def test_the_gate_waits_on_the_classifier_and_still_fails_on_any_failed_job(name):
    green = jobs(doc(name))["ci-green"]
    assert "classify" in green["needs"]
    assert green["if"] == "always()"
    run = next(s["run"] for s in steps_of(green) if str(s.get("name", "")).startswith("Every job passed"))
    assert 'not in ("success", "skipped")' in run


@pytest.mark.parametrize("name", NAMES)
def test_lint_and_gate_jobs_never_skip(name):
    all_jobs = jobs(doc(name))
    for j, body in all_jobs.items():
        if j in GATED[name] or j == "classify":
            continue
        assert RULE not in str(body.get("if", "")), f"{j} must not skip on a docs-only change"


def test_security_scans_always_run():
    text = (WORKFLOWS / "security.yml").read_text()
    assert "docs-only" not in text and "classify" not in text


def test_pr_python_versions_default_is_unchanged():
    inputs = triggers(doc("python-ci"))["workflow_call"]["inputs"]
    assert inputs["pr-python-versions"]["default"] == ""


def test_the_workflows_say_how_a_private_repository_grants_the_read():
    for name in NAMES:
        head = "\n".join((WORKFLOWS / f"{name}.yml").read_text().splitlines()[:80])
        assert re.search(r"pull-requests: read", head), f"{name}.yml header must tell a caller to grant pull-requests: read"
