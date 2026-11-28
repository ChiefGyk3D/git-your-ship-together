"""python-ci and bash-ci `skip-docs-only`: a built-in docs-only skip, so a caller needs no per-repo edit (issue #460).

The rules this file pins:

* the classifier job is inline (a reusable workflow cannot check out its own commit), a byte-identical copy of
  scripts/classify_changes.py, so it can never drift from the script the tests and the action use;
* it holds `contents: read` only, because a job may not ask for more than the caller granted and a new
  permission would stop every existing caller at startup; a private repository that wants the skip adds
  `pull-requests: read` itself, and without it the classifier fails closed (runs everything);
* only the test and distro jobs skip, and only on `docs-only == 'true'`; a failed or skipped classifier
  leaves them running, and `ci-green` waits on the classifier so its failure is never hidden;
* security scans are never touched;
* tofu-ci takes the same input names and the same inline classifier, with its own never-skip default
  (Terraform and lock files), and its gate tolerates a skipped test only on a docs-only verdict.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

REPO = Path(__file__).resolve().parent.parent
SCRIPT = (REPO / "scripts" / "classify_changes.py").read_text()
NAMES = ["python-ci", "bash-ci", "tofu-ci"]
GATED = {"python-ci": {"test", "distro"}, "bash-ci": {"test", "distro"}, "tofu-ci": {"test-dirs", "test"}}
# The never-skip default: python-ci and bash-ci keep none; tofu-ci keeps every Terraform and lock file.
NEVER_DEFAULT = {"python-ci": "", "bash-ci": "", "tofu-ci": "**/*.tf\n**/*.tfvars\n**/*.hcl\n**/*.lock\n"}
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
    assert skip["type"] == "boolean"
    assert skip["default"] is False, "off by default: a workflow may not read repository visibility, so callers opt in"
    patterns = inputs["docs-only-patterns"]["default"]
    assert "*.md" in patterns.split("\n")
    assert "**" not in patterns.replace("docs/**/*.md", ""), "the default list is markdown only"
    assert inputs["never-skip-patterns"]["default"] == NEVER_DEFAULT[name]


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
    assert cond == "github.event_name == 'pull_request' && inputs.skip-docs-only"
    assert "repository.private" not in cond
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


@pytest.mark.parametrize("name", ["python-ci", "bash-ci"])
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


# --- tofu-ci: the same skip, its own never-skip default and a gate that knows about the skip ----------------------


def tofu_inputs():
    return triggers(doc("tofu-ci"))["workflow_call"]["inputs"]


def test_tofu_never_skip_default_is_read_from_the_workflow_not_retyped():
    assert NEVER_DEFAULT["tofu-ci"] == tofu_inputs()["never-skip-patterns"]["default"]


def classifier():
    spec = importlib.util.spec_from_file_location("classify_changes", REPO / "scripts" / "classify_changes.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "path",
    [
        "stacks/a/main.tf",
        "modules/x/variables.tfvars",
        "stacks/a/.terraform.lock.hcl",
        "stacks/a/tests/a.tftest.hcl",
        "stacks/a/terraform.lock",
    ],
)
def test_tofu_a_terraform_or_lock_file_is_never_docs_only_even_when_the_patterns_name_it(path):
    """The callers' docs-only list names the file on purpose; only the never-skip default can stop the skip."""
    cc = classifier()
    never = tofu_inputs()["never-skip-patterns"]["default"]
    patterns = "stacks/**\nmodules/**\n*.md"  # whole directories named as docs only: never-skip must still win
    ok, reason = cc.classify(
        [{"filename": path, "status": "modified"}],
        cc.compile_patterns(patterns, "patterns", True),
        cc.compile_patterns(never, "never-skip", False),
    )
    assert not ok, reason


def test_tofu_the_never_skip_default_guard_bites_without_it():
    """Negative case: the same change, with the never-skip list empty, is docs-only: the guard is what stops it."""
    cc = classifier()
    ok, _ = cc.classify(
        [{"filename": "stacks/a/main.tf", "status": "modified"}],
        cc.compile_patterns("stacks/**", "patterns", True),
        cc.compile_patterns("", "never-skip", False),
    )
    assert ok


def test_tofu_a_markdown_change_is_still_docs_only_with_the_default_never_skip():
    cc = classifier()
    ok, reason = cc.classify(
        [{"filename": "docs/a.md", "status": "modified"}],
        cc.compile_patterns("*.md\ndocs/**/*.md", "patterns", True),
        cc.compile_patterns(tofu_inputs()["never-skip-patterns"]["default"], "never-skip", False),
    )
    assert ok, reason


def test_tofu_gate_needs_the_classifier_and_waits_on_it():
    gate_job = jobs(doc("tofu-ci"))["ci-green"]
    assert "classify" in gate_job["needs"] and gate_job["if"] == "always()"


def test_tofu_the_test_jobs_keep_their_input_and_gain_the_docs_only_rule():
    all_jobs = jobs(doc("tofu-ci"))
    for name in ("test-dirs", "test"):
        cond = str(all_jobs[name]["if"])
        assert "inputs.test" in cond and RULE in cond and "!cancelled()" in cond, name
        assert "classify" in all_jobs[name]["needs"], name
    assert "classify" in all_jobs["test-dirs"]["needs"] and "test-dirs" in all_jobs["test"]["needs"]


TOFU_OK = {
    "classify": "success",
    "fmt": "success",
    "validate": "success",
    "test-dirs": "skipped",
    "test": "skipped",
    "tflint": "success",
    "trivy": "success",
    "policy": "skipped",
    "plan": "skipped",
    "workflow-lint": "success",
}


def tofu_gate(results: dict, *, test_requested: bool, docs_only: str):
    step = next(
        s for s in steps_of(jobs(doc("tofu-ci"))["ci-green"]) if str(s.get("name", "")).startswith("Every job passed")
    )
    needs_json = {k: {"result": v, "outputs": {}} for k, v in results.items()}
    env = {
        **os.environ,
        "RESULTS": json.dumps(needs_json),
        "TEST_REQUESTED": "true" if test_requested else "false",
        "DOCS_ONLY": docs_only,
    }
    return subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True, timeout=60)


def test_tofu_gate_a_docs_only_verdict_lets_the_asked_for_tests_be_skipped():
    assert tofu_gate(TOFU_OK, test_requested=True, docs_only="true").returncode == 0


def test_tofu_gate_a_skipped_test_without_a_docs_only_verdict_still_fails_when_asked_for():
    assert tofu_gate({**TOFU_OK, "classify": "skipped"}, test_requested=True, docs_only="").returncode == 1
    assert tofu_gate(TOFU_OK, test_requested=True, docs_only="false").returncode == 1


def test_tofu_gate_a_failed_classifier_fails_even_with_a_docs_only_verdict():
    assert tofu_gate({**TOFU_OK, "classify": "failure"}, test_requested=True, docs_only="true").returncode == 1


def test_tofu_gate_a_docs_only_verdict_never_hides_another_failure():
    assert tofu_gate({**TOFU_OK, "fmt": "failure"}, test_requested=True, docs_only="true").returncode == 1
    assert tofu_gate({**TOFU_OK, "test": "failure"}, test_requested=True, docs_only="true").returncode == 1

