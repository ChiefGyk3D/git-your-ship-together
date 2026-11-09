"""PR title lint behavior and the reusable workflow that carries it."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "check_pr_title.py"
WORKFLOW = REPO / ".github" / "workflows" / "pr-title-lint.yml"


def run_title(
    title: str,
    *,
    pattern: str | None = None,
    max_length: str | int | None = None,
    allow_prefixes: str | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PR_TITLE"] = title
    if pattern is not None:
        env["PATTERN"] = pattern
    if max_length is not None:
        env["MAX_LENGTH"] = str(max_length)
    if allow_prefixes is not None:
        env["ALLOW_PREFIXES"] = allow_prefixes
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT)],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )


@pytest.mark.parametrize(
    "title",
    [
        "Add pull request title linting",
        "Fix title handling (Refs #12)",
        "Harden title handling (Closes #12)",
        "Update café title validation",
    ],
)
def test_default_pattern_accepts_imperative_titles(title):
    result = run_title(title)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "title",
    [
        "Added pull request title linting",
        "Fix it.",
        "Fix\nmalicious title",
        "x" * 121,
    ],
)
def test_default_pattern_rejects_bad_titles(title):
    result = run_title(title)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "::error title=PR title lint::" in result.stdout
    assert "rule=" in result.stdout and "fix=" in result.stdout


def test_custom_pattern_replaces_the_default():
    result = run_title("ABC-42 ship it", pattern=r"ABC-\d+ .+")
    assert result.returncode == 0, result.stdout + result.stderr


def test_custom_max_length_is_applied_before_matching():
    result = run_title("a" * 40 + "!", pattern=r"(a+)+$", max_length=40)
    assert result.returncode == 1
    assert "41 characters" in result.stdout
    assert "at most 40" in result.stdout
    assert "timed out" not in result.stdout


@pytest.mark.parametrize("prefix", ["release:", "chore(deps):"])
def test_allowed_prefix_bypasses_only_the_pattern(prefix):
    result = run_title(f"{prefix} not imperative", allow_prefixes=" release: , chore(deps): ")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "allowed prefix" in result.stdout


def test_allowed_prefix_does_not_bypass_max_length():
    result = run_title("release:" + "x" * 30, max_length=20, allow_prefixes="release:")
    assert result.returncode == 1
    assert "at most 20" in result.stdout


@pytest.mark.parametrize(
    "title",
    [
        "Fix $(touch /tmp/pr-title-pwned) handling",
        "Fix `echo nope` and $HOME handling",
        "Fix 100% ::error:: command handling",
    ],
)
def test_shell_metacharacters_are_data(title, tmp_path):
    marker = Path("/tmp/pr-title-pwned")
    marker.unlink(missing_ok=True)
    result = run_title(title, pattern=r"Fix .+")
    assert result.returncode == 0, result.stdout + result.stderr
    assert not marker.exists()


def test_newline_is_escaped_out_of_the_workflow_command():
    result = run_title("Fix first\n::error::forged", pattern=r"Fix .+")
    assert result.returncode == 1
    assert result.stdout.count("\n") == 1
    assert "%0A" in result.stdout
    assert "\n::error::forged" not in result.stdout


def test_unicode_is_counted_as_characters_not_bytes():
    result = run_title("Fix café", pattern=r"Fix .+", max_length=8)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "8 characters" in result.stdout


def test_invalid_regular_expression_is_clear_and_has_no_traceback():
    result = run_title("Fix title", pattern="[")
    assert result.returncode == 2
    assert "invalid regular expression" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_catastrophic_regular_expression_is_interrupted():
    started = time.monotonic()
    result = run_title("a" * 119 + "!", pattern=r"(a+)+$")
    elapsed = time.monotonic() - started
    assert result.returncode == 2
    assert elapsed < 2
    assert "regular expression timed out" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_bad_max_length_is_a_clear_configuration_error():
    result = run_title("Fix title", max_length="zero")
    assert result.returncode == 2
    assert "max-length must be a positive integer" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_workflow_reads_the_event_title_through_env_and_never_checks_out():
    doc = yaml.safe_load(WORKFLOW.read_text())
    job = doc["jobs"]["lint"]
    check = next(step for step in job["steps"] if step.get("name") == "Check the pull request title")
    assert check["if"] == "github.event_name == 'pull_request'"
    assert check["env"]["PR_TITLE"] == "${{ github.event.pull_request.title }}"
    assert "${{" not in check["run"]
    assert not any("actions/checkout@" in str(step.get("uses", "")) for step in job["steps"])
    assert job["permissions"] == {}


def test_non_pull_request_event_is_a_notice_and_no_op():
    doc = yaml.safe_load(WORKFLOW.read_text())
    job = doc["jobs"]["lint"]
    notice = next(step for step in job["steps"] if step.get("name") == "Notice unsupported event")
    assert notice["if"] == "github.event_name != 'pull_request'"
    assert "::notice" in notice["run"]


def test_workflow_carries_the_script_byte_for_byte():
    text = WORKFLOW.read_text()
    match = re.search(r"          #!/usr/bin/env python3\n(?P<body>.*?)\n          PY\n", text, re.DOTALL)
    assert match, "pr-title-lint.yml has no inlined check_pr_title.py"
    inlined = "\n".join(line.removeprefix("          ") for line in match.group("body").splitlines())
    assert "#!/usr/bin/env python3\n" + inlined + "\n" == SCRIPT.read_text()


def test_ci_dogfoods_title_lint_and_gates_on_it():
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())
    jobs = doc["jobs"]
    fixture = jobs["fixture-pr-title-lint"]
    assert fixture["uses"] == "./.github/workflows/pr-title-lint.yml"
    assert fixture["needs"] == "changes"
    assert fixture["if"] == "needs.changes.outputs.docs-only != 'true'"
    gate = jobs["ci-green"]
    assert "fixture-pr-title-lint" in gate["needs"]
    gate_step = next(step for step in gate["steps"] if step.get("name") == "Every job passed")
    assert "fixture-pr-title-lint" in gate_step["with"]["required-jobs"].split()
    assert "fixture-pr-title-lint" in gate_step["with"]["skippable-jobs"].split()
