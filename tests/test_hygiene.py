"""Hygiene the shared workflows hold to: no sudo, hash-checked cached tools, a type check, a coverage floor.

Each assertion was broken on purpose once to confirm it goes red with a message
naming the fix.
"""

from __future__ import annotations

import re

import pytest
import yaml
from test_new_repo import DAEMON, adopt, caller_text, write
from test_workflows import (
    HARDEN_RUNNER,
    REUSABLE,
    WORKFLOWS,
    all_steps,
    jobs,
    load,
    steps_of,
    triggers,
)

HYGIENE_FILES = [
    "python-ci.yml",
    "bash-ci.yml",
    "tofu-ci.yml",
    "arduino-ci.yml",
    "python-package-release.yml",
    "artifact-release.yml",
]
# Jobs that run a caller's own install command on the host. The documented
# example of each is `sudo apt-get install ...`, so they cannot lose sudo
# without breaking the callers that follow the README. Nothing else may.
SUDO_EXEMPT = {
    ("bash-ci.yml", "test"): "test-install-command",
    ("arduino-ci.yml", "test"): "test-install-command",
    ("artifact-release.yml", "build"): "build-install-command",
}
CACHE = "actions/cache@"
# The tools fetched by URL, and the inputs naming their pinned version and hash.
CACHED_DOWNLOADS = {
    "bash-ci.yml": {"shellcheck": "shellcheck-version", "shfmt": "shfmt-version"},
    "tofu-ci.yml": {"tofu": "tofu-version", "tflint": "tflint-version"},
    "arduino-ci.yml": {"arduino-cli": "arduino-cli-version"},
}


def run_text(job: dict) -> str:
    return "\n".join(str(s.get("run", "")) for s in steps_of(job))


def harden_step(job: dict) -> dict:
    first = steps_of(job)[0]
    assert str(first.get("uses", "")).startswith(HARDEN_RUNNER)
    return first


# --- disable-sudo -----------------------------------------------------------


@pytest.mark.parametrize("name", HYGIENE_FILES)
def test_every_harden_runner_disables_sudo_unless_the_job_needs_it(name):
    """A compromised step that can sudo owns the runner; a job that never sudoes should not be able to."""
    for job_name, job in jobs(load(WORKFLOWS / name)).items():
        if not steps_of(job):
            continue
        disabled = (harden_step(job).get("with") or {}).get("disable-sudo") is True
        needs_sudo = "sudo" in run_text(job) or (name, job_name) in SUDO_EXEMPT
        assert disabled != needs_sudo, f"{name}: job {job_name!r} " + (
            "needs sudo but disables it" if needs_sudo else "never uses sudo; set `disable-sudo: true`"
        )


@pytest.mark.parametrize(("name", "job_name"), sorted(SUDO_EXEMPT))
def test_a_job_that_keeps_sudo_runs_a_caller_install_command(name, job_name):
    """An exemption has to stay true: the job must really be the one that runs the caller's install command."""
    job = jobs(load(WORKFLOWS / name))[job_name]
    uses = [s for s in steps_of(job) if f"inputs.{SUDO_EXEMPT[(name, job_name)]}" in str(s.get("env", ""))]
    assert uses, f"{name}: job {job_name!r} no longer runs {SUDO_EXEMPT[(name, job_name)]}; drop the exemption"


# --- concurrency ------------------------------------------------------------


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_a_reusable_workflow_does_not_declare_concurrency(path):
    """In a called workflow `github.workflow` is the caller's name: the same group would cancel the caller."""
    doc = load(path)
    assert "concurrency" not in doc, f"{path.name}: concurrency belongs to the caller"
    for job_name, job in jobs(doc).items():
        assert "concurrency" not in job, f"{path.name}: job {job_name!r} declares concurrency"


CONCURRENCY = {
    "group": "${{ github.workflow }}-${{ github.ref }}",
    "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
}


def test_the_fixture_caller_cancels_superseded_pull_request_runs_only():
    assert load(WORKFLOWS / "ci.yml")["concurrency"] == CONCURRENCY


def test_the_generated_caller_cancels_superseded_pull_request_runs_only(tmp_path):
    out = tmp_path / "out"
    adopt(write(tmp_path / "tree", DAEMON), out)
    assert yaml.safe_load(caller_text(out, "ci.yml"))["concurrency"] == CONCURRENCY


# --- cached downloads -------------------------------------------------------


def downloads() -> list:
    found = []
    for name, tools in CACHED_DOWNLOADS.items():
        for job_name, job in jobs(load(WORKFLOWS / name)).items():
            steps = steps_of(job)
            for index, step in enumerate(steps):
                body = step.get("run")
                if isinstance(body, str) and "curl" in body:
                    found.append(pytest.param(name, job_name, steps, index, tools, id=f"{name}:{job_name}"))
    return found


@pytest.mark.parametrize(("name", "job_name", "steps", "index", "tools"), downloads())
def test_every_download_restores_a_cache_first_and_hashes_what_is_on_disk(name, job_name, steps, index, tools):
    step = steps[index]
    env = step["env"]
    version_input = next(i for i in tools.values() if f"inputs.{i} " in env["VERSION"])
    tool = next(t for t, i in tools.items() if i == version_input)
    caches = [s for s in steps[:index] if str(s.get("uses", "")).startswith(CACHE)]
    assert caches, f"{name}: job {job_name!r} downloads {tool} without restoring a cache first"
    key = caches[0]["with"]["key"]
    for part in (tool, f"inputs.{version_input}", "runner.os", "runner.arch"):
        assert part in key, f"{name}: the {tool} cache key {key!r} lacks {part}"
    assert caches[0]["with"]["path"] == env["CACHE_DIR"], f"{name}: {tool} caches a different path than it reads"
    body = step["run"]
    curl_line = next(line for line in body.splitlines() if "curl" in line)
    # The last hash check is outside the `if [ ! -f ]` that guards the download,
    # so it runs on the cached archive and the fresh one alike.
    check_lines = [line for line in body.splitlines() if re.search(r"sha256sum -c -$", line)]
    last = check_lines[-1]
    assert body.index(last) > body.index(curl_line)
    assert "--status" not in last, f"{name}: the final hash check must be the one that fails the job"
    indent = lambda line: len(line) - len(line.lstrip())  # noqa: E731
    assert indent(last) < indent(curl_line), f"{name}: the hash check of {tool} runs only when it downloads"
    assert "SHA256" in last and "$CACHE_DIR/" in last


def test_the_cache_action_is_pinned_and_never_reaches_a_publishing_workflow():
    for name in ("python-package-release.yml", "artifact-release.yml"):
        assert CACHE not in (WORKFLOWS / name).read_text(), f"{name} publishes; it must not restore a cache"
    for name in CACHED_DOWNLOADS:
        for line in (WORKFLOWS / name).read_text().splitlines():
            if CACHE in line:
                assert re.search(r"actions/cache@[0-9a-f]{40} # v\d+\.\d+\.\d+$", line.strip().removeprefix("uses: "))


# --- type check -------------------------------------------------------------


def test_python_ci_type_checks_only_when_asked_and_the_gate_waits_for_it():
    doc = load(WORKFLOWS / "python-ci.yml")
    inputs = triggers(doc)["workflow_call"]["inputs"]
    assert inputs["typecheck-command"]["default"] == ""
    assert inputs["typecheck-install-command"]["default"] == ""
    job = jobs(doc)["typecheck"]
    assert job["name"] == "Type check"
    assert job["if"] == "inputs.typecheck-command != ''"
    assert "typecheck" in jobs(doc)["ci-green"]["needs"]
    install = next(s for s in steps_of(job) if s.get("name") == "Install the type checker")
    assert install["if"] == "inputs.typecheck-install-command != ''", "an empty install command installs nothing"
    ran = next(s for s in steps_of(job) if s.get("name") == "Type check")
    assert ran["env"]["COMMAND"] == "${{ inputs.typecheck-command }}"
    assert "id-token" not in (job.get("permissions") or {})


def test_the_fixture_runs_the_type_check_with_a_pinned_checker():
    with_ = jobs(load(WORKFLOWS / "ci.yml"))["fixture-ci"]["with"]
    assert with_["typecheck-command"] == "mypy fixture/src"
    assert re.fullmatch(r"pip install mypy==\d+\.\d+\.\d+", with_["typecheck-install-command"])


# --- coverage threshold -----------------------------------------------------


def test_the_coverage_threshold_is_checked_on_the_leg_that_uploads_the_report():
    doc = load(WORKFLOWS / "python-ci.yml")
    assert triggers(doc)["workflow_call"]["inputs"]["coverage-threshold"]["default"] == ""
    step = next(s for s in steps_of(jobs(doc)["test"]) if s.get("name") == "Check the coverage threshold")
    condition = step["if"]
    assert "inputs.coverage-threshold != ''" in condition
    assert "matrix.python-version == inputs.coverage-python-version" in condition
    assert "fromJSON(inputs.runners)[0]" in condition
    assert step["env"]["THRESHOLD"] == "${{ inputs.coverage-threshold }}"
    assert "line-rate" in step["run"] and "sys.exit(1)" in step["run"]
    names = [s.get("name") for s in steps_of(jobs(doc)["test"])]
    assert names.index("Run tests") < names.index("Check the coverage threshold")


def test_the_fixture_produces_a_report_and_meets_a_threshold_below_what_it_measures():
    with_ = jobs(load(WORKFLOWS / "ci.yml"))["fixture-ci"]["with"]
    assert "--cov-report=xml" in with_["test-command"], "the threshold reads the XML the tests write"
    threshold = float(with_["coverage-threshold"])
    assert 0 < threshold < 76.4, "measured 76.47% line coverage on 2026-10-02; keep a few points of slack"
    assert "pytest-cov==" in (WORKFLOWS.parent.parent / "fixture" / "requirements.in").read_text()
    assert "--hash=sha256:" in (WORKFLOWS.parent.parent / "fixture" / "requirements.txt").read_text()


def test_every_run_block_here_reads_inputs_through_env():
    """The new steps join the rule test_workflows enforces for the rest; this names the two that carry data."""
    for name in ("python-ci.yml",):
        for job_name, step in all_steps(WORKFLOWS / name):
            if step.get("name") in ("Check the coverage threshold", "Type check"):
                assert "${{" not in str(step.get("run")), f"{job_name}: {step.get('name')} interpolates into run:"


@pytest.mark.parametrize("path", [WORKFLOWS / "python-ci.yml", WORKFLOWS / "bash-ci.yml"], ids=lambda p: p.name)
def test_the_distro_job_marks_the_mounted_checkout_safe_for_git(path):
    """The image runs as root over a checkout owned by the runner's user; git refuses that until told."""
    steps = load(path)["jobs"]["distro"]["steps"]
    run = next(s["run"] for s in steps if s.get("name") == "Run the tests in the image")
    assert "git config --global --add safe.directory /src" in run
    assert run.index('eval "$SETUP"') < run.index("safe.directory") < run.index('eval "$TEST"')
