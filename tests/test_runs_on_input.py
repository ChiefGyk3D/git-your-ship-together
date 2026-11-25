"""The `runs-on` input of security.yml and dast.yml (slice 1 of self-hosted runner support).

`runs-on` takes a string, an array or an object, so the input is a JSON string and every job reads it with
`fromJSON(inputs.runs-on)`. The default parses to the label the workflow used before the input existed, so a caller
that does not pass it sees no change. A job that follows the secretless egress input may only reach `audit` on a
GitHub-hosted label (EX-0001); the label check follows the input, see tests/test_egress_policy.py for the oracle.
"""

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
# workflow file -> the label every job used before the input existed
DEFAULTS = {"security.yml": "ubuntu-latest", "dast.yml": "ubuntu-24.04"}
EXPECTED = "${{ fromJSON(inputs.runs-on) }}"


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def test_something_was_collected():
    assert sum(len(load(n)["jobs"]) for n in DEFAULTS) >= 10


@pytest.mark.parametrize("name,label", sorted(DEFAULTS.items()))
def test_the_input_default_parses_to_todays_label(name, label):
    doc = load(name)
    spec = doc[True]["workflow_call"]["inputs"]["runs-on"]
    assert spec["type"] == "string" and spec.get("required") is not True
    assert json.loads(spec["default"]) == label
    assert "JSON" in spec["description"]


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_every_job_uses_the_input(name):
    for job_name, job in load(name)["jobs"].items():
        assert job["runs-on"] == EXPECTED, f"{name}:{job_name}"


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_the_header_documents_harden_runner_on_self_hosted_runners(name):
    head = (WORKFLOWS / name).read_text().split("\nname:")[0].lower()
    assert "self-hosted" in head and "no-op" in head and "2026-11-25" in head and "verified" in head


GUARD = "Refuse an untrusted self-hosted runner"


def guard_problems(doc: dict) -> list[str]:
    """Jobs without the guard, or with it too late (anything but the policy check and harden-runner before it)."""
    bad = []
    for name, job in doc["jobs"].items():
        steps = job["steps"]
        names = [s.get("name") for s in steps]
        if names.count(GUARD) != 1:
            bad.append(f"{name}: guard missing")
            continue
        before = steps[: names.index(GUARD)]
        if not all(
            s.get("name") == "Validate the egress policy inputs" or "harden-runner" in str(s.get("uses"))
            for s in before
        ):
            bad.append(f"{name}: a step runs before the guard")
    return bad


def guard_script(doc: dict) -> str:
    return next(s for s in next(iter(doc["jobs"].values()))["steps"] if s.get("name") == GUARD)["run"]


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_every_job_has_the_guard_early_and_identical(name):
    doc = load(name)
    assert guard_problems(doc) == []
    scripts = {j["steps"][[s.get("name") for s in j["steps"]].index(GUARD)]["run"] for j in doc["jobs"].values()}
    assert len(scripts) == 1


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_removing_the_guard_from_any_job_is_caught(name):
    doc = load(name)
    for victim in doc["jobs"]:
        mutated = copy.deepcopy(doc)
        mutated["jobs"][victim]["steps"] = [s for s in mutated["jobs"][victim]["steps"] if s.get("name") != GUARD]
        assert guard_problems(mutated) == [f"{victim}: guard missing"]
    late = copy.deepcopy(doc)
    first = next(iter(late["jobs"].values()))["steps"]
    first.insert(0, {"name": "x", "run": "true"})
    assert any("runs before" in p for p in guard_problems(late))


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_the_guard_inputs_come_through_env_never_interpolated(name):
    for job in load(name)["jobs"].values():
        step = next(s for s in job["steps"] if s.get("name") == GUARD)
        assert "${{" not in step["run"]
        assert set(step["env"]) == {"RUNNER_ENV", "EVENT_NAME", "REPO_PRIVATE", "HEAD_FORK", "ALLOW_PUBLIC"}
    spec = load(name)[True]["workflow_call"]["inputs"]["allow-self-hosted-public"]
    assert spec["type"] == "boolean" and spec["default"] is False


def run_guard(name: str, **env: str) -> subprocess.CompletedProcess:
    base = {
        "RUNNER_ENV": "github-hosted",
        "EVENT_NAME": "pull_request",
        "REPO_PRIVATE": "false",
        "HEAD_FORK": "false",
        "ALLOW_PUBLIC": "false",
    }
    clean = {k: v for k, v in os.environ.items() if k not in base}
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", guard_script(load(name))],
        capture_output=True,
        text=True,
        timeout=20,
        env={**clean, **base, **env},
    )


# (environment, event, private, head fork, allow input) -> exit code
CASES = [
    (dict(), 0),  # hosted public pull request: unchanged behavior
    (dict(RUNNER_ENV="GitHub-Hosted", HEAD_FORK="true"), 0),  # hosted fork PR is fine
    (dict(RUNNER_ENV="self-hosted"), 1),  # public, not allowed
    (dict(RUNNER_ENV="self-hosted", REPO_PRIVATE=""), 1),  # unknown fails closed
    (dict(RUNNER_ENV=""), 1),
    (dict(RUNNER_ENV="self-hosted", REPO_PRIVATE="true"), 0),  # private repository
    (dict(RUNNER_ENV="self-hosted", ALLOW_PUBLIC="true"), 0),  # explicit opt-in
    (dict(RUNNER_ENV="self-hosted", ALLOW_PUBLIC="true", HEAD_FORK="true"), 1),  # fork never, even with the input
    (dict(RUNNER_ENV="self-hosted", ALLOW_PUBLIC="true", REPO_PRIVATE="true", EVENT_NAME="pull_request_target"), 1),
    (dict(RUNNER_ENV="self-hosted", REPO_PRIVATE="true", HEAD_FORK="TRUE"), 1),
    (dict(RUNNER_ENV="self-hosted", ALLOW_PUBLIC="yes"), 1),  # only exactly true
]


@pytest.mark.parametrize("name", sorted(DEFAULTS))
@pytest.mark.parametrize("env,code", CASES)
def test_the_guard_decides_correctly(name, env, code):
    done = run_guard(name, **env)
    assert done.returncode == code, done.stdout + done.stderr


def test_the_guard_never_executes_hostile_values():
    done = run_guard("security.yml", RUNNER_ENV="self-hosted", EVENT_NAME="$(touch /nonexistent/x)", HEAD_FORK="`id`")
    assert done.returncode == 1 and "uid=" not in done.stdout + done.stderr
