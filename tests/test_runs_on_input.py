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
import tempfile
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


GUARD_ENV = {"RUNNER_ENV", "EVENT_NAME", "HEAD_REPO", "THIS_REPO", "ALLOW_SELF_HOSTED"}
# Variables that change how bash behaves, or what it runs, when the script starts.
SHELL_ENV = {
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "PS4",
    "IFS",
    "PATH",
    "BASH_XTRACEFD",
    "CDPATH",
    "GLOBIGNORE",
    "LD_PRELOAD",
    "PROMPT_COMMAND",
}


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
        step = steps[names.index(GUARD)]
        if "if" in step:
            bad.append(f"{name}: the guard has an `if`")
        if step.get("continue-on-error") not in (None, False):
            bad.append(f"{name}: the guard has continue-on-error")
        if job.get("continue-on-error") not in (None, False):
            bad.append(f"{name}: the job has continue-on-error")
        if step.get("shell") != "bash":
            bad.append(f"{name}: the guard shell is not exactly bash")
        if "shell" in (job.get("defaults") or {}).get("run", {}) or "shell" in (doc.get("defaults") or {}).get(
            "run", {}
        ):
            bad.append(f"{name}: a defaults.run.shell override")
        if set(step.get("env") or {}) != GUARD_ENV:
            bad.append(f"{name}: the guard env is not exactly its inputs")
        for where, env in (("job", job.get("env")), ("workflow", doc.get("env"))):
            if isinstance(env, dict) and set(env) & SHELL_ENV:
                bad.append(f"{name}: the {where} env can change shell behavior")
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
    for victim in doc["jobs"]:
        for key, value, word in (("if", False, "`if`"), ("continue-on-error", True, "continue-on-error")):
            neutered = copy.deepcopy(doc)
            step = next(s for s in neutered["jobs"][victim]["steps"] if s.get("name") == GUARD)
            step[key] = value
            assert any(word in x for x in guard_problems(neutered)), (victim, key)
        neutered = copy.deepcopy(doc)
        neutered["jobs"][victim]["continue-on-error"] = True
        assert any("the job has" in x for x in guard_problems(neutered)), victim
    for victim in doc["jobs"]:
        for shell in ("bash {0} || true", "sh", "bash -e {0}", None):
            neutered = copy.deepcopy(doc)
            step = next(s for s in neutered["jobs"][victim]["steps"] if s.get("name") == GUARD)
            if shell is None:
                del step["shell"]
            else:
                step["shell"] = shell
            assert any("shell is not exactly" in x for x in guard_problems(neutered)), (victim, shell)
        neutered = copy.deepcopy(doc)
        neutered["jobs"][victim]["defaults"] = {"run": {"shell": "sh"}}
        assert any("defaults.run.shell" in x for x in guard_problems(neutered)), victim
        neutered = copy.deepcopy(doc)
        neutered["defaults"] = {"run": {"shell": "sh"}}
        assert any("defaults.run.shell" in x for x in guard_problems(neutered)), victim
        for var in sorted(SHELL_ENV):
            for where in ("step", "job", "workflow"):
                neutered = copy.deepcopy(doc)
                if where == "step":
                    step = next(s for s in neutered["jobs"][victim]["steps"] if s.get("name") == GUARD)
                    step["env"][var] = "/dev/null"
                elif where == "job":
                    neutered["jobs"][victim]["env"] = {var: "/dev/null"}
                else:
                    neutered["env"] = {var: "/dev/null"}
                assert guard_problems(neutered), (victim, var, where)
    late = copy.deepcopy(doc)
    first = next(iter(late["jobs"].values()))["steps"]
    first.insert(0, {"name": "x", "run": "true"})
    assert any("runs before" in p for p in guard_problems(late))


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_the_guard_inputs_come_through_env_never_interpolated(name):
    for job in load(name)["jobs"].values():
        step = next(s for s in job["steps"] if s.get("name") == GUARD)
        assert "${{" not in step["run"]
        assert set(step["env"]) == {
            "RUNNER_ENV",
            "EVENT_NAME",
            "HEAD_REPO",
            "THIS_REPO",
            "ALLOW_SELF_HOSTED",
        }
    spec = load(name)[True]["workflow_call"]["inputs"]["allow-self-hosted"]
    assert spec["type"] == "boolean" and spec["default"] is False


def run_guard(name: str, **env: str) -> subprocess.CompletedProcess:
    base = {
        "RUNNER_ENV": "github-hosted",
        "EVENT_NAME": "pull_request",
        "HEAD_REPO": "o/r",
        "THIS_REPO": "o/r",
        "ALLOW_SELF_HOSTED": "false",
    }
    clean = {k: v for k, v in os.environ.items() if k not in base}
    doc = load(name)
    shell = next(s for s in next(iter(doc["jobs"].values()))["steps"] if s.get("name") == GUARD)["shell"]
    assert shell == "bash"  # GitHub expands `bash` to: bash --noprofile --norc -eo pipefail {0}
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "step.sh"
        script.write_text(guard_script(doc))
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
            capture_output=True,
            text=True,
            timeout=20,
            env={**clean, **base, **env},
        )


# (environment, event, head repository, this repository, allow input) -> exit code
CASES = [
    (dict(), 0),  # hosted public pull request: unchanged behavior
    (dict(RUNNER_ENV="GitHub-Hosted", HEAD_REPO="fork/r"), 0),  # hosted fork PR is fine
    (dict(RUNNER_ENV="", ALLOW_SELF_HOSTED="false"), 1),  # an unknown environment is treated as self-hosted
    (dict(RUNNER_ENV="self-hosted"), 1),  # not attested
    (dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED=""), 1),  # a missing value fails closed
    (dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="TRUE"), 0),  # the comparison ignores case, like GitHub's
    (dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="true"), 0),  # attested, same-repository PR allowed
    (dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="true", HEAD_REPO="Fork/r"), 1),  # fork PR refused
    (dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="true", HEAD_REPO=""), 1),  # deleted fork: empty head repo
    (dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="true", THIS_REPO=""), 1),
    (dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="true", HEAD_REPO="O/R"), 0),  # case-insensitive full name
    (dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="yes"), 1),  # only exactly true
]
for _event in ("push", "schedule", "workflow_dispatch", "release", "PUSH"):
    CASES.append((dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="true", EVENT_NAME=_event, HEAD_REPO=""), 0))
for _event in (
    "merge_group",
    "workflow_run",
    "issue_comment",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
    "repository_dispatch",
    "something_new",
    "",
):
    # refused whatever the opt-in or the privacy of the repository says
    CASES.append((dict(RUNNER_ENV="self-hosted", ALLOW_SELF_HOSTED="true", EVENT_NAME=_event), 1))


@pytest.mark.parametrize("name", sorted(DEFAULTS))
@pytest.mark.parametrize("env,code", CASES)
def test_the_guard_decides_correctly(name, env, code):
    done = run_guard(name, **env)
    assert done.returncode == code, done.stdout + done.stderr


def test_the_guard_never_executes_hostile_values():
    done = run_guard("security.yml", RUNNER_ENV="self-hosted", EVENT_NAME="$(touch /nonexistent/x)", HEAD_REPO="`id`")
    assert done.returncode == 1 and "uid=" not in done.stdout + done.stderr


def test_no_workflow_reads_the_repository_visibility():
    for name in DEFAULTS:
        assert "repository.private" not in (WORKFLOWS / name).read_text()
