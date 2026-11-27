"""The `runs-on` input of security.yml, dast.yml, tofu-ci.yml, bash-ci.yml, python-ci.yml and
container-release.yml (self-hosted runner support).

`runs-on` takes a string, an array or an object, so the input is a JSON string and every job reads it with
`fromJSON(inputs.runs-on)`. The default parses to the label the workflow used before the input existed, so a caller
that does not pass it sees no change. A job that follows the secretless egress input may only reach `audit` on a
GitHub-hosted label (EX-0001); the label check follows the input, see tests/test_egress_policy.py for the oracle.
"""

import copy
import hashlib
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
DEFAULTS = {
    "security.yml": "ubuntu-latest",
    "dast.yml": "ubuntu-24.04",
    "tofu-ci.yml": "ubuntu-latest",
    "bash-ci.yml": "ubuntu-latest",
    "python-ci.yml": "ubuntu-latest",
    "container-release.yml": "ubuntu-24.04",
}
EXPECTED = "${{ fromJSON(inputs.runs-on) }}"
# matrix jobs take their runner from the matrix (the `runners` and `distro-runners` inputs), never from runs-on
MATRIX_RUNS_ON = {
    ("container-release.yml", "build"): "${{ matrix.runner }}",
    ("container-release.yml", "build-local"): "${{ matrix.runner }}",
    ("bash-ci.yml", "test"): "${{ matrix.runner }}",
    ("bash-ci.yml", "distro"): "${{ matrix.runner }}",
    ("python-ci.yml", "test"): "${{ matrix.runner }}",
    ("python-ci.yml", "distro"): "${{ matrix.runner }}",
}


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
        assert job["runs-on"] == MATRIX_RUNS_ON.get((name, job_name), EXPECTED), f"{name}:{job_name}"


def test_container_build_jobs_keep_their_github_hosted_matrix_runners():
    doc = load("container-release.yml")
    for name in ("build", "build-local"):
        assert doc["jobs"][name]["runs-on"] == "${{ matrix.runner }}"
        assert doc["jobs"][name]["strategy"]["matrix"]["include"] == "${{ fromJSON(needs.plan.outputs.matrix) }}"
    plan_script = next(step["run"] for step in doc["jobs"]["plan"]["steps"] if step.get("id") == "plan")
    assert "linux/arm64) runner=ubuntu-24.04-arm ;;" in plan_script
    assert "*) runner=ubuntu-24.04 ;;" in plan_script


def test_bash_ci_matrix_jobs_keep_the_existing_runner_input():
    jobs = load("bash-ci.yml")["jobs"]
    assert jobs["test"]["runs-on"] == "${{ matrix.runner }}"
    assert jobs["distro"]["runs-on"] == "${{ matrix.runner }}"
    assert jobs["test"]["strategy"]["matrix"]["runner"] == "${{ fromJSON(inputs.runners) }}"
    assert jobs["distro"]["strategy"]["matrix"]["runner"] == "${{ fromJSON(inputs.distro-runners) }}"


def test_python_ci_matrix_jobs_keep_their_matrix_runner():
    doc = load("python-ci.yml")
    matrix_jobs = {n for n, j in doc["jobs"].items() if "matrix" in (j.get("strategy") or {})}
    assert matrix_jobs == {"test", "distro"}
    for n in matrix_jobs:
        assert doc["jobs"][n]["runs-on"] == "${{ matrix.runner }}", n
        assert "inputs.runs-on" not in json.dumps(doc["jobs"][n]), n


@pytest.mark.parametrize("name", ["python-ci.yml"])
def test_python_ci_egress_follows_the_label_for_non_matrix_jobs(name):
    doc = load(name)
    for n, job in doc["jobs"].items():
        text = json.dumps(job)
        if n in MATRIX_JOBS_PYCI:
            assert "matrix.runner" in text and "inputs.runs-on" not in text, n
        elif n in ID_TOKEN_JOBS_PYCI:
            assert id_token_job_problems(job) == [], n
        else:
            assert "contains(fromJSON(" in text and "fromJSON(inputs.runs-on)" in text, n


ID_TOKEN_JOBS_PYCI = {"coverage", "classify"}  # classify: the job token reaches the GitHub API, so it stays in block (#460)
ORIGINAL_EGRESS_POLICY = "${{ inputs.egress-policy == 'audit' && 'audit' || 'block' }}"
ORIGINAL_DISABLE_TELEMETRY = "${{ (inputs.egress-policy == 'audit' && 'audit' || 'block') == 'block' }}"


def id_token_job_problems(job):
    """Why an id-token job's harden-runner step is not the original egress expression."""
    problems = []
    steps = [s for s in job["steps"] if "harden-runner" in s.get("uses", "")]
    if not steps:
        problems.append("no harden-runner step")
    for s in steps:
        if s["with"]["egress-policy"] != ORIGINAL_EGRESS_POLICY:
            problems.append("egress-policy changed")
        if s["with"]["disable-telemetry"] != ORIGINAL_DISABLE_TELEMETRY:
            problems.append("disable-telemetry changed")
    if "contains(fromJSON(" in json.dumps(job):
        problems.append("runner check present")
    if job["runs-on"] != EXPECTED:
        problems.append("runs-on changed")
    return problems


def test_python_ci_id_token_job_runner_check_is_flagged():
    """Mutation: re-adding the hosted-label check to the coverage job must be flagged."""
    job = copy.deepcopy(load("python-ci.yml")["jobs"]["coverage"])
    assert job["permissions"].get("id-token") == "write"
    assert id_token_job_problems(job) == []
    step = next(s for s in job["steps"] if "harden-runner" in s.get("uses", ""))
    step["with"]["egress-policy"] = step["with"]["egress-policy"].replace(
        "inputs.egress-policy == 'audit'",
        "inputs.egress-policy == 'audit' && contains(fromJSON('[\"ubuntu-latest\"]'), fromJSON(inputs.runs-on))",
    )
    assert "egress-policy changed" in id_token_job_problems(job)
    assert "runner check present" in id_token_job_problems(job)


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_the_header_documents_harden_runner_on_self_hosted_runners(name):
    head = (WORKFLOWS / name).read_text().split("\nname:")[0].lower()
    assert "self-hosted" in head and "no-op" in head and "2026-11-25" in head and "verified" in head


GUARD = "Refuse an untrusted self-hosted runner"


GUARD_ENV = {
    "RUNNER_ENV": "${{ runner.environment }}",
    "EVENT_NAME": "${{ github.event_name }}",
    "HEAD_REPO": "${{ github.event.pull_request.head.repo.full_name }}",
    "THIS_REPO": "${{ github.repository }}",
    "ALLOW_SELF_HOSTED": "${{ inputs.allow-self-hosted }}",
}
VALIDATOR = "Validate the egress policy inputs"
HARDEN = "step-security/harden-runner@46b06cea07f9e64621fdf066ba77ac6915163d43"  # v2.22.3
HARDEN_WITH = {"egress-policy", "allowed-endpoints", "disable-telemetry", "disable-sudo"}
# The POLICY_ variables each workflow's validator declares. A job's validator env must be exactly these.
VALIDATOR_VARS = {
    "security.yml": ("EGRESS_POLICY", "EGRESS_POLICY_SECRETLESS", "SEMGREP_EGRESS_POLICY"),
    "dast.yml": ("EGRESS_POLICY", "EGRESS_POLICY_SECRETLESS"),
    "tofu-ci.yml": ("EGRESS_POLICY", "EGRESS_POLICY_SECRETLESS"),
    "bash-ci.yml": ("DISTRO_EGRESS_POLICY", "EGRESS_POLICY", "EGRESS_POLICY_SECRETLESS"),
    "python-ci.yml": ("DISTRO_EGRESS_POLICY", "EGRESS_POLICY", "EGRESS_POLICY_SECRETLESS"),
    "container-release.yml": ("EGRESS_POLICY", "EGRESS_POLICY_SECRETLESS"),
}
# (file, job) whose harden-runner deliberately omits disable-sudo: its caller install command may need sudo
SUDO_EXCEPTIONS = {("bash-ci.yml", "test")}
CHECK_ACTION = REPO / ".github" / "actions" / "egress-policy-check" / "action.yml"
# Everything that can decide whether a job runs, and the environment it starts with, as the jobs have it today:
# an allowlist, so a new `if`, `needs`, `strategy` or env key is a change this test makes the author look at.
PYCI_TEST_NEEDS = [
    "classify",
    "lint",
    "typecheck",
    "workflow-lint",
    "test",
    "distro",
    "coverage",
    "smoke",
    "docker",
    "fragment-check",
    "commit-claims",
]
MATRIX_JOBS_PYCI = {"test", "distro"}
JOB_SCHEDULING = {
    ("bash-ci.yml", "shellcheck"): {},
    ("bash-ci.yml", "shfmt"): {"if": "inputs.shfmt"},
    ("bash-ci.yml", "classify"): {
        "if": "github.event_name == 'pull_request' && inputs.skip-docs-only",
    },
    ("bash-ci.yml", "test"): {
        "if": "${{ !cancelled() && needs.classify.outputs.docs-only != 'true' && inputs.test-command != '' }}",
        "needs": "classify",
        "strategy": {"fail-fast": False, "matrix": {"runner": "${{ fromJSON(inputs.runners) }}"}},
    },
    ("bash-ci.yml", "distro"): {
        "if": "${{ !cancelled() && needs.classify.outputs.docs-only != 'true' && inputs.distros != '[]' && inputs.test-command != '' }}",
        "needs": "classify",
        "strategy": {
            "fail-fast": False,
            "matrix": {
                "image": "${{ fromJSON(inputs.distros) }}",
                "runner": "${{ fromJSON(inputs.distro-runners) }}",
            },
        },
    },
    ("bash-ci.yml", "config-lint"): {"if": "inputs.config-lint-command != ''"},
    ("bash-ci.yml", "workflow-lint"): {"if": "inputs.workflow-lint"},
    ("bash-ci.yml", "fragment-check"): {
        "if": "github.event_name == 'pull_request' && inputs.fragment-check-command != ''"
    },
    ("bash-ci.yml", "commit-claims"): {
        "if": "github.event_name == 'pull_request' && inputs.commit-claims-command != ''"
    },
    ("bash-ci.yml", "ci-green"): {
        "if": "always()",
        "needs": [
            "classify",
            "shellcheck",
            "shfmt",
            "test",
            "distro",
            "config-lint",
            "workflow-lint",
            "fragment-check",
            "commit-claims",
        ],
    },
    ("container-release.yml", "plan"): {},
    ("container-release.yml", "dockerfile-lint"): {"if": "inputs.hadolint"},
    ("container-release.yml", "build"): {
        "if": "${{ !cancelled() && needs.plan.result == 'success' && needs.plan.outputs.publish == 'true' && "
        "(needs.dockerfile-lint.result == 'success' || needs.dockerfile-lint.result == 'skipped') }}",
        "needs": ["plan", "dockerfile-lint"],
        "strategy": {"fail-fast": False, "matrix": {"include": "${{ fromJSON(needs.plan.outputs.matrix) }}"}},
    },
    ("container-release.yml", "build-local"): {
        "if": "${{ !cancelled() && needs.plan.result == 'success' && needs.plan.outputs.publish != 'true' && "
        "(needs.dockerfile-lint.result == 'success' || needs.dockerfile-lint.result == 'skipped') }}",
        "needs": ["plan", "dockerfile-lint"],
        "strategy": {"fail-fast": False, "matrix": {"include": "${{ fromJSON(needs.plan.outputs.matrix) }}"}},
    },
    ("container-release.yml", "merge"): {
        "if": "needs.plan.outputs.publish == 'true' && github.event_name != 'pull_request'",
        "needs": ["plan", "build"],
        "concurrency": {"group": "container-release-${{ needs.plan.outputs.serialize }}", "cancel-in-progress": False},
    },
    ("dast.yml", "scan"): {
        "env": {
            "ZAP_IMAGE": "ghcr.io/zaproxy/zaproxy:2.17.0@"
            "sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
        }
    },
    ("dast.yml", "upload"): {
        "if": "always() && inputs.upload-sarif && needs.scan.outputs.sarif == 'true' && "
        "(github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)",
        "needs": "scan",
    },
    ("python-ci.yml", "ci-green"): {"if": "always()", "needs": PYCI_TEST_NEEDS},
    ("python-ci.yml", "commit-claims"): {
        "if": "github.event_name == 'pull_request' && inputs.commit-claims-command != ''"
    },
    ("python-ci.yml", "coverage"): {"if": "inputs.codecov && github.event_name != 'pull_request'", "needs": "test"},
    ("python-ci.yml", "classify"): {
        "if": "github.event_name == 'pull_request' && inputs.skip-docs-only",
    },
    ("python-ci.yml", "distro"): {
        "if": "${{ !cancelled() && needs.classify.outputs.docs-only != 'true' && inputs.distros != '[]' }}",
        "needs": "classify",
        "strategy": {
            "fail-fast": False,
            "matrix": {"image": "${{ fromJSON(inputs.distros) }}", "runner": "${{ fromJSON(inputs.distro-runners) }}"},
        },
    },
    ("python-ci.yml", "docker"): {"if": "inputs.docker-build"},
    ("python-ci.yml", "fragment-check"): {
        "if": "github.event_name == 'pull_request' && inputs.fragment-check-command != ''"
    },
    ("python-ci.yml", "lint"): {},
    ("python-ci.yml", "smoke"): {"if": "inputs.smoke-command != ''"},
    ("python-ci.yml", "test"): {
        "if": "${{ !cancelled() && needs.classify.outputs.docs-only != 'true' }}",
        "needs": "classify",
        "strategy": {
            "fail-fast": False,
            "matrix": {
                "python-version": "${{ fromJSON(startsWith(github.event_name, 'pull_request') && "
                "inputs.pr-python-versions != '' && inputs.pr-python-versions || inputs.python-versions) }}",
                "runner": "${{ fromJSON(inputs.runners) }}",
            },
        }
    },
    ("python-ci.yml", "typecheck"): {"if": "inputs.typecheck-command != ''"},
    ("python-ci.yml", "workflow-lint"): {"if": "inputs.workflow-lint"},
    ("security.yml", "advanced-security-check"): {},
    ("security.yml", "codeql"): {"if": "inputs.codeql && inputs.advanced-security != 'false'"},
    ("security.yml", "dependency-audit"): {"if": "inputs.pip-audit-requirements != '' || inputs.audit-command != ''"},
    ("security.yml", "dependency-review"): {
        "if": "inputs.dependency-review && github.event_name == 'pull_request' && inputs.advanced-security != 'false'"
    },
    ("security.yml", "gitleaks"): {"if": "inputs.gitleaks"},
    ("security.yml", "scorecard"): {
        "if": "inputs.scorecard && github.event_name != 'pull_request' && "
        "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
    },
    ("security.yml", "semgrep"): {"if": "inputs.semgrep"},
    ("security.yml", "snyk"): {
        "if": "inputs.snyk && github.event_name != 'pull_request' && "
        "(inputs.snyk-on == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')"
    },
    ("tofu-ci.yml", "fmt"): {},
    ("tofu-ci.yml", "validate"): {},
    ("tofu-ci.yml", "test-dirs"): {"if": "inputs.test"},
    ("tofu-ci.yml", "test"): {
        "if": "inputs.test",
        "needs": "test-dirs",
        "strategy": {"fail-fast": False, "matrix": {"leg": "${{ fromJSON(needs.test-dirs.outputs.legs) }}"}},
    },
    ("tofu-ci.yml", "tflint"): {"if": "inputs.tflint"},
    ("tofu-ci.yml", "trivy"): {"if": "inputs.trivy"},
    ("tofu-ci.yml", "policy"): {"if": "inputs.policy-directories != ''"},
    ("tofu-ci.yml", "plan"): {"if": "inputs.plan-command != '' && github.event_name != 'pull_request'"},
    ("tofu-ci.yml", "workflow-lint"): {"if": "inputs.workflow-lint"},
    ("tofu-ci.yml", "ci-green"): {
        "if": "always()",
        "needs": ["fmt", "validate", "test-dirs", "test", "tflint", "trivy", "policy", "plan", "workflow-lint"],
    },
}
# Job keys that may exist at all; a strategy is allowed only at its exact known value. `container`, `services`,
# `defaults`, `continue-on-error` may not. `concurrency` may exist only with the exact value in JOB_SCHEDULING.
JOB_KEYS = {
    "name",
    "runs-on",
    "timeout-minutes",
    "permissions",
    "steps",
    "outputs",
    "if",
    "needs",
    "env",
    "strategy",
    "concurrency",
}
WORKFLOW_KEYS = {"name", True, "permissions", "jobs"}  # `on` parses to True


# Review tripwires, not immutable security pins: SHA-256 of the exact script text. The equality with the composite
# action alone would pass a backdoor written into the action and every inline copy together, so a digest makes that
# edit visible in review. It does not stop a coordinated edit by itself: a script and its digest changed in one pull
# request are stopped only by CODEOWNERS review of this file and of the workflows. Change a constant only deliberately,
# when the validator or the guard legitimately changes, after reading the diff of the script itself.
VALIDATOR_SHA256 = "3d1b25b484795c2d26e5e997ccc1f102e1273b68f13e7fad8590490ce0453c72"  # review tripwire, not a pin
GUARD_SHA256 = "6d1587f9bda84a487bec47ee347a97499dde635309e0ee0eaab823c5ccacc9bb"  # review tripwire, not a pin
PIN_HINT = "update the SHA-256 constant in tests/test_runs_on_input.py deliberately if this script legitimately changed"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check_script() -> str:
    return yaml.safe_load(CHECK_ACTION.read_text())["runs"]["steps"][0]["run"]


def guard_problems(doc: dict, file: str | None = None, action_script: str | None = None) -> list[str]:
    """Jobs without an operative guard. Allowlist based: the guard is the third step, the validator and
    harden-runner before it pinned exactly; the guard's own keys and environment are pinned exactly, and nothing
    at step, job or workflow level may add an environment variable, a shell default, a condition or a matrix that
    is not already there."""
    bad = []
    if set(doc) - WORKFLOW_KEYS:
        bad.append(f"workflow: unexpected keys {sorted(map(str, set(doc) - WORKFLOW_KEYS))}")
    for name, job in doc["jobs"].items():
        steps = job["steps"]
        names = [s.get("name") for s in steps]
        if names.count(GUARD) != 1:
            bad.append(f"{name}: guard missing")
            continue
        # `strategy` is allowed only where the known schedule has one (python-ci's matrix jobs)
        extra = {"strategy"} if file is not None and "strategy" in JOB_SCHEDULING[(file, name)] else set()
        if set(job) - JOB_KEYS - extra:
            bad.append(f"{name}: unexpected job keys {sorted(set(job) - JOB_KEYS - extra)}")
        if job.get("continue-on-error") not in (None, False):
            bad.append(f"{name}: the job has continue-on-error")
        if file is not None:
            expected = JOB_SCHEDULING[(file, name)]
            for key in ("if", "needs", "env", "strategy", "concurrency"):
                if job.get(key) != expected.get(key):
                    bad.append(f"{name}: the job {key} differs from the known value")
        if names.index(GUARD) != 2:
            bad.append(f"{name}: the guard is not the third step")
            continue
        if len(steps) < 3:
            bad.append(f"{name}: fewer than three steps")
            continue
        first, second, step = steps[0], steps[1], steps[2]
        expected_env = {
            "POLICY_" + v: "${{ inputs." + v.lower().replace("_", "-") + " }}" for v in VALIDATOR_VARS.get(file, ())
        }
        if (
            first.get("name") != VALIDATOR
            or first.get("run") != (action_script if action_script is not None else check_script())
            or set(first) != {"name", "timeout-minutes", "shell", "working-directory", "env", "run"}
            or first["shell"] != "bash"
            or first.get("env") != expected_env
        ):
            bad.append(f"{name}: the policy validator is not the exact expected step")
        sudo_exception = (file, name) in SUDO_EXCEPTIONS
        harden_keys = HARDEN_WITH - {"disable-sudo"} if sudo_exception else HARDEN_WITH
        harden_with = second.get("with") or {}
        if (
            second.get("uses") != HARDEN
            or set(second) != {"uses", "with"}
            or set(harden_with) != harden_keys
            or (not sudo_exception and harden_with.get("disable-sudo") is not True)
        ):
            bad.append(f"{name}: harden-runner is not the exact pinned step")
        if sha(first.get("run", "")) != VALIDATOR_SHA256:
            bad.append(f"{name}: the validator script differs from its pinned SHA-256; {PIN_HINT}")
        if sha(step.get("run", "")) != GUARD_SHA256:
            bad.append(f"{name}: the guard script differs from its pinned SHA-256; {PIN_HINT}")
        if "if" in step:
            bad.append(f"{name}: the guard has an `if`")
        if step.get("continue-on-error") not in (None, False):
            bad.append(f"{name}: the guard has continue-on-error")
        if step.get("shell") != "bash":
            bad.append(f"{name}: the guard shell is not exactly bash")
        if set(step) != {"name", "timeout-minutes", "shell", "env", "run"}:
            bad.append(f"{name}: the guard step has unexpected keys")
        if "shell" in (job.get("defaults") or {}).get("run", {}) or "shell" in (doc.get("defaults") or {}).get(
            "run", {}
        ):
            bad.append(f"{name}: a defaults.run.shell override")
        if step.get("env") != GUARD_ENV:
            bad.append(f"{name}: the guard env is not exactly its inputs")
        if doc.get("env"):
            bad.append(f"{name}: the workflow sets env")
        if job.get("env") and (file is None or job.get("env") != JOB_SCHEDULING[(file, name)].get("env")):
            bad.append(f"{name}: the job sets env that is not the known value")
    return bad


def guard_script(doc: dict) -> str:
    return next(s for s in next(iter(doc["jobs"].values()))["steps"] if s.get("name") == GUARD)["run"]


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_every_job_has_the_guard_third_and_identical(name):
    doc = load(name)
    assert guard_problems(doc, name) == []
    scripts = {j["steps"][[s.get("name") for s in j["steps"]].index(GUARD)]["run"] for j in doc["jobs"].values()}
    assert len(scripts) == 1


def mutations(doc: dict, victim: str):
    """(label, mutated copy) pairs, each of which stops the guard from refusing in `victim`."""

    def fresh():
        d = copy.deepcopy(doc)
        return d, d["jobs"][victim], d["jobs"][victim]["steps"]

    def guard(steps):
        return next(s for s in steps if s.get("name") == GUARD)

    d, job, steps = fresh()
    job["steps"] = [s for s in steps if s.get("name") != GUARD]
    yield "guard removed", d
    for key, value in (("if", False), ("continue-on-error", True), ("shell", "bash {0} || true"), ("shell", "sh")):
        d, job, steps = fresh()
        guard(steps)[key] = value
        yield f"guard {key}={value}", d
    d, job, steps = fresh()
    del guard(steps)["shell"]
    yield "guard shell removed", d
    d, job, steps = fresh()
    job["continue-on-error"] = True
    yield "job continue-on-error", d
    for where in ("job", "workflow"):
        d, job, steps = fresh()
        (job if where == "job" else d)["defaults"] = {"run": {"shell": "sh"}}
        yield f"{where} defaults.run.shell", d
    # inherited environment: any key at all, an exported bash function included, on the step, job or workflow
    for var in ("BASH_FUNC_exit%%", "BASH_ENV", "SHELLOPTS", "PS4", "SOMETHING_NEW"):
        for where in ("step", "job", "workflow"):
            d, job, steps = fresh()
            value = "() { return 0; }" if var.startswith("BASH_FUNC_") else "/dev/null"
            if where == "step":
                guard(steps)["env"][var] = value
            elif where == "job":
                job["env"] = {**job.get("env", {}), var: value}
            else:
                d["env"] = {var: value}
            yield f"{where} env {var}", d
    # the validator and harden-runner come first and the guard is the third step: each is pinned exactly
    d, job, steps = fresh()
    steps[0]["run"] = "echo attacker-controlled"
    yield "validator replaced", d
    d, job, steps = fresh()
    steps[0]["run"] = steps[0]["run"] + "\ntrue"
    yield "validator extended", d
    d, job, steps = fresh()
    steps[1]["uses"] = "attacker/harden-runner-backdoor@main"
    yield "harden-runner replaced", d
    d, job, steps = fresh()
    steps[1]["uses"] = steps[1]["uses"].replace("@46b0", "@0000")
    yield "harden-runner repinned", d
    d, job, steps = fresh()
    steps.insert(0, {"name": "extra", "run": "echo before the validator"})
    yield "extra first step", d
    d, job, steps = fresh()
    steps.insert(1, {"name": "extra", "run": "echo between the validator and harden-runner"})
    yield "extra step between the validator and harden-runner", d
    d, job, steps = fresh()
    steps.insert(2, {"name": "extra", "run": "echo between harden-runner and the guard"})
    yield "extra step between harden-runner and the guard", d
    d, job, steps = fresh()
    steps[:] = [steps[2], steps[0], steps[1]] + steps[3:]
    yield "guard moved to first", d
    d, job, steps = fresh()
    steps[:] = [steps[0], steps[2], steps[1]] + steps[3:]
    yield "guard before harden-runner", d
    d, job, steps = fresh()
    steps[:] = [steps[1], steps[0]] + steps[2:]
    yield "harden-runner before the validator", d
    # the validator's environment is exactly the expected mapping: one variable or all of them missing is caught
    d, job, steps = fresh()
    env = steps[0]["env"]
    del env[next(iter(env))]
    yield "validator env variable deleted", d
    d, job, steps = fresh()
    steps[0]["env"] = {}
    yield "validator env emptied", d
    d, job, steps = fresh()
    del steps[0]["env"]
    yield "validator env removed", d
    # harden-runner keeps disable-sudo: true (the one documented exception has no such key to remove)
    d, job, steps = fresh()
    if "disable-sudo" in steps[1]["with"]:
        del steps[1]["with"]["disable-sudo"]
        yield "harden-runner disable-sudo removed", d
    d, job, steps = fresh()
    if "disable-sudo" in steps[1]["with"]:
        steps[1]["with"]["disable-sudo"] = False
        yield "harden-runner disable-sudo false", d
    # scheduling: the job may not be skipped or emptied
    d, job, steps = fresh()
    job["if"] = False
    yield "job if false", d
    d, job, steps = fresh()
    job["if"] = "${{ cancelled() }}"
    yield "job if cancelled", d
    d, job, steps = fresh()
    job["strategy"] = {"matrix": {"include": []}}
    yield "empty matrix", d
    d, job, steps = fresh()
    job["needs"] = "advanced-security-check"
    yield "new needs", d
    d, job, steps = fresh()
    job["container"] = "alpine"
    yield "container", d


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_every_way_of_neutering_the_guard_is_caught_in_every_job(name):
    doc = load(name)
    assert guard_problems(doc, name) == []
    seen = 0
    for victim in doc["jobs"]:
        for label, mutated in mutations(doc, victim):
            seen += 1
            assert guard_problems(mutated, name), (victim, label)
    assert seen >= 35 * len(doc["jobs"])


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


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_a_synchronized_backdoor_in_the_action_and_every_copy_is_caught(name):
    doc = load(name)
    assert guard_problems(doc, name) == []
    bad_action = "id >/dev/null\n" + check_script()
    for victim in doc["jobs"]:
        mutated = copy.deepcopy(doc)
        for job in mutated["jobs"].values():
            job["steps"][0]["run"] = bad_action
        problems = guard_problems(mutated, name, action_script=bad_action)
        assert any("pinned SHA-256" in x and "validator" in x for x in problems), victim
        mutated = copy.deepcopy(doc)
        guard = next(s for s in mutated["jobs"][victim]["steps"] if s.get("name") == GUARD)
        guard["run"] = "id >/dev/null\n" + guard["run"]
        assert any("guard script differs" in x for x in guard_problems(mutated, name)), victim


def test_the_pins_match_the_files_today():
    assert sha(check_script()) == VALIDATOR_SHA256, PIN_HINT
    assert sha(guard_script(load("security.yml"))) == GUARD_SHA256, PIN_HINT


# ---- Bash 3.2 compatibility of the inlined scripts (GitHub macOS runners run `shell: bash` as Bash 3.2) ----
BASH4_ONLY = (",,", "^^", ";;&", ";&", "declare -A", "mapfile", "readarray", "[[ -v", "${!", "&>>", "|&", "coproc")


def bash4_constructs(script: str) -> list[str]:
    found = []
    for token in BASH4_ONLY:
        if token in script:
            found.append(token)
            if token == ";;&":
                script = script.replace(";;&", "")  # so ";&" is not double-counted
    return found


def every_guard_and_validator_script():
    for name in DEFAULTS:
        for job_name, job in load(name)["jobs"].items():
            for step in job["steps"]:
                if step.get("name") in (GUARD, VALIDATOR):
                    yield f"{name}:{job_name}:{step['name']}", step["run"]
    yield "action:validator", check_script()


def test_guard_and_validator_scripts_use_no_bash4_only_construct():
    scripts = list(every_guard_and_validator_script())
    assert len(scripts) >= 90
    assert [(label, bash4_constructs(s)) for label, s in scripts if bash4_constructs(s)] == []


@pytest.mark.parametrize("token", BASH4_ONLY)
def test_a_bash4_only_construct_in_the_guard_is_flagged(token):
    script = guard_script(load("security.yml"))
    assert bash4_constructs(script) == []
    assert bash4_constructs(script + "\n" + token + "\n") == [token]
    assert bash4_constructs(script.replace('lower "$RUNNER_ENV"', "x=${RUNNER_ENV,,}", 1)) == [",,"]


def test_the_case_terminators_are_checked_longest_first_and_each_is_flagged():
    # ";;&" contains ";&" as a substring, so ";;&" is listed (and checked) before ";&".
    assert BASH4_ONLY.index(";;&") < BASH4_ONLY.index(";&")
    base = "case x in a) echo a ;; esac\n"
    assert bash4_constructs(base) == []
    assert bash4_constructs("case x in a) echo a ;;& b) echo b ;; esac\n") == [";;&"]
    assert bash4_constructs("case x in a) echo a ;& b) echo b ;; esac\n") == [";&"]


# Note on lower(): the guard lowercases with `tr`, which matches Bash 4 ${x,,} for ASCII
# values. That is all a GitHub repository name, event name, runner environment or boolean
# can contain. For exotic non-ASCII input it can differ, and it fails closed.


# ---- duplicate mapping keys: PyYAML keeps the last one silently ----
class StrictLoader(yaml.SafeLoader):
    pass


def _no_duplicate_keys(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in seen:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys)


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_no_workflow_has_a_duplicate_mapping_key(name):
    yaml.load((WORKFLOWS / name).read_text(), Loader=StrictLoader)


@pytest.mark.parametrize("name", sorted(DEFAULTS))
def test_a_duplicated_key_is_flagged(name):
    text = (WORKFLOWS / name).read_text()
    marker = "          disable-sudo: true\n"
    assert marker in text
    mutated = text.replace(marker, marker + marker, 1)
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        yaml.load(mutated, Loader=StrictLoader)
