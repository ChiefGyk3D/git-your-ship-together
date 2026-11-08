"""container-release.yml `skip-secret-scan-in-site-packages`: an opt-in allow rule for Trivy's SECRET scanner.

Why it exists: Trivy's `gcp-service-account` rule matches docstring text inside the installed `anthropic` SDK under
`<venv>/lib/python3.x/site-packages/`. The text is not a credential, the newest SDK version has it and no fixed
version exists. The input lets a caller stop the secret scanner reading that directory. The vulnerability scanner,
the severity, `ignore-unfixed` and the exit code are untouched, and nothing changes while the input is off.

Mechanism (Trivy secret scanning docs, "Allow Rules", read 2026-11-07, https://trivy.dev/docs/latest/guide/scanner/secret/):
a `trivy-secret.yaml` with a global `allow-rules` entry that has a `path` regex; the config path is passed with the
documented `--secret-config` flag, through its environment form TRIVY_SECRET_CONFIG. trivy-action v0.36.0 has no
input for it but does not clear the environment.

The structure checker is run on the real workflow and then on mutated copies, which it must refuse.
"""

from __future__ import annotations

import copy
import re

import pytest
import yaml
from test_container_release_digests import RELEASE, run_script, step
from test_workflows import jobs, load, steps_of, triggers

INPUT = "skip-secret-scan-in-site-packages"
ALLOW = "Let Trivy's secret scanner skip installed Python packages"
TRIVY = "Scan the image with Trivy"
JOBS = ("build", "build-local")
# The Trivy step as it is without the input: a change to it is a change for every caller.
TRIVY_WITH = {
    "image-ref": "release-candidate:local",
    "format": "sarif",
    "output": "trivy-results.sarif",
    "severity": "${{ inputs.trivy-severity }}",
    "exit-code": "${{ inputs.trivy-exit-code }}",
    "ignore-unfixed": "${{ inputs.trivy-ignore-unfixed }}",
    "trivyignores": "${{ inputs.trivyignores }}",
}
CONDITION = f"inputs.trivy && inputs.{INPUT}"
# Paths inside an image as Trivy reports them: no leading slash.
SKIPPED = [
    "opt/venv/lib/python3.14/site-packages/anthropic/types/x.py",
    "usr/local/lib/python3.12/site-packages/pkg/mod.py",
    "usr/lib64/python3.11/site-packages/pkg/mod.py",
]
SCANNED = [
    "app/config.py",
    "app/site-packages/keys.py",
    "etc/secrets/key.json",
    "usr/lib/python3/dist-packages/pkg/mod.py",
    "opt/venv/bin/activate",
    "home/user/site-packages.txt",
]


def run_text(doc: dict, job: str = "build") -> str:
    return step(job, ALLOW, doc)["run"]


def config_problems(text: str) -> list[str]:
    """Why a generated secret config is wider than the one allow rule it may contain."""
    cfg = yaml.safe_load(text)
    if not isinstance(cfg, dict) or set(cfg) != {"allow-rules"}:
        return [f"keys other than allow-rules: {sorted(cfg) if isinstance(cfg, dict) else cfg!r}"]
    rules = cfg["allow-rules"]
    if not isinstance(rules, list) or len(rules) != 1:
        return ["not exactly one allow rule"]
    rule = rules[0]
    if "regex" in rule or "path" not in rule:
        return ["the allow rule must be a path rule only"]
    problems = []
    for p in SKIPPED:
        if not re.search(rule["path"], p):
            problems.append(f"does not skip {p}")
    for p in SCANNED:
        if re.search(rule["path"], p):
            problems.append(f"skips {p}")
    return problems


def problems(doc: dict) -> list[str]:
    out: list[str] = []
    wc = triggers(doc)["workflow_call"]["inputs"].get(INPUT)
    if not wc or wc.get("type") != "boolean" or wc.get("default") is not False:
        out.append("input must be a boolean defaulting to false")
    if not wc or "Trivy" not in wc.get("description", "") or "vulnerab" not in wc.get("description", ""):
        out.append("description must state the reason and that the vulnerability scan stays on")
    for job in JOBS:
        names = [s.get("name") for s in steps_of(jobs(doc)[job])]
        if names.count(ALLOW) != 1 or names.count(TRIVY) != 1:
            out.append(f"{job}: allow step or Trivy step missing or duplicated")
            continue
        if names.index(ALLOW) + 1 != names.index(TRIVY):
            out.append(f"{job}: the allow step must sit directly before the Trivy step")
        s = step(job, ALLOW, doc)
        if s.get("if") != CONDITION:
            out.append(f"{job}: allow step condition is {s.get('if')!r}")
        if "uses" in s or s.get("shell", "bash") != "bash":
            out.append(f"{job}: allow step must be plain bash")
        if "${{" in s["run"]:
            out.append(f"{job}: no expression inside run")
        t = step(job, TRIVY, doc)
        if t.get("with") != TRIVY_WITH:
            out.append(f"{job}: the Trivy step's inputs changed: {t.get('with')}")
        if t.get("if") != "inputs.trivy" or set(t) - {"name", "if", "uses", "with"}:
            out.append(f"{job}: the Trivy step's condition or keys changed")
    if step("build", ALLOW, doc) != step("build-local", ALLOW, doc):
        out.append("the allow step differs between the jobs")
    if not out:
        for job in JOBS:
            text = re.search(r"cat > \"\$CONFIG\" <<'EOF'\n(.*?)\nEOF\n", run_text(doc, job), re.S)
            out += config_problems(text.group(1)) if text else ["no heredoc config"]
    return out


def test_the_real_workflow_passes_the_checker():
    assert problems(load(RELEASE)) == []


def test_the_default_leaves_the_trivy_step_exactly_as_it_was():
    for job in JOBS:
        t = step(job, TRIVY)
        assert t["with"] == TRIVY_WITH and t["if"] == "inputs.trivy"
        assert "env" not in t and "scanners" not in t["with"]
        assert not {"skip-dirs", "skip-files", "trivy-config"} & set(t["with"])


def test_the_input_is_a_boolean_defaulting_off():
    spec = triggers(load(RELEASE))["workflow_call"]["inputs"][INPUT]
    assert spec["type"] == "boolean" and spec["default"] is False


def test_both_jobs_carry_the_same_allow_step_before_the_trivy_step():
    assert step("build", ALLOW) == step("build-local", ALLOW)


def test_the_allow_step_writes_only_the_path_rule_and_exports_the_config_path(tmp_path):
    runner = tmp_path / "runner"
    runner.mkdir()
    genv = tmp_path / "github_env"
    genv.write_text("")
    code, _, out = run_script(run_text(load(RELEASE)), tmp_path, {"RUNNER_TEMP": str(runner), "GITHUB_ENV": str(genv)})
    assert code == 0, out
    lines = genv.read_text().splitlines()
    assert len(lines) == 1 and lines[0].startswith("TRIVY_SECRET_CONFIG=" + str(runner))
    cfg = (tmp_path / lines[0].split("=", 1)[1]).read_text()
    assert config_problems(cfg) == []
    assert "disable" not in cfg and "skip-patterns" not in cfg and "enable-builtin" not in cfg


def test_config_checker_refuses_a_wider_rule():
    good = "allow-rules:\n  - id: x\n    path: (^|/)lib(64)?/python[0-9.]+/site-packages/\n"
    assert config_problems(good) == []
    for bad in (
        "allow-rules:\n  - id: x\n    path: .*\n",
        "allow-rules:\n  - id: x\n    path: site-packages\n",
        good + "disable-rules:\n  - gcp-service-account\n",
        good + "skip-patterns: []\n",
        "allow-rules:\n  - id: x\n    regex: .*\n",
        "allow-rules:\n  - id: x\n    path: a\n  - id: y\n    path: b\n",
    ):
        assert config_problems(bad), bad


def mutate_each():
    def drop_condition(d):
        step("build", ALLOW, d).pop("if")

    def on_by_default(d):
        triggers(d)["workflow_call"]["inputs"][INPUT]["default"] = True

    def as_string(d):
        triggers(d)["workflow_call"]["inputs"][INPUT]["type"] = "string"

    def scanners(d):
        step("build", TRIVY, d)["with"]["scanners"] = "vuln"

    def skip_dirs(d):
        step("build-local", TRIVY, d)["with"]["skip-dirs"] = "opt/venv"

    def weaker_severity(d):
        step("build", TRIVY, d)["with"]["severity"] = "CRITICAL"

    def hard_ignore_unfixed(d):
        step("build-local", TRIVY, d)["with"]["ignore-unfixed"] = "true"

    def drift(d):
        step("build-local", ALLOW, d)["run"] += "\n# drift"

    def wide_path(d):
        for j in JOBS:
            s = step(j, ALLOW, d)
            s["run"] = s["run"].replace("(^|/)lib(64)?/python[0-9.]+/site-packages/", ".*")

    def wrong_order(d):
        lst = jobs(d)["build"]["steps"]
        i = next(n for n, s in enumerate(lst) if s.get("name") == ALLOW)
        lst[i], lst[i + 1] = lst[i + 1], lst[i]

    def expression(d):
        step("build", ALLOW, d)["run"] += "\necho ${{ github.head_ref }}"

    def env_on_trivy(d):
        step("build", TRIVY, d)["env"] = {"TRIVY_SECRET_CONFIG": "x"}

    return [
        drop_condition, on_by_default, as_string, scanners, skip_dirs, weaker_severity, hard_ignore_unfixed, drift,
        wide_path, wrong_order, expression, env_on_trivy,
    ]  # fmt: skip


@pytest.mark.parametrize("mutation", mutate_each(), ids=lambda f: f.__name__)
def test_each_mutation_is_refused_by_the_checker(mutation):
    doc = copy.deepcopy(load(RELEASE))
    mutation(doc)
    assert problems(doc), mutation.__name__
