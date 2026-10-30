"""security.yml `advanced-security`: a private repository without GitHub Advanced Security (issue #248).

The decision is one GitHub expression, used verbatim in job- and step-level `if`s, so these tests evaluate that
expression for every combination rather than trusting its text. Dependency review and CodeQL are skipped when it is
off; Semgrep and gitleaks still run and still fail on a finding but do not upload SARIF. Anything unrecognized runs
everything and fails the job: a typo must never read as "off".
"""

from __future__ import annotations

import ast
import itertools
import os
import re
import subprocess

import pytest
from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

DOC = load(WORKFLOWS / "security.yml")
INPUTS = triggers(DOC)["workflow_call"]["inputs"]
JOBS = jobs(DOC)
ON = (
    "inputs.advanced-security != 'false' && "
    "(inputs.advanced-security != 'auto' || github.event.repository.private != true)"
)
VALIDATE = "Validate the advanced-security input"
NOTE = "Note the skipped Advanced Security features"


class Text(str):
    """GitHub compares strings case-insensitively."""

    def __eq__(self, other):
        return isinstance(other, str) and self.lower() == other.lower()

    def __ne__(self, other):
        return not self == other

    __hash__ = str.__hash__


def evaluate(expression: str, mode: str, private, **extra) -> bool:
    """The forms the expression uses: inputs.X, the repository flag, ==, !=, &&, ||, parentheses, true/false."""
    py = expression.replace("&&", " and ").replace("||", " or ")
    py = py.replace("inputs.advanced-security", "ADV").replace("github.event.repository.private", "PRIVATE")
    py = re.sub(r"\binputs\.([\w-]+)", lambda m: "IN_" + m.group(1).replace("-", "_"), py)
    py = re.sub(r"\btrue\b", "True", py)
    names = {"ADV": Text(mode), "PRIVATE": private, "__builtins__": {}}
    names.update({"IN_" + k.replace("-", "_"): v for k, v in extra.items()})
    tree = ast.parse(py.strip(), mode="eval")
    for node in ast.walk(tree):
        assert isinstance(
            node,
            (
                ast.Expression,
                ast.BoolOp,
                ast.Compare,
                ast.Name,
                ast.Constant,
                ast.And,
                ast.Or,
                ast.Eq,
                ast.NotEq,
                ast.Load,
            ),
        ), f"unsupported expression form: {ast.dump(node)}"
    return bool(eval(compile(tree, "<expr>", "eval"), names))  # the AST above admits only the whitelisted node types


def step(job: str, name: str) -> dict:
    return next(s for s in steps_of(JOBS[job]) if s.get("name") == name)


def uploads(job: str) -> list[dict]:
    return [s for s in steps_of(JOBS[job]) if "upload-sarif" in str(s.get("uses", ""))]


def test_the_input_is_documented_with_a_neutral_default():
    spec = INPUTS["advanced-security"]
    assert spec["type"] == "string" and spec["default"] == "auto"
    for word in ("auto", "true", "false"):
        assert word in spec["description"]


MODES = ["auto", "true", "false"]
PRIVACY = [True, False, None]


@pytest.mark.parametrize(("mode", "private"), list(itertools.product(MODES, PRIVACY)))
def test_the_decision_for_each_mode_and_visibility(mode, private):
    expected = {"true": True, "false": False, "auto": private is not True}[mode]
    assert evaluate(ON, mode, private) is expected


def test_the_four_headline_cases():
    assert evaluate(ON, "auto", False) is True  # public, auto: as today
    assert evaluate(ON, "auto", True) is False  # private, auto: off
    assert evaluate(ON, "true", True) is True  # private, caller says true: as today
    assert evaluate(ON, "false", False) is False  # public, caller says false: off


@pytest.mark.parametrize("bad", ["", "yes", "no", "0", "off", "autom", "true ", " false", "false;true", "null"])
@pytest.mark.parametrize("private", PRIVACY)
def test_an_invalid_value_never_reads_as_off(bad, private):
    assert evaluate(ON, bad, private) is True, "the expression must keep every scan running on a value it does not know"


@pytest.mark.parametrize("job", ["codeql", "dependency-review", "gitleaks", "semgrep"])
def test_the_validate_step_comes_after_harden_runner_and_fails_closed(job):
    names = [s.get("name") for s in steps_of(JOBS[job])]
    assert VALIDATE in names
    first = steps_of(JOBS[job])[0]
    assert str(first.get("uses", "")).startswith("step-security/harden-runner@") or first["name"].startswith(
        "Validate the egress"
    )
    assert names.index(VALIDATE) < next(
        i for i, s in enumerate(steps_of(JOBS[job])) if "checkout" in str(s.get("uses", ""))
    )
    s = step(job, VALIDATE)
    assert "if" not in s, "the validation runs whenever the job does"
    assert "inputs." not in s["run"], "inputs reach the script through env, never interpolated"
    assert s["env"]["ADVANCED_SECURITY"] == "${{ inputs.advanced-security }}"


def run_validate(value: str | None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("ADVANCED_")}
    if value is not None:
        env["ADVANCED_SECURITY"] = value
    script = step("gitleaks", VALIDATE)["run"]
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script], capture_output=True, text=True, env=env, timeout=20
    )


@pytest.mark.parametrize("good", MODES)
def test_the_validate_script_accepts_the_three_values(good):
    done = run_validate(good)
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("bad", ["", "True", "FALSE", "yes", "off", "autom", "true ", "false;true", "$(id)", None])
def test_the_validate_script_rejects_anything_else_with_a_clear_error(bad):
    done = run_validate(bad)
    assert done.returncode == 1, "an invalid value must fail the job, not pass it"
    assert "::error" in done.stdout and "advanced-security" in done.stdout
    assert "auto" in done.stdout and "true" in done.stdout and "false" in done.stdout
    assert "uid=" not in done.stdout + done.stderr, "the value is data, never executed"


def test_the_validate_scripts_are_identical_in_every_job():
    scripts = {step(j, VALIDATE)["run"] for j in ("codeql", "dependency-review", "gitleaks", "semgrep")}
    assert len(scripts) == 1


def test_codeql_and_dependency_review_are_skipped_not_failed():
    assert JOBS["codeql"]["if"] == f"inputs.codeql && ({ON})"
    assert (
        JOBS["dependency-review"]["if"] == f"inputs.dependency-review && github.event_name == 'pull_request' && ({ON})"
    )
    for mode, private in itertools.product(MODES, PRIVACY):
        on = evaluate(ON, mode, private)
        assert evaluate(JOBS["codeql"]["if"], mode, private, codeql=True) is on
        assert evaluate(JOBS["codeql"]["if"], mode, private, codeql=False) is False


def test_semgrep_and_gitleaks_still_run_and_still_fail_on_a_finding():
    assert JOBS["semgrep"]["if"] == "inputs.semgrep" and JOBS["gitleaks"]["if"] == "inputs.gitleaks"
    scan = step("gitleaks", "Scan the full history (gitleaks)")
    assert "if" not in scan and "--exit-code 1" in scan["run"]
    semgrep = step("semgrep", "Scan (Semgrep)")
    assert "if" not in semgrep and "--error" in semgrep["run"]


def test_the_sarif_uploads_follow_the_decision_and_keep_their_other_conditions():
    (gitleaks,) = uploads("gitleaks")
    (semgrep,) = uploads("semgrep")
    assert ON in gitleaks["if"] and "inputs.gitleaks-upload-sarif" in gitleaks["if"]
    assert "always()" in gitleaks["if"] and "hashFiles('gitleaks.sarif')" in gitleaks["if"]
    assert ON in semgrep["if"] and "always()" in semgrep["if"] and "hashFiles('semgrep.sarif')" in semgrep["if"]
    for mode, private in itertools.product(MODES, PRIVACY):
        on = evaluate(ON, mode, private)
        assert (
            evaluate(
                gitleaks["if"].replace("always() &&", "True &&").replace("hashFiles('gitleaks.sarif') != ''", "true"),
                mode,
                private,
                **{"gitleaks-upload-sarif": True},
            )
            is on
        )


def test_snyk_and_scorecard_uploads_are_unchanged():
    # Both are opt-in and a caller who turns them on has Advanced Security; the decision does not reach them.
    for job in ("snyk", "scorecard"):
        assert not any(ON in str(s.get("if", "")) for s in steps_of(JOBS[job]))


def run_note(mode: str, private: str, tmp_path):
    summary = tmp_path / "summary.md"
    summary.unlink(missing_ok=True)
    env = {**os.environ, "ADVANCED_SECURITY": mode, "REPOSITORY_PRIVATE": private, "GITHUB_STEP_SUMMARY": str(summary)}
    script = step("semgrep", NOTE)["run"]
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", script], capture_output=True, text=True, env=env, timeout=20
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return summary.read_text()


@pytest.mark.parametrize("job", ["gitleaks", "semgrep"])
def test_the_note_step_runs_only_when_the_features_are_off(job):
    s = step(job, NOTE)
    assert s["if"] == "${{ !(" + ON + ") }}"
    assert "inputs." not in s["run"]


def test_the_summary_says_what_was_skipped_why_and_how_to_turn_it_on(tmp_path):
    auto = run_note("auto", "true", tmp_path)
    assert "private repository" in auto
    for word in ("dependency review", "CodeQL", "SARIF", "advanced-security: true"):
        assert word.lower() in auto.lower()
    assert "Semgrep" in auto and "gitleaks" in auto and "still" in auto
    forced = run_note("false", "false", tmp_path)
    assert "advanced-security: false" in forced and "private repository" not in forced


def test_the_two_note_scripts_are_identical():
    assert step("gitleaks", NOTE)["run"] == step("semgrep", NOTE)["run"]
