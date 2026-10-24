"""threat-model.yml: the structure the workflow promises and the script it carries.

The general rules (pinning, permissions, harden-runner, injection, documented
inputs) are held for every reusable workflow in test_workflows.py. This file
runs the embedded validator, the exact text that ships, against models and git
repositories built on the spot, because a check nobody has seen go red is not
known to go red.
"""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "threat-model.yml"
DOC = yaml.safe_load(WORKFLOW.read_text())
INPUTS = (DOC.get("on") or DOC.get(True))["workflow_call"]["inputs"]
STEP = next(s for s in DOC["jobs"]["check"]["steps"] if s.get("name") == "Check the threat model")
SCRIPT = textwrap.dedent(re.search(r"<<'PY'\n(.*?)\n\s*PY\s*$", STEP["run"], re.S).group(1))


def threat(tid="t1", number=1, **over):
    base = {
        "id": tid,
        "number": number,
        "status": "Mitigated",
        "severity": "High",
        "title": "Prompt injection through a fetched page",
        "type": "Tampering",
        "description": "Untrusted text reaches the model as instructions.",
        "mitigation": "Fetched text is wrapped as data and never reaches a tool call unreviewed.",
    }
    base.update(over)
    return base


def cell(cid, shape="process", threats=None, **extra):
    data = {"name": cid, "threats": threats or []}
    return {"id": cid, "shape": shape, "data": data, **extra}


def good_model():
    cells = [
        cell("user", "actor"),
        cell("agent", "process", [threat()]),
        cell("store", "store"),
        cell("f1", "flow", source={"cell": "user"}, target={"cell": "agent"}),
        cell("f2", "flow", source={"cell": "agent"}, target={"cell": "store"}),
        {"id": "b1", "shape": "trust-boundary-box", "data": {"name": "model boundary"}},
    ]
    return {
        "version": "2.6.2",
        "summary": {"title": "Assistant"},
        "detail": {
            "diagrams": [{"id": 0, "title": "Main", "diagramType": "STRIDE", "cells": cells}],
            "threatTop": 1,
        },
    }


def env_for(**over):
    env = {
        "MODEL_GLOB": "docs/threat-model/*.threat-dragon.json",
        "REQUIRE_MODEL": "true",
        "AI_PATHS": "",
        "REQUIRED_TOPICS": "",
        "FAIL_ON_OPEN": "none",
        "EVENT_NAME": "push",
        "BASE_REF": "",
        "PR_BODY": "",
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/"),
    }
    env.update(over)
    return env


def run(cwd: Path, **over):
    return subprocess.run(
        [sys.executable, "-I", "-c", SCRIPT], cwd=cwd, env=env_for(**over), capture_output=True, text=True, check=False
    )


def write_model(root: Path, model: dict, name="app.threat-dragon.json"):
    folder = root / "docs" / "threat-model"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(json.dumps(model))


@pytest.fixture
def repo(tmp_path):
    write_model(tmp_path, good_model())
    return tmp_path


# --- the workflow's shape ---------------------------------------------------


def test_one_job_with_a_least_privilege_token():
    assert list(DOC["jobs"]) == ["check"]
    assert DOC["jobs"]["check"]["permissions"] == {"contents": "read"}
    assert DOC["permissions"] == {"contents": "read"}


def test_it_checks_out_history_and_keeps_no_credentials():
    checkout = next(s for s in DOC["jobs"]["check"]["steps"] if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}


def test_defaults_are_a_working_call_with_no_inputs():
    assert INPUTS["require-model"]["default"] is True
    assert INPUTS["ai-paths"]["default"] == "", "a path rule is the caller's to name"
    assert INPUTS["required-topics"]["default"] == ""
    assert INPUTS["fail-on-open-severity"]["default"] == "none"
    assert INPUTS["model-glob"]["default"].endswith(".threat-dragon.json")


def test_every_caller_value_reaches_the_script_through_the_environment():
    assert "${{" not in STEP["run"]
    for name in ("PR_BODY", "AI_PATHS", "MODEL_GLOB", "BASE_REF"):
        assert name in STEP["env"]


# --- the model --------------------------------------------------------------


def test_a_valid_model_passes(repo):
    out = run(repo)
    assert out.returncode == 0, out.stdout
    assert "threat model ok: 1 file(s), 1 threat(s)" in out.stdout


def mutate(fn):
    def apply(model):
        model = copy.deepcopy(model)
        fn(model)
        return model

    return apply


def cells_of(model):
    return model["detail"]["diagrams"][0]["cells"]


DEFECTS = {
    "version": (mutate(lambda m: m.update(version="1.0")), "not a Threat Dragon v2 model"),
    "no title": (mutate(lambda m: m["summary"].update(title="")), "summary.title"),
    "no diagrams": (mutate(lambda m: m["detail"].update(diagrams=[])), "detail.diagrams"),
    "duplicate cell": (mutate(lambda m: cells_of(m).append(cell("user", "actor"))), "duplicate cell id 'user'"),
    "dangling flow": (
        mutate(lambda m: cells_of(m).append(cell("f3", "flow", source={"cell": "user"}, target={"cell": "ghost"}))),
        "target 'ghost'",
    ),
    "no boundary": (
        mutate(lambda m: cells_of(m).__setitem__(slice(None), [c for c in cells_of(m) if c["id"] != "b1"])),
        "no trust boundary",
    ),
    "no flow": (
        mutate(lambda m: cells_of(m).__setitem__(slice(None), [c for c in cells_of(m) if c["shape"] != "flow"])),
        "no data flow",
    ),
    "no threats": (mutate(lambda m: cells_of(m)[1]["data"].update(threats=[])), "records no threat"),
    "bad status": (mutate(lambda m: cells_of(m)[1]["data"]["threats"][0].update(status="Done")), "status 'Done'"),
    "bad severity": (mutate(lambda m: cells_of(m)[1]["data"]["threats"][0].update(severity="Huge")), "severity 'Huge'"),
    "tbd severity": (mutate(lambda m: cells_of(m)[1]["data"]["threats"][0].update(severity="TBD")), "severity TBD"),
    "mitigated without text": (
        mutate(lambda m: cells_of(m)[1]["data"]["threats"][0].update(mitigation=" ")),
        "Mitigated with no mitigation",
    ),
    "no threat title": (mutate(lambda m: cells_of(m)[1]["data"]["threats"][0].update(title="")), "has no title"),
    "duplicate threat id": (
        mutate(lambda m: cells_of(m)[0]["data"].update(threats=[threat(tid="t1", number=2)])),
        "duplicate id 't1'",
    ),
    "duplicate number": (
        mutate(lambda m: cells_of(m)[0]["data"].update(threats=[threat(tid="t2", number=1)])),
        "threat numbers are not unique",
    ),
    "stale threatTop": (mutate(lambda m: m["detail"].update(threatTop=0)), "threatTop"),
}


@pytest.mark.parametrize("name", DEFECTS)
def test_each_defect_fails_and_names_itself(repo, name):
    fix, expected = DEFECTS[name]
    write_model(repo, fix(good_model()))
    out = run(repo)
    assert out.returncode == 1, out.stdout
    assert expected in out.stdout
    assert "::error file=docs/threat-model/app.threat-dragon.json,title=Threat model::" in out.stdout


def test_an_unmitigated_or_not_applicable_threat_needs_no_mitigation_text(repo):
    model = good_model()
    cells_of(model)[1]["data"]["threats"] = [
        threat("t1", 1, status="Open", mitigation=""),
        threat("t2", 2, status="NotApplicable", mitigation="", severity="TBD"),
    ]
    model["detail"]["threatTop"] = 2
    write_model(repo, model)
    assert run(repo).returncode == 0


@pytest.mark.parametrize("body", ["", "[1, 2]", "not json at all", "{"])
def test_a_file_that_is_not_a_model_fails_cleanly(repo, body):
    (repo / "docs" / "threat-model" / "app.threat-dragon.json").write_text(body)
    out = run(repo)
    assert out.returncode == 1
    assert "Traceback" not in out.stderr


def test_a_missing_model_fails_unless_it_is_not_required(tmp_path):
    out = run(tmp_path)
    assert out.returncode == 1 and "no threat model found" in out.stdout
    assert run(tmp_path, REQUIRE_MODEL="false").returncode == 0


def test_every_matching_file_is_checked(repo):
    broken = good_model()
    broken["summary"]["title"] = ""
    write_model(repo, broken, "second.threat-dragon.json")
    out = run(repo)
    assert out.returncode == 1 and "second.threat-dragon.json" in out.stdout


def test_a_double_star_glob_reaches_nested_models(tmp_path):
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    (nested / "m.threat-dragon.json").write_text(json.dumps(good_model()))
    out = run(tmp_path, MODEL_GLOB="**/*.threat-dragon.json")
    assert out.returncode == 0 and "1 file(s)" in out.stdout


def test_a_model_value_cannot_inject_a_workflow_command(repo):
    model = good_model()
    model["summary"]["title"] = ""
    cells_of(model)[1]["data"]["threats"][0]["status"] = "x\n::set-output name=a::b%0A"
    write_model(repo, model)
    out = run(repo)
    assert out.returncode == 1
    assert all(not line.startswith("::set-output") for line in out.stdout.splitlines())
    assert "%250A" in out.stdout


def test_a_file_name_cannot_inject_a_property_or_a_command(tmp_path):
    folder = tmp_path / "docs" / "threat-model"
    folder.mkdir(parents=True)
    hostile = "a,title=x::error b%.threat-dragon.json"
    (folder / hostile).write_text("{")
    out = run(tmp_path)
    assert out.returncode == 1
    annotated = [line for line in out.stdout.splitlines() if line.startswith("::error file=")]
    assert annotated, out.stdout
    prefix = annotated[0].split(",title=Threat model::")[0]
    assert "," not in prefix.removeprefix("::error file=") and "::" not in prefix.removeprefix("::error ")
    assert "a%2Ctitle=x%3A%3Aerror b%25.threat-dragon.json" in prefix


# --- topics and the open-threat bar -----------------------------------------


def test_required_topics_must_each_appear_in_some_threat(repo):
    assert run(repo, REQUIRED_TOPICS="prompt injection, tampering").returncode == 0
    out = run(repo, REQUIRED_TOPICS="prompt injection, data leakage")
    assert out.returncode == 1 and "'data leakage'" in out.stdout


def test_topics_are_not_checked_when_there_is_no_model(tmp_path):
    out = run(tmp_path, REQUIRE_MODEL="false", REQUIRED_TOPICS="data leakage")
    assert out.returncode == 0


@pytest.mark.parametrize(
    ("bar", "severity", "status", "fails"),
    [
        ("none", "High", "Open", False),
        ("High", "High", "Open", True),
        ("High", "Medium", "Open", False),
        ("Medium", "High", "Open", True),
        ("Low", "Low", "Open", True),
        ("High", "High", "Mitigated", False),
        ("High", "High", "NotApplicable", False),
    ],
)
def test_the_open_threat_bar(repo, bar, severity, status, fails):
    model = good_model()
    cells_of(model)[1]["data"]["threats"] = [threat(severity=severity, status=status)]
    write_model(repo, model)
    assert (run(repo, FAIL_ON_OPEN=bar).returncode == 1) is fails


def test_an_unknown_bar_is_an_error_not_a_pass(repo):
    out = run(repo, FAIL_ON_OPEN="Severe")
    assert out.returncode == 1 and "not High, Medium, Low or none" in out.stdout


# --- the pull request rule --------------------------------------------------


def git(cwd, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def pr_repo(repo):
    """A repository whose `origin/main` is the base and whose HEAD is a branch off it."""
    git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("x\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    git(repo, "checkout", "-q", "-b", "topic")
    return repo


def change(repo, path, text="changed\n"):
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", f"touch {path}")


def pr(repo, body="", paths="prompts/** **/mcp*.json agents.yaml"):
    return run(repo, EVENT_NAME="pull_request", BASE_REF="main", AI_PATHS=paths, PR_BODY=body)


def test_a_change_outside_the_ai_surface_passes(pr_repo):
    change(pr_repo, "docs/readme.md")
    assert pr(pr_repo).returncode == 0


def test_an_ai_change_with_no_model_change_and_no_note_fails(pr_repo):
    change(pr_repo, "prompts/system.md")
    out = pr(pr_repo)
    assert out.returncode == 1
    assert "prompts/system.md" in out.stdout and "threat-model: n/a - <reason>" in out.stdout


def test_a_model_change_in_the_same_pull_request_satisfies_the_rule(pr_repo):
    change(pr_repo, "prompts/system.md")
    model = good_model()
    model["summary"]["title"] = "Assistant, second pass"
    write_model(pr_repo, model)
    git(pr_repo, "add", "-A")
    git(pr_repo, "commit", "-q", "-m", "model")
    out = pr(pr_repo)
    assert out.returncode == 0 and "model updated" in out.stdout


@pytest.mark.parametrize(
    "body",
    [
        "threat-model: n/a - typo fix in a comment only",
        "Some text\n\nthreat-model: n/a – renamed a file, no behavior change\n\nmore",
        "  Threat-Model: N/A - reviewed, nothing new crosses a boundary",
    ],
)
def test_a_stated_reason_satisfies_the_rule(pr_repo, body):
    change(pr_repo, "tools/mcp.json")
    out = pr(pr_repo, body)
    assert out.returncode == 0 and "n/a recorded" in out.stdout


@pytest.mark.parametrize(
    "body",
    [
        "",
        "threat-model: n/a",
        "threat-model: n/a - ",
        "threat-model: n/a - ok",
        "see threat-model: n/a - because I said so, trust me",
    ],
)
def test_a_bare_or_buried_note_does_not(pr_repo, body):
    change(pr_repo, "agents.yaml")
    assert pr(pr_repo, body).returncode == 1


@pytest.mark.parametrize("name", ["prompts/caf\u00e9 prompt.md", 'prompts/say "hi".md', "prompts/\u65e5\u672c.md"])
def test_a_file_name_git_would_quote_still_matches_the_ai_paths(pr_repo, name):
    change(pr_repo, name)
    out = pr(pr_repo)
    assert out.returncode == 1 and "changes the AI surface" in out.stdout


def test_the_rule_applies_only_to_pull_requests(pr_repo):
    change(pr_repo, "prompts/system.md")
    out = run(pr_repo, EVENT_NAME="push", AI_PATHS="prompts/**")
    assert out.returncode == 0


def test_an_empty_ai_paths_turns_the_rule_off(pr_repo):
    change(pr_repo, "prompts/system.md")
    assert pr(pr_repo, paths="").returncode == 0


def test_an_unresolvable_base_fails_instead_of_passing(pr_repo):
    change(pr_repo, "prompts/system.md")
    out = run(pr_repo, EVENT_NAME="pull_request", BASE_REF="nope", AI_PATHS="prompts/**")
    assert out.returncode == 1 and "cannot diff" in out.stdout


# --- the reference model ----------------------------------------------------


def test_the_fixture_model_passes_the_check():
    out = run(REPO / "fixture", MODEL_GLOB="threat-model/*.threat-dragon.json", REQUIRED_TOPICS="prompt injection")
    assert out.returncode == 0, out.stdout
