"""python-fuzz.yml: the contract a caller relies on, and the run step itself, run for real.

The run step is lifted out of the workflow and executed with bash against tiny
Atheris targets, so what is asserted is what the job does, not what its YAML
looks like. Each assertion was broken on purpose once (the crash target made
to pass, the missing-directory check removed, a hash altered) to confirm it
goes red with a message naming the fix.

Atheris is in requirements-dev.txt and the tests need it: it publishes x86_64
wheels only, so a machine without one cannot run this file, and a skip would
hide the one check that proves a crash fails the job.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from test_workflows import README, REPO, WORKFLOWS, jobs, load, steps_of, triggers

WORKFLOW = WORKFLOWS / "python-fuzz.yml"
FIXTURE_TARGET_DIR = REPO / "fixture" / "fuzz"
PASS_DIR = REPO / "tests" / "fuzz_pass"
CRASH_DIR = REPO / "tests" / "fuzz_crash"
TIMEOUT_DIR = REPO / "tests" / "fuzz_timeout"

INPUTS = {
    "python-version": "3.14",
    "fuzz-dir": "fuzz",
    "target-glob": "fuzz_*.py",
    "seconds-per-target": 60,
    "timeout-per-input": 25,
    "max-len": 4096,
    "install-command": "pip install -e .",
    "runner": "ubuntu-24.04",
}


def fuzz_job() -> dict:
    return jobs(load(WORKFLOW))["fuzz"]


def step_named(fragment: str) -> dict:
    for step in steps_of(fuzz_job()):
        if fragment in str(step.get("name", "")):
            return step
    raise AssertionError(f"python-fuzz.yml has no step named like {fragment!r}")


# --- the contract -----------------------------------------------------------


def test_it_is_callable_and_takes_the_documented_inputs():
    doc = load(WORKFLOW)
    assert "workflow_call" in triggers(doc)
    declared = triggers(doc)["workflow_call"]["inputs"]
    for name, default in INPUTS.items():
        assert name in declared, f"input {name!r} is missing"
        assert declared[name]["default"] == default, f"{name} default is {declared[name]['default']!r}, not {default!r}"


def test_every_input_is_in_the_readme_table():
    readme = README.read_text()
    section = readme[readme.index("Inputs of `python-fuzz.yml`") :]
    for name in load(WORKFLOW).get(True, load(WORKFLOW).get("on"))["workflow_call"]["inputs"]:
        assert f"| `{name}` |" in section, f"README's python-fuzz.yml table does not list `{name}`"


def test_the_python_default_is_stated_with_its_reason():
    text = README.read_text()
    assert "Atheris 3.1.0" in text and "3.14" in text, "README must say which Python is the default and why"


def test_atheris_is_installed_hash_checked_and_binary_only():
    run = str(step_named("Install Atheris")["run"])
    assert "--require-hashes" in run, "Atheris must be installed under --require-hashes"
    assert "--only-binary=:all:" in run, "Atheris must never be built from source on the runner"
    env = str(step_named("Install Atheris")["env"]["REQUIREMENTS"])
    assert re.search(r"^atheris==\d+\.\d+\.\d+ ", env), "Atheris must be pinned to one exact version"
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", env)) >= 3, "one hash per published wheel (3.12, 3.13, 3.14)"


def test_the_workflow_pin_matches_the_one_this_repository_tests_with():
    """Two places name the Atheris version; they move together or the tests prove nothing about the workflow."""
    env = str(step_named("Install Atheris")["env"]["REQUIREMENTS"])
    version = re.search(r"atheris==(\S+)", env)[1]
    hashes = set(re.findall(r"sha256:([0-9a-f]{64})", env))
    assert f"atheris=={version}\n" in (REPO / "requirements-dev.in").read_text(), (
        f"requirements-dev.in does not pin atheris=={version}, the version python-fuzz.yml installs"
    )
    lock = (REPO / "requirements-dev.txt").read_text()
    assert f"atheris=={version} " in lock, "requirements-dev.txt does not lock the workflow's Atheris version"
    missing = {h for h in hashes if h not in lock}
    assert not missing, f"hashes in python-fuzz.yml but not in requirements-dev.txt: {sorted(missing)}"


def test_findings_are_uploaded_for_thirty_days_even_when_the_step_failed():
    upload = [s for s in steps_of(fuzz_job()) if str(s.get("uses", "")).startswith("actions/upload-artifact@")]
    assert len(upload) == 1
    step = upload[0]
    assert step["if"] == "always()", "a crash fails the run step; the upload must still happen"
    assert step["with"]["retention-days"] == 30
    for kind in ("crash", "leak", "timeout", "oom"):
        assert f"/{kind}-*" in step["with"]["path"], f"{kind}-* artefacts are not uploaded"


def test_the_job_holds_nothing_beyond_read_only_and_no_sudo():
    job = fuzz_job()
    assert job["permissions"] == {"contents": "read"}
    harden = steps_of(job)[0]
    assert harden["with"]["disable-sudo"] is True


def test_caller_values_never_reach_the_shell_by_template_expansion():
    for step in steps_of(fuzz_job()):
        assert "${{" not in str(step.get("run", "")), f"step {step.get('name')!r} expands a template into the script"


def test_the_fixture_ships_a_target_the_workflow_will_find():
    assert list(FIXTURE_TARGET_DIR.glob(INPUTS["target-glob"])), "fixture/fuzz has no target for ci.yml to run"


# --- the run step, executed -------------------------------------------------


def run_step(
    tmp_path: Path,
    fuzz_dir: Path | str,
    seconds: int = 3,
    glob: str = "fuzz_*.py",
    timeout_per_input: int = 25,
    process_timeout: int = 120,
):
    """Run python-fuzz.yml's run step under bash the way the job does, in a scratch directory."""
    assert importlib.util.find_spec("atheris"), (
        "atheris is not installed: pip install --require-hashes -r requirements-dev.txt"
    )
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    python = bindir / "python"
    if not python.exists():
        # A wrapper, not a symlink: a venv's interpreter finds its site-packages from the path it was started by.
        python.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
        python.chmod(0o755)
    summary = tmp_path / "summary.md"
    findings = tmp_path / "findings"
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "FUZZ_DIR": str(fuzz_dir),
        "TARGET_GLOB": glob,
        "SECONDS_PER_TARGET": str(seconds),
        "TIMEOUT_PER_INPUT": str(timeout_per_input),
        "MAX_LEN": "64",
        "FINDINGS": str(findings),
        "GITHUB_STEP_SUMMARY": str(summary),
    }
    done = subprocess.run(
        ["bash", "-c", str(step_named("Run the fuzz targets")["run"])],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=process_timeout,
    )
    return done, (summary.read_text() if summary.exists() else ""), findings


def test_a_missing_fuzz_dir_fails_and_names_the_fix(tmp_path):
    done, _, _ = run_step(tmp_path, tmp_path / "nowhere")
    assert done.returncode != 0
    assert "fuzz-dir" in done.stdout and "add" in done.stdout, done.stdout


def test_a_dir_with_no_matching_target_fails_and_names_the_fix(tmp_path):
    empty = tmp_path / "fuzz"
    empty.mkdir()
    (empty / "helper.py").write_text("x = 1\n")
    done, _, _ = run_step(tmp_path, empty)
    assert done.returncode != 0
    assert "target-glob" in done.stdout, done.stdout


def test_a_passing_target_passes_and_is_summarised(tmp_path):
    done, summary, _ = run_step(tmp_path, PASS_DIR)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "| `" in summary and "passed" in summary and "FAILED" not in summary, summary
    assert re.search(r"fuzz_ok\.py: passed, \d+ executions", done.stdout), done.stdout


def test_a_crashing_target_fails_the_step_and_leaves_its_input(tmp_path):
    done, summary, findings = run_step(tmp_path, CRASH_DIR)
    assert done.returncode != 0, "a crashing target did not fail the step: the job could never go red"
    assert "FAILED" in summary, summary
    assert list(findings.glob("*/crash-*")), f"no crash-* input saved under {findings}"


def test_a_timed_out_input_fails_the_step_and_leaves_its_input(tmp_path):
    done, summary, findings = run_step(
        tmp_path, TIMEOUT_DIR, seconds=5, timeout_per_input=1, process_timeout=20
    )
    assert done.returncode != 0, "a hanging input did not fail the step"
    assert "FAILED" in summary, summary
    assert list(findings.glob("*/timeout-*")), f"no timeout-* input saved under {findings}"


def test_one_failing_target_does_not_hide_the_others(tmp_path):
    both = tmp_path / "fuzz"
    both.mkdir()
    (both / "fuzz_a_ok.py").write_text((PASS_DIR / "fuzz_ok.py").read_text())
    (both / "fuzz_b_crash.py").write_text((CRASH_DIR / "fuzz_crash.py").read_text())
    done, summary, _ = run_step(tmp_path, both)
    assert done.returncode != 0
    assert "fuzz_a_ok.py` | passed" in summary and "fuzz_b_crash.py` | FAILED" in summary, summary


@pytest.mark.parametrize("name", ["fuzz_ok.py"])
def test_the_fixture_target_and_the_test_target_are_not_the_same_file(name):
    """tests/fuzz_pass is not a caller's directory: nothing but these tests may run it."""
    assert not (FIXTURE_TARGET_DIR / name).exists()
