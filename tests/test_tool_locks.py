"""Every `pip install` a workflow runs is hash-checked, and the tool locks security.yml carries are the files'.

Scorecard's PinnedDependencies check (issue #87) flags a `pip install` that is
not pinned by hash. These reusable workflows are pinned by commit by every
repository that calls them, so an unhashed install here runs unchecked code in
all of them. pip-audit and Semgrep are installed from locks that travel inside
security.yml (a reusable workflow cannot check out its own commit); the source
of each is `.github/requirements/<tool>.{in,txt}`, and scripts/tool_locks.py
copies one into the other.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys

import pytest
from test_workflows import ACTION_FILES, REPO, WORKFLOW_FILES, WORKFLOWS, jobs, load, steps_of

SCRIPT = REPO / "scripts" / "tool_locks.py"
REQS = REPO / ".github" / "requirements"
TOOLS = {"pip-audit": "Install pip-audit", "semgrep": "Install Semgrep"}
JOBS = {"pip-audit": "dependency-audit", "semgrep": "semgrep"}
# An install at the start of a command, not the words "pip install" inside a docstring or an echo.
PIP_INSTALL = re.compile(r"(?:^|[;&|(!]|\b(?:then|do|else|sudo))\s*(?:python3?\s+-m\s+)?pip3?\s+install\b")


def run_steps():
    """Every shell step of every workflow and composite action: (file, step name, run text without comment lines)."""
    for path in [*WORKFLOW_FILES, *ACTION_FILES]:
        doc = load(path)
        job_steps = [s for j in jobs(doc).values() for s in steps_of(j)] or steps_of(doc.get("runs") or {})
        for step in job_steps:
            if "run" in step:
                text = "\n".join(line for line in str(step["run"]).splitlines() if not line.lstrip().startswith("#"))
                yield path.name, step.get("name", "(unnamed)"), text


def pip_installs():
    for file, name, text in run_steps():
        # A command may continue on the next line with a backslash; join them so --require-hashes is seen.
        for command in re.sub(r"\\\n\s*", " ", text).splitlines():
            if PIP_INSTALL.search(command):
                yield file, name, command.strip()


def test_the_scan_finds_the_installs_this_test_governs():
    """A scan that matches nothing would pass for ever; these are the steps known to install from pip."""
    found = {(file, name) for file, name, _ in pip_installs()}
    for expected in (
        ("security.yml", "Install pip-audit"),
        ("security.yml", "Install Semgrep"),
        ("security.yml", "Install dependencies for Snyk Open Source"),
        ("python-fuzz.yml", "Install Atheris"),
        ("ci.yml", "Install test dependencies"),
    ):
        assert expected in found, f"{expected} no longer shows up as a pip install; update the scan or this list"


def test_no_workflow_runs_an_unhashed_pip_install():
    offenders = [
        f"{file} / {name}: {command}" for file, name, command in pip_installs() if "--require-hashes" not in command
    ]
    assert not offenders, (
        "pip install without --require-hashes (Scorecard PinnedDependencies, #87). Lock the package with "
        "scripts/tool_locks.py or `pip-compile --generate-hashes`:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize("tool", TOOLS)
def test_the_workflow_carries_the_lock_file_verbatim(tool):
    step = next(s for s in steps_of(jobs(load(WORKFLOWS / "security.yml"))[JOBS[tool]]) if s.get("name") == TOOLS[tool])
    assert step["env"]["REQUIREMENTS"] == (REQS / f"{tool}.txt").read_text(), (
        f"security.yml's {TOOLS[tool]!r} lock differs from .github/requirements/{tool}.txt; run scripts/tool_locks.py"
    )


def test_the_inline_script_check_agrees():
    result = subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("tool", TOOLS)
def test_the_install_is_hash_checked_binary_only_and_resolves_nothing(tool):
    job = JOBS[tool]
    step = next(s for s in steps_of(jobs(load(WORKFLOWS / "security.yml"))[job]) if s.get("name") == TOOLS[tool])
    run = step["run"]
    assert "--require-hashes" in run and "--no-deps" in run and "--only-binary=:all:" in run
    assert "inputs." not in run, "inputs reach the shell through env, never by expansion"
    assert "REQUESTED_VERSION" not in str(step["env"].get("REQUIREMENTS")), "the lock is the lock, not an input"


@pytest.mark.parametrize("tool", TOOLS)
def test_the_lock_pins_the_version_the_in_file_names_and_hashes_every_line(tool):
    wanted = (REQS / f"{tool}.in").read_text().strip()
    assert re.fullmatch(rf"{tool}==\d+(\.\d+)+", wanted), f"{tool}.in must be the one exact pin, got {wanted!r}"
    lock = (REQS / f"{tool}.txt").read_text()
    assert f"\n{wanted} \\\n" in "\n" + lock or lock.startswith(f"{wanted} \\\n"), f"{tool}.txt does not lock {wanted}"
    entries = re.split(r"\n(?=[A-Za-z0-9])", "\n".join(line for line in lock.splitlines() if not line.startswith("#")))
    assert len(entries) > 3, "the lock lists the dependency tree, not only the tool"
    for entry in entries:
        assert re.match(r"[A-Za-z0-9_.\-]+==\S+", entry), f"not a pin: {entry!r}"
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", entry), f"no hash: {entry.splitlines()[0]}"


def snyk_install_step():
    snyk = jobs(load(WORKFLOWS / "security.yml"))["snyk"]
    return next(s for s in steps_of(snyk) if s.get("name") == "Install dependencies for Snyk Open Source")


def run_snyk_install(tmp_path, requirements_text):
    """Run the real step under bash with a `pip` that records its arguments instead of installing."""
    stubs = tmp_path / "bin"
    stubs.mkdir()
    pip = stubs / "pip"
    pip.write_text('#!/bin/sh\necho "$@" >> "$PIP_LOG"\n')
    pip.chmod(pip.stat().st_mode | stat.S_IXUSR)
    lock = tmp_path / "requirements.txt"
    lock.write_text(requirements_text)
    log = tmp_path / "pip.log"
    env = {
        **os.environ,
        "PATH": f"{stubs}:{os.environ['PATH']}",
        "PIP_LOG": str(log),
        "REQUIREMENTS": str(lock),
        "INSTALL": "",
    }
    result = subprocess.run(["bash", "-e", "-c", snyk_install_step()["run"]], env=env, capture_output=True, text=True)
    return result, log.read_text() if log.exists() else ""


def test_snyk_installs_a_hashed_lock_under_require_hashes(tmp_path):
    result, calls = run_snyk_install(tmp_path, "requests==2.0.0 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    assert result.returncode == 0, result.stderr
    assert calls.strip() == f"install --require-hashes -r {tmp_path / 'requirements.txt'}"


def test_snyk_refuses_a_lock_without_hashes_and_installs_nothing(tmp_path):
    result, calls = run_snyk_install(tmp_path, "requests==2.0.0\n")
    assert result.returncode == 1
    assert "has no hashes" in result.stdout and "--generate-hashes" in result.stdout
    assert calls == "", "an unhashed pin list must never reach pip"


def semgrep_install_step():
    semgrep = jobs(load(WORKFLOWS / "security.yml"))["semgrep"]
    return next(s for s in steps_of(semgrep) if s.get("name") == "Install Semgrep")


def run_semgrep_install(tmp_path, requested):
    """Run the real step under bash with a `python` that records its arguments instead of installing."""
    stubs = tmp_path / "bin"
    stubs.mkdir()
    python = stubs / "python"
    python.write_text('#!/bin/sh\necho "$@" >> "$PY_LOG"\n')
    python.chmod(python.stat().st_mode | stat.S_IXUSR)
    step = semgrep_install_step()
    log = tmp_path / "python.log"
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "PY_LOG": str(log), "RUNNER_TEMP": str(tmp_path)}
    env.update(REQUIREMENTS=step["env"]["REQUIREMENTS"], REQUESTED_VERSION=requested)
    result = subprocess.run(["bash", "-e", "-c", step["run"]], env=env, capture_output=True, text=True)
    return result, log.read_text() if log.exists() else ""


def locked_semgrep():
    return re.search(r"^semgrep==(\S+) ", (REQS / "semgrep.txt").read_text(), re.M)[1]


@pytest.mark.parametrize("requested", ["", "LOCKED"])
def test_semgrep_version_empty_or_the_locked_one_installs(tmp_path, requested):
    result, calls = run_semgrep_install(tmp_path, locked_semgrep() if requested else "")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "--require-hashes" in calls and "-m pip install" in calls


def test_semgrep_version_other_than_the_locked_one_fails_naming_it_and_installs_nothing(tmp_path):
    result, calls = run_semgrep_install(tmp_path, "0.0.1")
    assert result.returncode == 1
    assert locked_semgrep() in result.stdout and "deprecated" in result.stdout and "will be removed" in result.stdout
    assert calls == ""
