"""scripts/new-repo.sh writes a repository's caller files from what the repository holds.

Every run here is --dry-run against a tree built in tmp_path: no network, no
git history touched. What is checked is what a caller relies on: every
`uses:` pinned to the SHA given with the version in a comment, one CI job
per language with the gates the audit will require, the Python-shaped
security defaults turned off for a repository with no Python, and the old
workflows named for replacement rather than silently deleted.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "new-repo.sh"
SHA = "d5d9556afeeb06f78419b91ecb5d146e789c6d51"
PIN = "v9.9.9"

spec = importlib.util.spec_from_file_location("audit_baseline", REPO / "scripts" / "audit_baseline.py")
audit = importlib.util.module_from_spec(spec)
sys.modules["audit_baseline"] = audit
spec.loader.exec_module(audit)


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def adopt(tree: Path, out: Path, *extra: str) -> str:
    out.mkdir()
    result = subprocess.run(
        [
            str(SCRIPT),
            "ChiefGyk3D/example",
            "--dry-run",
            "--path",
            str(tree),
            "--out",
            str(out),
            "--pin",
            PIN,
            "--sha",
            SHA,
            *extra,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def workflow(out: Path, name: str) -> dict:
    return yaml.safe_load((out / ".github" / "workflows" / name).read_text())


def caller_text(out: Path, name: str) -> str:
    return (out / ".github" / "workflows" / name).read_text()


DAEMON = {
    "pyproject.toml": (
        '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
        '[project]\nname = "daemon"\nversion = "1.0"\n'
        'classifiers = ["Programming Language :: Python :: 3.12", "Programming Language :: Python :: 3.13"]\n'
        '[project.scripts]\ndaemon = "daemon:main"\n[tool.ruff]\nline-length = 100\n[tool.mypy]\nstrict = true\n'
    ),
    "requirements.txt": "requests==2.0 --hash=sha256:abc\n",
    "requirements-dev.txt": "requests==2.0 --hash=sha256:abc\npytest==9.0 --hash=sha256:def\n",
    "docker/Dockerfile": "FROM python:3.13-slim\n",
    "scripts/install.sh": "#!/usr/bin/env bash\nset -euo pipefail\n    echo four spaces\n",
    "CHANGELOG.md": "## [1.0]\n",
    ".github/workflows/ci.yml": "name: CI\non: push\njobs: {}\n",
    ".github/workflows/docs.yml": "name: Docs\non: push\njobs: {}\n",
}

SHELL_ONLY = {
    "bin/tool": "#!/bin/bash\n  echo two spaces\n",
    "lib/common.sh": "#!/usr/bin/env bash\n  echo two spaces\n",
    "tests/test-tool.sh": "#!/usr/bin/env bash\n  ./bin/tool\n",
    ".github/workflows/lint.yml": "name: Lint\non: push\njobs: {}\n",
}

LIBRARY = {
    "pyproject.toml": (
        '[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
        '[project]\nname = "lib"\nversion = "1.0"\nrequires-python = ">=3.10"\n'
        '[project.optional-dependencies]\ndev = ["pytest", "ruff"]\n[tool.ruff]\nline-length = 100\n'
    ),
    ".github/workflows/release.yml": (
        "name: Release\non: release\njobs:\n  p:\n    steps:\n      - uses: pypa/gh-action-pypi-publish@abc # v1\n"
    ),
}


def test_a_python_daemon_with_shell_gets_two_ci_jobs_a_container_release_and_both_gates(tmp_path):
    out = tmp_path / "out"
    stdout = adopt(write(tmp_path / "tree", DAEMON), out)
    ci = workflow(out, "ci.yml")
    assert set(ci["jobs"]) == {"ci", "shell"}
    assert ci["jobs"]["ci"]["uses"].startswith(
        "ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@" + SHA
    )
    assert ci["jobs"]["shell"]["uses"].startswith(
        "ChiefGyk3D/git-your-ship-together/.github/workflows/bash-ci.yml@" + SHA
    )
    assert audit.expected_gates(caller_text(out, "ci.yml")) == {"ci / CI green", "shell / CI green"}
    with_ = ci["jobs"]["ci"]["with"]
    assert with_["python-versions"] == '["3.12", "3.13"]', "the classifiers name the versions"
    assert "--require-hashes -r requirements-dev.txt" in with_["install-command"], (
        "a hash-pinned lock is installed as one"
    )
    assert "mypy" in with_["lint-command"] and "ruff check" in with_["lint-command"]
    assert with_["smoke-command"] == "daemon --help"
    assert with_["dockerfile"] == "docker/Dockerfile"
    assert with_["egress-policy"] == "block"
    assert ci["jobs"]["shell"]["with"]["shfmt-args"] == "-i 4 -ci"
    assert ci["jobs"]["shell"]["with"]["workflow-lint"] is False, "one workflow lint per repository"
    release = workflow(out, "release.yml")
    assert set(release["jobs"]) == {"package", "container"}
    assert release["jobs"]["package"]["with"]["pypi"] is False, "no Trusted Publisher exists until a person makes one"
    assert "CHANGELOG.md" in release["jobs"]["package"]["with"]["verify-command"]
    assert release["jobs"]["container"]["with"]["dockerfile"] == "docker/Dockerfile"
    dependabot = yaml.safe_load((out / ".github" / "dependabot.yml").read_text())
    assert [u["package-ecosystem"] for u in dependabot["updates"]] == ["pip", "github-actions", "docker"]
    assert dependabot["updates"][2]["directory"] == "/docker"
    assert "replaces:     ci.yml" in stdout and "leaves alone: docs.yml" in stdout
    assert '"checks": [{"context": "ci / CI green"}, {"context": "shell / CI green"}]' in stdout


def test_a_shell_only_repository_calls_bash_ci_as_ci_and_turns_the_python_defaults_off(tmp_path):
    out = tmp_path / "out"
    stdout = adopt(write(tmp_path / "tree", SHELL_ONLY), out)
    ci = workflow(out, "ci.yml")
    assert set(ci["jobs"]) == {"ci"}
    assert "bash-ci.yml@" + SHA in ci["jobs"]["ci"]["uses"]
    assert ci["jobs"]["ci"]["with"]["shfmt-args"] == "-i 2 -ci", "the indent the scripts already write"
    assert "test-command" not in ci["jobs"]["ci"]["with"], "a test runner is named by a person, not guessed"
    assert "tests/test-tool.sh" in caller_text(out, "ci.yml"), "but what was seen is written down"
    assert audit.expected_gates(caller_text(out, "ci.yml")) == {"ci / CI green"}
    security = workflow(out, "security.yml")["jobs"]["security"]["with"]
    assert security["codeql-languages"] == "actions"
    assert security["pip-audit-requirements"] == ""
    assert not (out / ".github" / "workflows" / "release.yml").exists(), "nothing to release"
    dependabot = yaml.safe_load((out / ".github" / "dependabot.yml").read_text())
    assert [u["package-ecosystem"] for u in dependabot["updates"]] == ["github-actions"]
    assert "replaces:     lint.yml" in stdout


def test_a_library_that_already_publishes_to_pypi_keeps_publishing(tmp_path):
    out = tmp_path / "out"
    adopt(write(tmp_path / "tree", LIBRARY), out)
    ci = workflow(out, "ci.yml")["jobs"]["ci"]["with"]
    assert ci["python-versions"] == '["3.10", "3.11", "3.12", "3.13"]', "from requires-python up"
    assert 'pip install -e ".[dev]"' in ci["install-command"]
    assert ci["docker-build"] is False
    release = workflow(out, "release.yml")["jobs"]
    assert set(release) == {"package"}
    assert release["package"]["with"]["pypi"] is True, "the old workflow published there; a Trusted Publisher exists"
    assert release["package"]["with"]["publish"] == "${{ startsWith(github.ref, 'refs/tags/v') }}"


@pytest.mark.parametrize("tree", [DAEMON, SHELL_ONLY, LIBRARY], ids=["daemon", "shell", "library"])
def test_every_written_workflow_passes_the_audits_pin_check_and_names_the_auto_merge(tmp_path, tree):
    out = tmp_path / "out"
    adopt(write(tmp_path / "tree", tree), out)
    for path in sorted((out / ".github" / "workflows").glob("*.yml")):
        text = path.read_text()
        assert audit.workflow_findings(path.name, text) == [], path.name
        assert f"@{SHA} # {PIN}" in text, f"{path.name} is not pinned to the requested release"
        doc = yaml.safe_load(text)
        assert doc["permissions"] == {"contents": "read"}, f"{path.name} widens top-level permissions"
    assert "dependabot-auto-merge.yml@" + SHA in caller_text(out, "dependabot-auto-merge.yml")


def test_languages_can_be_forced_and_an_empty_tree_is_refused(tmp_path):
    out = tmp_path / "out"
    adopt(write(tmp_path / "tree", SHELL_ONLY), out, "--language", "python", "--language", "bash")
    assert set(workflow(out, "ci.yml")["jobs"]) == {"ci", "shell"}
    empty = tmp_path / "empty"
    empty.mkdir()
    result = subprocess.run(
        [str(SCRIPT), "ChiefGyk3D/example", "--dry-run", "--path", str(empty), "--out", str(tmp_path / "out2")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0 and "neither Python nor shell" in result.stderr
