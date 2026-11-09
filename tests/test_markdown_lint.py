"""markdown-lint.yml and its offline input/annotation runner (issue #394).

The real rumdl release is deliberately not downloaded here. A fake executable
checks the command boundary and emits rumdl's GitHub format, while the workflow
shape test pins the supplied release facts and the shared download helper.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml
from test_fetch_release import block_of, source_block

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "run_markdown_lint.py"
WORKFLOW = REPO / ".github" / "workflows" / "markdown-lint.yml"
CONFIG = REPO / ".github" / "rumdl.toml"
CI = REPO / ".github" / "workflows" / "ci.yml"
VERSION = "0.3.2"
URL = "https://github.com/rvben/rumdl/releases/download/v0.3.2/rumdl-v0.3.2-x86_64-unknown-linux-gnu.tar.gz"
SHA256 = "f527d1374765d826c1627ceab3d1f46e548268731a495b5b12a3af529b3d79e8"


def executable(path: Path, body: str) -> Path:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "docs" / "nested").mkdir(parents=True)
    (tmp_path / "docs" / "one.md").write_text("# One\n")
    (tmp_path / "docs" / "nested" / "two words.md").write_text("# Two\n")
    (tmp_path / "notes.txt").write_text("notes\n")
    (tmp_path / "custom.toml").write_text('[global]\ndisable = ["MD013"]\n')
    (tmp_path / "default.toml").write_text('[global]\ndisable = ["MD013", "MD033"]\n')
    return tmp_path


def fake_rumdl(tree: Path, output: str = "", code: int = 0) -> Path:
    return executable(
        tree / "rumdl",
        "#!/usr/bin/env python3\n"
        "import os, pathlib, sys\n"
        "pathlib.Path(os.environ['RUMDL_LOG']).write_text('\\n'.join(sys.argv[1:]))\n"
        f"sys.stdout.write({output!r})\n"
        f"raise SystemExit({code})\n",
    )


def run(tree: Path, rumdl: Path, *, globs="**/*.md", config="", fail=True, env=None):
    output = tree / "github-output"
    full_env = {**os.environ, "RUMDL_LOG": str(tree / "rumdl.log"), "GITHUB_OUTPUT": str(output), **(env or {})}
    done = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SCRIPT),
            "--root",
            str(tree),
            "--rumdl",
            str(rumdl),
            "--globs",
            globs,
            "--config",
            config,
            "--default-config",
            str(tree / "default.toml"),
            "--fail-on-findings",
            str(fail).lower(),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=full_env,
    )
    return done, (output.read_text() if output.exists() else "")


def test_newline_globs_expand_deduplicate_and_keep_spaces_as_one_argument(tree):
    done, written = run(tree, fake_rumdl(tree), globs="docs/**/*.md\nnotes.txt\ndocs/one.md\n\n")
    assert done.returncode == 0, done.stdout + done.stderr
    assert (tree / "rumdl.log").read_text().splitlines() == [
        "check",
        "--config",
        str(tree / "default.toml"),
        "--output-format",
        "github",
        "--",
        "docs/nested/two words.md",
        "docs/one.md",
        "notes.txt",
    ]
    assert written == "findings=0\n"


def test_a_repository_config_is_resolved_inside_the_checkout(tree):
    done, _ = run(tree, fake_rumdl(tree), globs="docs/one.md", config="custom.toml")
    assert done.returncode == 0
    args = (tree / "rumdl.log").read_text().splitlines()
    assert args[args.index("--config") + 1] == str(tree / "custom.toml")


@pytest.mark.parametrize("config", ["../outside.toml", "/etc/passwd", "missing.toml"])
def test_an_escaping_or_missing_config_fails_before_rumdl(tree, config):
    rumdl = fake_rumdl(tree)
    done, _ = run(tree, rumdl, config=config)
    assert done.returncode == 2 and not (tree / "rumdl.log").exists()


@pytest.mark.parametrize("globs", ["", "../*.md", "/tmp/*.md", "missing/**/*.md"])
def test_empty_escaping_or_unmatched_globs_fail_before_rumdl(tree, globs):
    rumdl = fake_rumdl(tree)
    done, _ = run(tree, rumdl, globs=globs)
    assert done.returncode == 2 and not (tree / "rumdl.log").exists()


def annotation(number: int) -> str:
    return f"::error file=docs/one.md,line={number},col=2,title=MD001::MD001 heading jump {number}"


def test_findings_are_normalized_bounded_to_50_and_fail_by_default(tree):
    raw = "\n".join(annotation(n) for n in range(1, 56)) + "\n"
    done, written = run(tree, fake_rumdl(tree, raw, 1), globs="docs/one.md")
    lines = [line for line in done.stdout.splitlines() if line.startswith("::error ")]
    assert done.returncode == 1 and len(lines) == 50
    assert lines[0] == "::error file=docs/one.md,line=1,col=2,title=MD001::MD001: heading jump 1"
    assert "5 more finding(s) omitted" in done.stdout
    assert written == "findings=55\n"


def test_fail_on_findings_false_makes_the_same_findings_warnings(tree):
    done, written = run(tree, fake_rumdl(tree, annotation(7) + "\n", 1), globs="docs/one.md", fail=False)
    assert done.returncode == 0
    assert done.stdout.startswith("::warning file=docs/one.md,line=7,col=2,title=MD001::MD001: heading jump 7")
    assert written == "findings=1\n"


def test_an_unparseable_linter_failure_fails_closed(tree):
    done, written = run(tree, fake_rumdl(tree, "unexpected output\n", 2), globs="docs/one.md", fail=False)
    assert done.returncode == 2 and "rumdl failed" in done.stdout
    assert written == ""


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def inlined_python() -> str:
    text = WORKFLOW.read_text()
    match = re.search(r"<<'PY'\n(.*?)\n\s*PY\n", text, re.S)
    assert match, "the lint step has no PY heredoc"
    return textwrap.dedent(match.group(1)) + "\n"


def inlined_config() -> str:
    text = WORKFLOW.read_text()
    match = re.search(r"<<'TOML'\n(.*?)\n\s*TOML\n", text, re.S)
    assert match, "the lint step has no TOML heredoc"
    return textwrap.dedent(match.group(1)) + "\n"


def test_workflow_pins_the_supplied_release_facts_and_shared_fetch_helper():
    text = WORKFLOW.read_text()
    inputs = workflow()[True]["workflow_call"]["inputs"]
    assert inputs["rumdl-version"]["default"] == VERSION
    assert inputs["rumdl-url"]["default"] == URL
    assert inputs["rumdl-sha256"]["default"] == SHA256
    run_text = workflow()["jobs"]["lint"]["steps"][-1]["run"]
    assert block_of(run_text) == source_block()
    assert 'fetch_release "$RUMDL_URL" "$archive" "$RUMDL_SHA256"' in text
    outside_helper = run_text.split("# BEGIN fetch_release", 1)[0] + run_text.split("# END fetch_release", 1)[1]
    assert "tar -xzf" in run_text and "curl " not in outside_helper


def test_workflow_inputs_defaults_outputs_and_committed_sources_are_pinned():
    doc = workflow()
    call = doc[True]["workflow_call"]
    inputs = call["inputs"]
    assert inputs["globs"]["default"] == "**/*.md"
    assert inputs["config"]["default"] == ""
    assert inputs["fail-on-findings"]["default"] is True
    assert call["outputs"]["findings"]["value"] == "${{ jobs.lint.outputs.findings }}"
    assert doc["permissions"] == {"contents": "read"}
    assert inlined_python() == SCRIPT.read_text()
    assert inlined_config() == CONFIG.read_text()
    assert CONFIG.read_text() == '[global]\ndisable = ["MD013", "MD033"]\n'


def test_ci_has_a_passing_fixture_and_a_planted_finding_control():
    jobs = yaml.safe_load(CI.read_text())["jobs"]
    passing = jobs["fixture-markdown-lint"]
    planted = jobs["fixture-markdown-lint-planted"]
    control = jobs["markdown-lint-control"]
    assert passing["uses"] == planted["uses"] == "./.github/workflows/markdown-lint.yml"
    assert passing["with"]["globs"] == "fixture/markdown-lint/passing.md"
    assert planted["with"]["globs"] == "fixture/markdown-lint/planted.md"
    assert planted["with"]["fail-on-findings"] is False
    assert "fixture-markdown-lint-planted" in control["needs"]
    assert "findings" in yaml.dump(control["steps"])
    for name in ("fixture-markdown-lint", "fixture-markdown-lint-planted", "markdown-lint-control"):
        assert name in jobs["ci-green"]["needs"]


def test_fixture_documents_are_a_small_pass_and_heading_jump_control():
    passing = (REPO / "fixture" / "markdown-lint" / "passing.md").read_text()
    planted = (REPO / "fixture" / "markdown-lint" / "planted.md").read_text()
    assert passing == "# Passing fixture\n\nA short paragraph.\n"
    assert planted == "# Planted finding\n\n### This skips a heading level\n"
