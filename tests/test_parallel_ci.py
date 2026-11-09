"""parallel-ci.yml: the planning script, the steps that run caller commands, and the properties of the workflow.

Three kinds of check. The planning script (scripts/parallel_ci_plan.py) is run as a process, the way the workflow
runs it, over hostile and ordinary inputs; the workflow's own `changes` step is run under bash in a real git
repository with a real merge commit, so the diff it takes is the diff the plan sees; and the YAML is read for the
properties a caller relies on and a reviewer would otherwise have to trust (no continue-on-error, no input in a
shell script, nothing written to the Actions PATH, a gate that needs every job). Each refusal has a passing twin.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "parallel_ci_plan.py"
WORKFLOW = REPO / ".github" / "workflows" / "parallel-ci.yml"
GATE_WORKFLOW = REPO / ".github" / "workflows" / "ci-gate.yml"

JOBS = [
    {"name": "always", "command": "true"},
    {"name": "code only", "command": "make test", "areas": ["code"], "timeout": 5},
    {"name": "docs only", "command": "make docs", "areas": ["docs"]},
]
AREAS = {"docs": ["docs/*.md", "README.md"], "code": ["*"]}


def base_env(**over):
    env = {
        "PLAN_JOBS": json.dumps(JOBS),
        "PLAN_AREAS": json.dumps(AREAS),
        "PLAN_BUILD_OUTPUT_PATH": "public",
        "PLAN_EXTRA_OUTPUT_PATH": "",
        "PLAN_ARTIFACT_NAME": "gyst-build",
        "PLAN_RETENTION_DAYS": "1",
        "PLAN_CACHE_PIP_FILES": "[]",
        "PLAN_BUILD_PIP_CACHE": "false",
        "PLAN_CACHE_TOOL_PATH": "",
        "PLAN_CACHE_TOOL_KEY_FILES": "[]",
        "PLAN_EVENT": "pull_request",
        "PLAN_BASE_REF": "main",
        "PLAN_DEFAULT_BRANCH": "main",
    }
    env.update({k: v if isinstance(v, str) else json.dumps(v) for k, v in over.items()})
    return env


def plan(tmp_path: Path, changed: list[bytes] | bytes | None = None, **over):
    """Run the script in tmp_path; returns (exit code, stdout, outputs dict). `changed` None means no diff."""
    out = tmp_path / "github_output"
    out.write_text("")
    args = [sys.executable, "-I", str(SCRIPT), "--output", str(out)]
    if changed is not None:
        data = changed if isinstance(changed, bytes) else b"".join(c + b"\0" for c in changed)
        (tmp_path / "changed.z").write_bytes(data)
        args += ["--changed", str(tmp_path / "changed.z")]
    env = {"PATH": "/usr/bin:/bin", "RUNNER_TEMP": "/home/runner/work/_temp", **base_env(**over)}
    done = subprocess.run(
        args, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL
    )
    lines = out.read_text().splitlines()
    outputs = dict(line.split("=", 1) for line in lines)
    assert len(outputs) == len(lines), "every output line is one key=value"
    return done.returncode, done.stdout, outputs


def names(outputs) -> list[str]:
    return [job["name"] for job in json.loads(outputs["matrix"])]


# --- which checks run -----------------------------------------------------------------------------------------


def test_a_docs_only_pull_request_skips_the_code_checks_and_keeps_the_others(tmp_path):
    code, _, out = plan(tmp_path, [b"docs/guide.md", b"README.md"])
    assert code == 0
    assert names(out) == ["always", "docs only"]
    assert out["skipped-jobs"] == "code only" and out["everything"] == "false" and out["areas"] == "docs"
    assert out["count"] == "2"


def test_a_code_change_runs_the_code_checks(tmp_path):
    code, _, out = plan(tmp_path, [b"src/app.py"])
    assert code == 0 and names(out) == ["always", "code only"]
    assert out["skipped-jobs"] == "docs only"


def test_a_mixed_change_runs_every_check(tmp_path):
    code, _, out = plan(tmp_path, [b"README.md", b"src/app.py"])
    assert code == 0 and names(out) == ["always", "code only", "docs only"]
    assert out["skipped-jobs"] == "" and out["areas"] == "code,docs"


def test_the_first_matching_area_wins(tmp_path):
    """README.md matches docs and, later, the code catch-all; it is a docs path."""
    code, _, out = plan(tmp_path, [b"README.md"])
    assert out["areas"] == "docs" and "code only" not in names(out)


@pytest.mark.parametrize("event", ["push", "schedule", "workflow_dispatch", "merge_group", "pull_request_target", ""])
def test_every_event_but_a_pull_request_runs_everything(tmp_path, event):
    code, _, out = plan(tmp_path, [b"README.md"], PLAN_EVENT=event, PLAN_BASE_REF="")
    assert code == 0
    assert names(out) == ["always", "code only", "docs only"] and out["everything"] == "true" and out["areas"] == ""


def test_a_push_to_the_default_branch_runs_everything_whatever_the_diff_says(tmp_path):
    _, _, out = plan(tmp_path, [b"README.md"], PLAN_EVENT="push", PLAN_BASE_REF="")
    assert out["everything"] == "true" and out["count"] == "3"


def test_a_pull_request_to_the_default_branch_narrows(tmp_path):
    _, _, out = plan(tmp_path, [b"README.md"], PLAN_BASE_REF="main")
    assert out["everything"] == "false" and out["areas"] == "docs"


@pytest.mark.parametrize("base", ["develop", "release/1.0", "", "main2", "Main", "ma in", "main\nx"])
def test_a_pull_request_to_any_other_branch_or_an_unknown_one_runs_everything(tmp_path, base):
    _, _, out = plan(tmp_path, [b"README.md"], PLAN_BASE_REF=base)
    assert out["everything"] == "true" and out["count"] == "3"


@pytest.mark.parametrize("default", ["", "bad name", "x" * 201])
def test_an_unusable_default_branch_runs_everything(tmp_path, default):
    _, _, out = plan(tmp_path, [b"README.md"], PLAN_DEFAULT_BRANCH=default, PLAN_BASE_REF=default)
    assert out["everything"] == "true"


def test_a_tag_run_runs_everything(tmp_path):
    _, _, out = plan(tmp_path, [b"README.md"], PLAN_EVENT="push", PLAN_BASE_REF="")
    assert out["everything"] == "true"


def test_a_missing_diff_runs_everything(tmp_path):
    _, _, out = plan(tmp_path, None)
    assert out["everything"] == "true" and out["count"] == "3"


def test_an_empty_diff_runs_everything(tmp_path):
    for empty in (b"", b"\0"):
        _, _, out = plan(tmp_path, empty)
        assert out["everything"] == "true" and out["count"] == "3"


def test_a_path_no_rule_matches_runs_everything(tmp_path):
    areas = {"docs": ["docs/*.md"], "code": ["src/*"]}
    _, _, out = plan(tmp_path, [b"docs/a.md", b"Makefile"], PLAN_AREAS=areas)
    assert out["everything"] == "true" and out["count"] == "3"
    _, _, out = plan(tmp_path, [b"docs/a.md"], PLAN_AREAS=areas)  # the passing twin: every path matched
    assert out["everything"] == "false" and names(out) == ["always", "docs only"]


@pytest.mark.parametrize(
    "path",
    [b"docs/a\nb.md", b"docs/\x1b[2Jx.md", b"docs/\xff\xfe.md", b"docs/tab\there.md", b"docs/\x7f.md"],
    ids=["newline", "escape", "invalid-utf8", "tab", "del"],
)
def test_a_path_with_an_odd_byte_runs_everything(tmp_path, path):
    _, _, out = plan(tmp_path, [b"README.md", path])
    assert out["everything"] == "true" and out["count"] == "3"


def test_an_unusual_but_printable_path_is_classified_not_refused(tmp_path):
    _, _, out = plan(tmp_path, ["docs/café déjà.md".encode()])
    assert out["everything"] == "false" and out["areas"] == "docs"


def test_a_job_with_no_areas_always_runs_and_the_list_keeps_its_order(tmp_path):
    jobs = [{"name": "z", "command": "true"}, {"name": "a", "command": "true"}]
    _, _, out = plan(tmp_path, [b"README.md"], PLAN_JOBS=jobs)
    assert names(out) == ["z", "a"]


def test_no_job_selected_is_reported_as_a_zero_count(tmp_path):
    jobs = [{"name": "only code", "command": "true", "areas": ["code"]}]
    _, _, out = plan(tmp_path, [b"README.md"], PLAN_JOBS=jobs)
    assert out["count"] == "0" and out["matrix"] == "[]" and out["skipped-jobs"] == "only code"


def test_the_matrix_carries_only_the_fields_a_leg_needs_with_defaults_filled(tmp_path):
    _, _, out = plan(tmp_path, None)
    legs = json.loads(out["matrix"])
    assert legs[0] == {
        "name": "always",
        "command": "true",
        "timeout": 15,
        "pip-cache": False,
        "tools": False,
        "build": True,
    }
    assert legs[1]["timeout"] == 5 and "areas" not in legs[1]


def test_a_command_with_line_breaks_stays_on_one_output_line(tmp_path):
    command = "echo a\necho b\n::set-output name=x::y\nEOF\nmatrix=[]"
    code, _, out = plan(tmp_path, None, PLAN_JOBS=[{"name": "multi", "command": command}])
    assert code == 0 and json.loads(out["matrix"])[0]["command"] == command
    assert set(out) == {
        "matrix", "count", "skipped-jobs", "everything", "areas", "output-path", "extra-path",
        "artifact-name", "pip-key", "build-pip-key", "tool-key", "tool-path",
    }  # fmt: skip


# --- the real `changes` step, in a real repository ------------------------------------------------------------


def git(repo: Path, *args: str) -> str:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(repo),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True).stdout


def plan_step() -> str:
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["changes"]["steps"]
    return next(s["run"] for s in steps if s.get("id") == "plan")


def run_step(repo: Path, event: str, base: str = "main", **over):
    out = repo / ".out"
    out.write_text("")
    script = repo / ".step.sh"
    script.write_text(plan_step())
    temp = repo / ".tmp"
    temp.mkdir(exist_ok=True)
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(repo),
        "GITHUB_OUTPUT": str(out),
        "RUNNER_TEMP": str(temp),
        **base_env(PLAN_EVENT=event, PLAN_BASE_REF=base, **over),
    }
    done = subprocess.run(
        ["bash", "-eo", "pipefail", str(script)], cwd=repo, env=env, capture_output=True, text=True, timeout=60
    )
    return done, dict(line.split("=", 1) for line in out.read_text().splitlines())


@pytest.fixture
def merge_repo(tmp_path):
    """main with src/ and docs/, and a merge commit checked out like a pull request's merge ref."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "src").mkdir()
    (repo / "docs").mkdir()
    (repo / "src" / "app.py").write_text("print(1)\n")
    (repo / "docs" / "guide.md").write_text("# guide\n")
    (repo / ".gitignore").write_text(".out\n.step.sh\n.tmp\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    return repo


def merge_change(repo: Path, edit):
    git(repo, "checkout", "-qb", "feature")
    edit(repo)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "change")
    git(repo, "checkout", "-q", "main")
    (repo / "docs" / "other.md").write_text("# a later commit on main\n")  # the base moves on; the diff must not see it
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "later")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "feature")


def test_the_step_sees_a_docs_only_pull_request_as_docs_only(merge_repo):
    merge_change(merge_repo, lambda r: (r / "docs" / "guide.md").write_text("# edited\n"))
    done, out = run_step(merge_repo, "pull_request")
    assert done.returncode == 0, done.stdout + done.stderr
    assert out["everything"] == "false" and out["areas"] == "docs" and out["skipped-jobs"] == "code only"


def test_the_step_sees_a_code_change(merge_repo):
    merge_change(merge_repo, lambda r: (r / "src" / "app.py").write_text("print(2)\n"))
    done, out = run_step(merge_repo, "pull_request")
    assert done.returncode == 0 and out["areas"] == "code" and out["skipped-jobs"] == "docs only"


def test_a_rename_out_of_a_code_path_is_seen_as_code(merge_repo):
    """--no-renames lists the old path too, so moving a code file into docs/ is not a docs-only change."""

    def move(repo: Path):
        (repo / "docs" / "moved.md").write_bytes((repo / "src" / "app.py").read_bytes())
        (repo / "src" / "app.py").unlink()

    merge_change(merge_repo, move)
    done, out = run_step(merge_repo, "pull_request")
    assert done.returncode == 0 and out["areas"] == "code,docs" and out["skipped-jobs"] == ""


def test_the_step_runs_everything_when_there_is_no_merge_commit(merge_repo):
    """A plain commit has no second parent: the step leaves the diff out and the script fails closed."""
    (merge_repo / "docs" / "guide.md").write_text("# edited\n")
    git(merge_repo, "commit", "-qam", "plain")
    done, out = run_step(merge_repo, "pull_request")
    assert done.returncode == 0
    assert out["everything"] == "true" and out["count"] == "3"
    assert "diff is unavailable" in done.stdout


def test_the_step_takes_no_diff_for_a_push(merge_repo):
    merge_change(merge_repo, lambda r: (r / "docs" / "guide.md").write_text("# edited\n"))
    done, out = run_step(merge_repo, "push", base="")
    assert done.returncode == 0 and out["everything"] == "true" and out["count"] == "3"
    assert "unavailable" not in done.stdout


def test_the_step_fails_on_an_invalid_input_instead_of_running_everything(merge_repo):
    done, out = run_step(merge_repo, "push", PLAN_JOBS="[]")
    assert done.returncode == 1 and not out


def test_the_step_runs_the_script_isolated_and_reads_the_diff_with_no_renames():
    text = plan_step()
    assert "git diff --no-renames --name-only -z 'HEAD^1' HEAD" in text
    assert "python3 -I - " in text


# --- invalid inputs are an error, not a quiet pass --------------------------------------------------------------


def bad(tmp_path, needle, **over):
    code, stdout, _ = plan(tmp_path, [b"README.md"], **over)
    assert code == 1, f"expected a refusal mentioning {needle!r}"
    assert needle in stdout
    assert stdout.count("\n") == 1, "one annotation line, nothing forged"


@pytest.mark.parametrize(
    "jobs,needle",
    [
        ("not json", "jobs is not valid JSON"),
        ("{}", "jobs must be a JSON list"),
        ("[]", "jobs is empty"),
        ('[{"name": "a", "command": "x"}, {"name": "a", "command": "x"}]', "used twice"),
        ('[{"name": "A", "command": "x"}, {"name": "a", "command": "x"}]', "used twice"),
        ('[{"name": "a", "command": "x", "name": "b"}]', "not valid JSON"),
        ('["a"]', "must be an object"),
        ('[{"name": "a", "command": "x", "pip_cache": true}]', "unknown keys"),
        ('[{"command": "x"}]', "name must match"),
        ('[{"name": "a,b", "command": "x"}]', "name must match"),
        ('[{"name": "a\\nb", "command": "x"}]', "name must match"),
        ('[{"name": "a", "command": ""}]', "command must be"),
        ('[{"name": "a", "command": "  "}]', "command must be"),
        ('[{"name": "a", "command": "x\\u0000y"}]', "command must be"),
        ('[{"name": "a", "command": 3}]', "command must be"),
        ('[{"name": "a", "command": "x", "timeout": 0}]', "timeout must be"),
        ('[{"name": "a", "command": "x", "timeout": 361}]', "timeout must be"),
        ('[{"name": "a", "command": "x", "timeout": true}]', "timeout must be"),
        ('[{"name": "a", "command": "x", "timeout": "5"}]', "timeout must be"),
        ('[{"name": "a", "command": "x", "areas": "code"}]', "areas must be a list"),
        ('[{"name": "a", "command": "x", "areas": ["nope"]}]', "which the areas input does not define"),
        ('[{"name": "a", "command": "x", "pip-cache": "yes"}]', "pip-cache must be true or false"),
        ('[{"name": "a", "command": "x", "tools": 1}]', "tools must be true or false"),
        ('[{"name": "a", "command": "x", "build": null}]', "build must be true or false"),
    ],
)
def test_an_invalid_jobs_list_is_refused(tmp_path, jobs, needle):
    bad(tmp_path, needle, PLAN_JOBS=jobs)


def test_too_many_jobs_are_refused(tmp_path):
    jobs = [{"name": f"job {i}", "command": "true"} for i in range(33)]
    bad(tmp_path, "more than 32", PLAN_JOBS=jobs)
    jobs = jobs[:32]  # the passing twin
    assert plan(tmp_path, None, PLAN_JOBS=jobs)[0] == 0


@pytest.mark.parametrize(
    "areas,needle",
    [
        ("not json", "areas is not valid JSON"),
        ("[]", "areas must be a JSON object"),
        ('{"bad name": ["*"]}', "area name"),
        ('{"a": []}', "non-empty list"),
        ('{"a": "*"}', "non-empty list"),
        ('{"a": [""]}', "pattern"),
        ('{"a": ["x\\ny"]}', "pattern"),
        ('{"a": [1]}', "pattern"),
        ('{"a": ["*"], "a": ["*"]}', "not valid JSON"),
    ],
)
def test_invalid_area_rules_are_refused(tmp_path, areas, needle):
    bad(tmp_path, needle, PLAN_AREAS=areas, PLAN_JOBS=[{"name": "a", "command": "x"}])


@pytest.mark.parametrize(
    "var,value",
    [
        ("PLAN_BUILD_OUTPUT_PATH", ""),
        ("PLAN_BUILD_OUTPUT_PATH", "/etc"),
        ("PLAN_BUILD_OUTPUT_PATH", "../outside"),
        ("PLAN_BUILD_OUTPUT_PATH", "a/../b"),
        ("PLAN_BUILD_OUTPUT_PATH", "."),
        ("PLAN_BUILD_OUTPUT_PATH", ".git"),
        ("PLAN_BUILD_OUTPUT_PATH", "a/.git/hooks"),
        ("PLAN_BUILD_OUTPUT_PATH", "-rf"),
        ("PLAN_BUILD_OUTPUT_PATH", "a b"),
        ("PLAN_BUILD_OUTPUT_PATH", "a\nb"),
        ("PLAN_BUILD_OUTPUT_PATH", "a;b"),
        ("PLAN_BUILD_OUTPUT_PATH", "$HOME"),
        ("PLAN_BUILD_OUTPUT_PATH", "a//b"),
        ("PLAN_EXTRA_OUTPUT_PATH", "RUNNER_TEMP/../x"),
        ("PLAN_EXTRA_OUTPUT_PATH", "RUNNER_TEMP/"),
        ("PLAN_EXTRA_OUTPUT_PATH", "/tmp/x"),
        ("PLAN_ARTIFACT_NAME", ""),
        ("PLAN_ARTIFACT_NAME", "a/b"),
        ("PLAN_ARTIFACT_NAME", "a b"),
        ("PLAN_ARTIFACT_NAME", "x" * 60),
        ("PLAN_RETENTION_DAYS", "0"),
        ("PLAN_RETENTION_DAYS", "8"),
        ("PLAN_RETENTION_DAYS", "90"),
        ("PLAN_RETENTION_DAYS", "1.5"),
        ("PLAN_RETENTION_DAYS", ""),
    ],
)
def test_an_unsafe_path_name_or_retention_is_refused(tmp_path, var, value):
    code, stdout, _ = plan(tmp_path, [b"README.md"], **{var: value})
    assert code == 1 and stdout.startswith("::error title=parallel-ci input::"), (var, value)


@pytest.mark.parametrize(
    "var,value",
    [
        ("PLAN_BUILD_OUTPUT_PATH", "public"),
        ("PLAN_BUILD_OUTPUT_PATH", "build/site-1.0/out"),
        ("PLAN_EXTRA_OUTPUT_PATH", "RUNNER_TEMP/public-staging"),
        ("PLAN_EXTRA_OUTPUT_PATH", "dist/extra"),
        ("PLAN_ARTIFACT_NAME", "site_2"),
        ("PLAN_RETENTION_DAYS", "7"),
        ("PLAN_RETENTION_DAYS", "1.0"),
    ],
)
def test_the_passing_twins_of_the_path_name_and_retention_checks(tmp_path, var, value):
    assert plan(tmp_path, [b"README.md"], **{var: value})[0] == 0


def test_a_runner_temp_path_is_resolved_and_a_hostile_runner_temp_is_refused(tmp_path):
    _, _, out = plan(tmp_path, None, PLAN_EXTRA_OUTPUT_PATH="RUNNER_TEMP/public-staging")
    assert out["extra-path"] == "/home/runner/work/_temp/public-staging"
    out_file = tmp_path / "o"
    done = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "--output", str(out_file)],
        cwd=tmp_path,
        env={"PATH": "/usr/bin", "RUNNER_TEMP": "/tmp/a b;rm", **base_env(PLAN_EXTRA_OUTPUT_PATH="RUNNER_TEMP/x")},
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert done.returncode == 1 and "RUNNER_TEMP" in done.stdout


# --- cache keys ---------------------------------------------------------------------------------------------


def pin(tmp_path: Path, name="requirements.txt", data=b"pkg==1 --hash=sha256:aa\n"):
    (tmp_path / name).write_bytes(data)
    return name


def test_the_pip_key_is_a_hash_of_the_named_files_and_changes_with_them(tmp_path):
    name = pin(tmp_path)
    _, _, one = plan(tmp_path, None, PLAN_CACHE_PIP_FILES=[name])
    assert re.fullmatch(r"[0-9a-f]{64}", one["pip-key"])
    assert one["build-pip-key"] == ""
    assert plan(tmp_path, None, PLAN_CACHE_PIP_FILES=[name])[2]["pip-key"] == one["pip-key"]
    pin(tmp_path, data=b"pkg==2 --hash=sha256:bb\n")
    assert plan(tmp_path, None, PLAN_CACHE_PIP_FILES=[name])[2]["pip-key"] != one["pip-key"]


def test_the_key_depends_on_the_file_name_as_well_as_the_bytes(tmp_path):
    data = b"same\n"
    a, b = pin(tmp_path, "a.txt", data), pin(tmp_path, "b.txt", data)
    key_a = plan(tmp_path, None, PLAN_CACHE_PIP_FILES=[a])[2]["pip-key"]
    assert key_a != plan(tmp_path, None, PLAN_CACHE_PIP_FILES=[b])[2]["pip-key"]
    assert key_a != hashlib.sha256(data).hexdigest()


def test_the_build_job_restores_the_pip_cache_only_when_asked(tmp_path):
    name = pin(tmp_path)
    _, _, out = plan(tmp_path, None, PLAN_CACHE_PIP_FILES=[name], PLAN_BUILD_PIP_CACHE="true")
    assert out["build-pip-key"] == out["pip-key"] != ""


def test_no_pin_files_means_no_key(tmp_path):
    _, _, out = plan(tmp_path, None)
    assert out["pip-key"] == "" and out["tool-key"] == "" and out["tool-path"] == ""


@pytest.mark.parametrize(
    "files",
    [["missing.txt"], ["../outside"], ["/etc/passwd"], ["dir"], ["a\nb"], "not json", '{"a": 1}', [1]],
    ids=["missing", "dotdot", "absolute", "directory", "newline", "not-json", "object", "number"],
)
def test_a_pin_file_that_is_not_a_plain_file_in_the_workspace_is_refused(tmp_path, files):
    (tmp_path / "dir").mkdir()
    code, stdout, _ = plan(tmp_path, None, PLAN_CACHE_PIP_FILES=files)
    assert code == 1 and "cache-pip-files" in stdout


def test_a_symlinked_pin_file_is_refused(tmp_path):
    (tmp_path.parent / "outside-pin.txt").write_text("x")
    (tmp_path / "link.txt").symlink_to(tmp_path.parent / "outside-pin.txt")
    code, stdout, _ = plan(tmp_path, None, PLAN_CACHE_PIP_FILES=["link.txt"])
    assert code == 1 and "regular file" in stdout


def test_the_tool_cache_needs_both_halves(tmp_path):
    name = pin(tmp_path, ".tool-version", b"1.2.3\n")
    code, stdout, _ = plan(tmp_path, None, PLAN_CACHE_TOOL_PATH="RUNNER_TEMP/dl")
    assert code == 1 and "together" in stdout
    code, stdout, _ = plan(tmp_path, None, PLAN_CACHE_TOOL_KEY_FILES=[name])
    assert code == 1 and "together" in stdout
    code, _, out = plan(tmp_path, None, PLAN_CACHE_TOOL_PATH="RUNNER_TEMP/dl", PLAN_CACHE_TOOL_KEY_FILES=[name])
    assert (
        code == 0
        and out["tool-path"] == "/home/runner/work/_temp/dl"
        and re.fullmatch(r"[0-9a-f]{64}", out["tool-key"])
    )


# --- the steps that run caller commands ------------------------------------------------------------------------


def job_steps(job: str) -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"][job]["steps"]


def command_step(job: str) -> dict:
    return next(s for s in job_steps(job) if s.get("name") in ("Build", "Run the check"))


def run_command(tmp_path: Path, job: str, setup: str, command: str):
    step = command_step(job)
    script = tmp_path / "step.sh"
    script.write_text(step["run"])
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    env = {"PATH": os.environ["PATH"], "RUNNER_TEMP": str(temp), "SETUP": setup, "COMMAND": command}
    done = subprocess.run(
        ["bash", "-eo", "pipefail", str(script)], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60
    )
    return done


@pytest.mark.parametrize("job", ["build", "checks"])
def test_a_command_that_succeeds_passes_and_one_that_fails_fails_with_its_status(tmp_path, job):
    assert run_command(tmp_path, job, "", "touch ran").returncode == 0 and (tmp_path / "ran").exists()
    assert run_command(tmp_path, job, "", "exit 3").returncode == 3
    assert run_command(tmp_path, job, "", "false; true").returncode != 0, "a failing line stops the command (-e)"
    assert run_command(tmp_path, job, "", "false | true").returncode != 0, "a failing pipe fails the command (pipefail)"


@pytest.mark.parametrize("job", ["build", "checks"])
def test_a_setup_that_ends_the_step_early_cannot_make_it_pass(tmp_path, job):
    done = run_command(tmp_path, job, "exit 0", "touch ran")
    assert done.returncode == 1 and not (tmp_path / "ran").exists()
    assert "ended the step before" in done.stdout
    assert run_command(tmp_path, job, "true", "touch ran").returncode == 0  # the passing twin


@pytest.mark.parametrize("job", ["build", "checks"])
def test_a_failing_setup_fails_the_step_and_runs_no_command(tmp_path, job):
    done = run_command(tmp_path, job, "false", "touch ran")
    assert done.returncode == 1 and not (tmp_path / "ran").exists()


@pytest.mark.parametrize("job", ["build", "checks"])
def test_a_tool_the_setup_puts_on_path_is_found_by_the_command_and_nowhere_else(tmp_path, job):
    setup = (
        'mkdir -p "$RUNNER_TEMP/bin"; printf "#!/bin/sh\\necho tool\\n" >"$RUNNER_TEMP/bin/mytool"; '
        'chmod +x "$RUNNER_TEMP/bin/mytool"; export PATH="$RUNNER_TEMP/bin:$PATH"'
    )
    assert run_command(tmp_path, job, setup, 'test "$(mytool)" = tool').returncode == 0
    assert run_command(tmp_path, job, "", "mytool").returncode != 0, "the PATH change does not outlive the step"


@pytest.mark.parametrize("job", ["build", "checks"])
def test_a_hostile_command_is_data_until_the_shell_runs_it_as_the_command(tmp_path, job):
    canary = tmp_path / "pwned"
    done = run_command(tmp_path, job, "", f"echo '$(touch {canary})' >/dev/null")
    assert done.returncode == 0 and not canary.exists(), "no second round of expansion"


# --- the workflow's properties ---------------------------------------------------------------------------------


def strings(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield str(k)
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)
    elif isinstance(node, str):
        yield node


@pytest.mark.parametrize("path", [WORKFLOW, GATE_WORKFLOW], ids=lambda p: p.name)
def test_nothing_continues_on_error_or_ignores_a_failure(path):
    text = path.read_text()
    assert "continue-on-error" not in text
    checked = 0
    for job in yaml.safe_load(text)["jobs"].values():
        for step in job.get("steps") or []:
            if step.get("name") == "Egress canary":
                continue  # its diagnostics are best effort by design; tests/test_egress_canary.py pins the script
            body = step.get("run") or ""
            checked += 1
            assert "|| true" not in body and "|| :" not in body, "a failure swallowed"
            assert "set +e" not in body
    assert checked >= 3


@pytest.mark.parametrize("path", [WORKFLOW, GATE_WORKFLOW], ids=lambda p: p.name)
def test_no_run_script_interpolates_an_expression(path):
    """Every value reaches a script through env. test_workflows holds inputs. and github.event.; this holds the rest."""
    for job_name, job in yaml.safe_load(path.read_text())["jobs"].items():
        for step in job.get("steps") or []:
            body = step.get("run")
            if isinstance(body, str):
                assert "${{" not in body, f"{path.name}:{job_name}: an expression inside a run script"


@pytest.mark.parametrize("path", [WORKFLOW, GATE_WORKFLOW], ids=lambda p: p.name)
def test_nothing_writes_the_actions_path_or_environment_files(path):
    """zizmor `github-env`: a value written there outlives the step and reaches every later one."""
    for job_name, job in yaml.safe_load(path.read_text())["jobs"].items():
        for step in job.get("steps") or []:
            body = step.get("run") or ""
            for forbidden in ("GITHUB_PATH", "GITHUB_ENV"):
                assert forbidden not in body, f"{path.name}:{job_name}: {forbidden}"


def test_caller_commands_reach_the_shell_only_through_env():
    expected = {
        "build": ("Build", {"SETUP": "${{ inputs.setup-command }}", "COMMAND": "${{ inputs.build-command }}"}),
        "checks": (
            "Run the check",
            {"SETUP": "${{ matrix.tools && inputs.setup-command || '' }}", "COMMAND": "${{ matrix.command }}"},
        ),
    }
    for job, (name, env) in expected.items():
        step = next(s for s in job_steps(job) if s.get("name") == name)
        assert step["env"] == env


def test_the_plan_step_takes_every_input_through_env():
    step = next(s for s in job_steps("changes") if s.get("id") == "plan")
    assert all(v.startswith("${{ ") for v in step["env"].values())
    inputs_used = {m for v in step["env"].values() for m in re.findall(r"inputs\.([\w-]+)", v)}
    assert {"jobs", "areas", "build-output-path", "extra-output-path", "cache-pip-files"} <= inputs_used


def test_the_inlined_plan_script_is_the_script_byte_for_byte():
    lines = plan_step().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("python3 -I - ") and line.endswith("<<'PY'"))
    end = max(i for i, line in enumerate(lines) if line == "PY")
    assert "\n".join(lines[start + 1 : end]) + "\n" == SCRIPT.read_text()


def test_the_plan_script_is_standard_library_only():
    imports = set(re.findall(r"^(?:from|import) (\w+)", SCRIPT.read_text(), re.M))
    assert imports <= set(sys.stdlib_module_names), sorted(imports - set(sys.stdlib_module_names))


def test_the_build_is_uploaded_once_for_one_day_with_the_run_attempt_in_the_name():
    doc = yaml.safe_load(WORKFLOW.read_text())
    uploads = [
        (name, s) for name, j in doc["jobs"].items() for s in j["steps"] if "upload-artifact@" in str(s.get("uses"))
    ]
    assert {name for name, _ in uploads} == {"build"}, "only the build job uploads"
    assert len(uploads) == 2
    for _, step in uploads:
        with_ = step["with"]
        assert with_["retention-days"] == "${{ inputs.artifact-retention-days }}"
        assert "${{ github.run_attempt }}" in with_["name"]
        assert with_["include-hidden-files"] is True and with_["if-no-files-found"] == "error"
    inputs = (doc.get(True) or doc.get("on"))["workflow_call"]["inputs"]
    assert inputs["artifact-retention-days"]["default"] == 1


def test_downloads_use_the_same_names_and_paths_as_the_uploads():
    jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
    up = [s["with"] for s in jobs["build"]["steps"] if "upload-artifact@" in str(s.get("uses"))]
    down = [s["with"] for s in jobs["checks"]["steps"] if "download-artifact@" in str(s.get("uses"))]
    assert [(w["name"], w["path"]) for w in up] == [(w["name"], w["path"]) for w in down]


def test_the_artifact_names_come_from_the_validated_plan_not_from_the_input():
    text = WORKFLOW.read_text()
    uses = re.findall(r"^\s+name: (\$\{\{ [^\n]*run_attempt \}\})$", text, re.M)
    assert uses and all("needs.changes.outputs.artifact-name" in u for u in uses)
    assert "inputs.artifact-name" in text and "inputs.build-output-path" in text
    for line in text.splitlines():
        if line.strip().startswith(("path:", "name:")) and "needs.changes" not in line and "inputs." in line:
            pytest.fail(f"an input used unvalidated: {line.strip()}")


def test_every_job_holds_contents_read_and_nothing_more():
    doc = yaml.safe_load(WORKFLOW.read_text())
    assert doc["permissions"] == {"contents": "read"}
    for name, job in doc["jobs"].items():
        assert job["permissions"] in ({"contents": "read"}, {}), name
    assert doc["jobs"]["ci-green"]["permissions"] == {}


def test_the_matrix_does_not_cancel_its_siblings_and_an_empty_list_skips_the_job():
    job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["checks"]
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"] == {"include": "${{ fromJSON(needs.changes.outputs.matrix) }}"}
    assert job["if"] == "${{ needs.changes.outputs.count != '0' }}"
    assert job["needs"] == ["changes", "build"]
    assert job["timeout-minutes"] == "${{ matrix.timeout }}"


def test_every_cache_is_downloads_only_keyed_on_pins_and_off_in_audit():
    doc = yaml.safe_load(WORKFLOW.read_text())
    seen = 0
    for name, job in doc["jobs"].items():
        for step in job["steps"]:
            if "actions/cache@" not in str(step.get("uses")):
                continue
            seen += 1
            assert step["if"].count("== 'block'") == 1 and "(inputs.egress-policy-secretless == 'audit'" in step["if"]
            key, path = step["with"]["key"], step["with"]["path"]
            assert re.fullmatch(
                r"(pip|dl)-\$\{\{ runner\.os \}\}-\$\{\{ needs\.changes\.outputs\.[\w-]+-key \}\}", key
            ), key
            assert path in ("~/.cache/pip", "${{ needs.changes.outputs.tool-path }}")
            assert "restore-keys" not in step["with"], "a prefix match would restore another pin's cache"
            assert "!= ''" in step["if"], f"{name}: a cache with no pin file would key on nothing"
    assert seen == 4


def test_no_cache_holds_the_build_output():
    text = WORKFLOW.read_text()
    assert "output-path }}\n          key" not in text
    for step in (s for j in yaml.safe_load(text)["jobs"].values() for s in j["steps"]):
        if "actions/cache@" in str(step.get("uses")):
            assert "output-path" not in step["with"]["path"]


def test_the_defaults_are_the_measured_ones():
    inputs = (yaml.safe_load(WORKFLOW.read_text()).get(True))["workflow_call"]["inputs"]
    assert inputs["allowed-endpoints"]["default"] == "api.github.com:443 github.com:443"
    assert inputs["egress-policy"]["default"] == "block" and inputs["egress-policy-secretless"]["default"] == "block"
    assert inputs["build-command"]["required"] is True and "default" not in inputs["build-command"]
    assert inputs["jobs"]["required"] is True and "default" not in inputs["jobs"]


def test_the_fixture_exercises_every_leg_kind():
    call = yaml.safe_load((REPO / ".github" / "workflows" / "ci.yml").read_text())["jobs"]["fixture-parallel"]
    assert call["uses"].startswith("./.github/workflows/parallel-ci.yml")
    legs = json.loads(call["with"]["jobs"])
    assert any(leg.get("areas") for leg in legs) and any(leg.get("tools") for leg in legs)
    assert any(leg.get("pip-cache") for leg in legs) and any(leg.get("build") is False for leg in legs)
    assert call["with"]["extra-output-path"] and call["with"]["cache-tool-path"]
    assert "egress-policy" not in call["with"], "the fixture runs the workflow's own defaults"
