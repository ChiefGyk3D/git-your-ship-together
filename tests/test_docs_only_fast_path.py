"""The docs-only fast path, the tofu test matrix and the opt-in pytest-xdist.

Three things share this file because they ship together (issue #331) and one rule runs through all of them:
nothing a caller does not ask for changes, and `CI green` stays honest. Every script is run for real with the
inputs a runner would give it; the workflow YAML is read, and the shell it carries is executed where a test needs
its verdict.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import ci_gate  # noqa: E402
import classify_changes as cc  # noqa: E402

WORKFLOWS = REPO / ".github" / "workflows"
CLASSIFY = REPO / "scripts" / "classify_changes.py"
GATE = REPO / "scripts" / "ci_gate.py"
DOCS = "docs/**\ntests/**\n*.md"


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def step_named(job: dict, prefix: str) -> dict:
    return next(s for s in job["steps"] if str(s.get("name", "")).startswith(prefix))


# --- the glob rules --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("docs/**", "docs/a.md", True),
        ("docs/**", "docs/deep/er/a.png", True),
        ("docs/**", "docsx/a.md", False),
        ("docs/**", "stacks/docs/a.md", False),
        ("*.md", "README.md", True),
        ("*.md", "docs/README.md", False),
        ("**/*.md", "docs/a/README.md", True),
        ("**/*.md", "README.md", True),
        ("*.md", "README.md.tf", False),
        ("tests/*.py", "tests/a.py", True),
        ("tests/*.py", "tests/sub/a.py", False),
        ("a?.md", "ab.md", True),
        ("a?.md", "a/.md", False),
        ("a.b", "aXb", False),
        ("docs/(x)+.md", "docs/(x)+.md", True),
    ],
)
def test_glob_semantics(pattern, path, expected):
    assert bool(cc.glob_to_regex(pattern).fullmatch(path)) is expected


@pytest.mark.parametrize("bad", ["**", "*", "**/*", "/docs/**", "!docs/**", "docs/../stacks/**", "#x", "**/**"])
def test_unsafe_patterns_are_refused(bad):
    with pytest.raises(cc.UsageError):
        cc.compile_patterns(bad, "patterns", True)


def files(*names, **renames):
    out = [{"filename": n, "status": "modified"} for n in names]
    out += [{"filename": new, "previous_filename": old, "status": "renamed"} for new, old in renames.items()]
    return out


def classify(file_list, patterns=DOCS, never=""):
    return cc.classify(
        file_list, cc.compile_patterns(patterns, "patterns", True), cc.compile_patterns(never, "never-skip", False)
    )


def test_docs_and_tests_and_markdown_only_is_docs_only():
    ok, _ = classify(files("docs/a.md", "docs/img/x.png", "tests/test_a.py", "README.md"))
    assert ok


@pytest.mark.parametrize(
    "changed",
    [
        ["docs/a.md", "stacks/00-foundation/main.tf"],  # a mixed PR must run tofu
        ["docs/a.md", "modules/vpc/main.tf"],
        ["stacks/10-access/tests/a.tftest.hcl"],
        ["docs/a.md", ".github/workflows/ci.yml"],  # the rule file itself changed
        [".github/CODEOWNERS"],
        ["docs/a.md", ".github/actions/x/action.yml"],
        ["docs/a.md", "scripts/gen.py"],
        ["docs/a.md", "Makefile"],
        ["docs/../stacks/a.tf"],
    ],
)
def test_anything_else_runs_every_job(changed):
    ok, reason = classify(files(*changed))
    assert not ok, reason


def test_a_rename_out_of_a_code_directory_is_not_docs_only():
    """`git mv stacks/a/main.tf docs/main.tf` deletes code: the old path counts."""
    ok, reason = classify(files(**{"docs/main.tf": "stacks/a/main.tf"}))
    assert not ok and "stacks/a/main.tf" in reason


def test_a_rename_within_docs_is_docs_only():
    ok, _ = classify(files(**{"docs/b.md": "docs/a.md"}))
    assert ok


def test_the_github_directory_is_never_docs_only_even_when_the_patterns_cover_it():
    ok, _ = classify(files(".github/notes.md"), patterns="**/*.md\n.github/**")
    assert not ok


def test_the_callers_never_skip_list_wins_over_the_docs_list():
    ok, _ = classify(files("docs/rules.yaml"), patterns="docs/**", never="docs/rules.yaml")
    assert not ok


def test_no_patterns_and_no_files_are_never_docs_only():
    assert not classify(files("docs/a.md"), patterns="")[0]
    assert not classify([])[0]


def test_a_filename_cannot_break_out_of_the_output_file(tmp_path):
    out = tmp_path / "out"
    os.environ["GITHUB_OUTPUT"] = str(out)
    try:
        ok, reason = classify(files("a.tf\ndocs-only=true"))
        cc.write_outputs(ok, reason, 1)
    finally:
        del os.environ["GITHUB_OUTPUT"]
    lines = out.read_text().splitlines()
    assert [ln.split("=")[0] for ln in lines] == ["docs-only", "reason", "changed"]
    assert lines[0] == "docs-only=false"


# --- the script as the step runs it, with a fake gh ------------------------------------------------------------


def fake_gh(
    tmp_path: Path,
    pr_head: str,
    listing: list[dict],
    fail: bool = False,
    later_head: str | None = None,
    later_changed: int | None = None,
) -> dict:
    """A `gh` on PATH that answers the calls the script makes.

    The pull request metadata is read twice (before and after the file pages); `later_head` and `later_changed`
    are what the second and later reads return, to model a push or a rewrite during the listing."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    first = {"head": {"sha": pr_head}, "changed_files": len(listing)}
    later = {
        "head": {"sha": later_head or pr_head},
        "changed_files": len(listing) if later_changed is None else later_changed,
    }
    (tmp_path / "meta1.json").write_text(json.dumps(first))
    (tmp_path / "meta2.json").write_text(json.dumps(later))
    (tmp_path / "files.json").write_text(json.dumps([listing]))  # --slurp: a list of pages
    gh = bindir / "gh"
    gh.write_text(
        "#!/bin/sh\n"
        + ("echo boom >&2; exit 1\n" if fail else "")
        + 'case "$*" in *--slurp*) cat "$FAKE_DIR/files.json"; exit 0 ;; esac\n'
        + 'n=$(cat "$FAKE_DIR/meta.count" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$FAKE_DIR/meta.count"\n'
        + 'if [ "$n" -eq 1 ]; then cat "$FAKE_DIR/meta1.json"; else cat "$FAKE_DIR/meta2.json"; fi\n'
    )
    gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
    return {"PATH": f"{bindir}:{os.environ['PATH']}", "FAKE_DIR": str(tmp_path)}


def run_classify(
    tmp_path,
    listing,
    *,
    event="pull_request",
    head="a" * 40,
    pr_head="a" * 40,
    count=None,
    fail=False,
    later_head=None,
    later_changed=None,
    extra_env=None,
):
    extra = fake_gh(tmp_path, pr_head, listing, fail, later_head, later_changed)
    out = tmp_path / "gh_output"
    env = {
        **extra,
        "GITHUB_OUTPUT": str(out),
        "CC_EVENT_NAME": event,
        "CC_REPO": "o/r",
        "CC_PR": "7",
        "CC_HEAD_SHA": head,
        "CC_CHANGED_FILES": str(len(listing) if count is None else count),
        "CC_PATTERNS": DOCS,
        "CC_NEVER_SKIP": "",
        "GH_TOKEN": "x",
        **(extra_env or {}),
    }
    done = subprocess.run([sys.executable, "-I", str(CLASSIFY)], env=env, capture_output=True, text=True, timeout=60)
    values = dict(ln.split("=", 1) for ln in out.read_text().splitlines()) if out.exists() else {}
    return done, values


def test_script_docs_only_pull_request(tmp_path):
    done, out = run_classify(tmp_path, files("docs/a.md", "tests/t.py"))
    assert done.returncode == 0 and out["docs-only"] == "true" and out["changed"] == "2"


def test_script_mixed_pull_request_runs_tofu(tmp_path):
    done, out = run_classify(tmp_path, files("docs/a.md", "stacks/00-foundation/main.tf"))
    assert done.returncode == 0 and out["docs-only"] == "false"


@pytest.mark.parametrize("event", ["push", "workflow_dispatch", "schedule", "merge_group", "pull_request_target"])
def test_script_only_a_pull_request_event_can_be_docs_only(tmp_path, event):
    done, out = run_classify(tmp_path, files("docs/a.md"), event=event)
    assert done.returncode == 0 and out["docs-only"] == "false"


def test_script_a_head_that_moved_runs_everything(tmp_path):
    done, out = run_classify(tmp_path, files("docs/a.md"), pr_head="b" * 40)
    assert out["docs-only"] == "false" and "head" in done.stdout


def test_script_a_count_that_disagrees_with_the_event_runs_everything(tmp_path):
    """The event says 3 files changed; the API listed 1: something is hidden, so nothing is skipped."""
    done, out = run_classify(tmp_path, files("docs/a.md"), count=3)
    assert out["docs-only"] == "false"


def test_script_an_unreadable_api_runs_everything_and_does_not_fail_the_job(tmp_path):
    done, out = run_classify(tmp_path, files("docs/a.md"), fail=True)
    assert done.returncode == 0 and out["docs-only"] == "false" and "::warning" in done.stdout


def test_script_a_head_that_moves_during_the_listing_runs_everything(tmp_path):
    """The head read before the pages was right; a push landed while they were fetched: the list is of no commit."""
    done, out = run_classify(tmp_path, files("docs/a.md"), later_head="b" * 40)
    assert out["docs-only"] == "false" and "head" in done.stdout


def test_script_same_count_and_paths_on_a_different_final_head_still_fails_closed(tmp_path):
    listing = files("docs/a.md", "tests/t.py")
    done, out = run_classify(tmp_path, listing, later_head="c" * 40, later_changed=len(listing))
    assert out["docs-only"] == "false"


def test_script_a_final_count_that_differs_from_the_listing_runs_everything(tmp_path):
    done, out = run_classify(tmp_path, files("docs/a.md"), later_changed=2)
    assert out["docs-only"] == "false" and "files" in done.stdout


def test_script_the_test_only_files_override_is_gone(tmp_path):
    """CC_FILES_JSON used to replace the API answer; it must now be ignored, so the real (fake gh) answer decides."""
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(files("docs/a.md")))
    done, out = run_classify(
        tmp_path, files("docs/a.md", "stacks/00-foundation/main.tf"), extra_env={"CC_FILES_JSON": str(forged)}
    )
    assert out["docs-only"] == "false"
    assert "CC_FILES_JSON" not in CLASSIFY.read_text()


def test_script_a_list_at_the_api_limit_runs_everything(tmp_path):
    listing = files(*[f"docs/{i}.md" for i in range(cc.API_FILE_LIMIT)])
    done, out = run_classify(tmp_path, listing)
    assert out["docs-only"] == "false"


def test_script_a_bad_pattern_is_a_loud_failure(tmp_path):
    env = {**os.environ, "CC_PATTERNS": "**", "CC_EVENT_NAME": "pull_request", "GITHUB_OUTPUT": str(tmp_path / "o")}
    done = subprocess.run([sys.executable, "-I", str(CLASSIFY)], env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 1 and "matches every path" in done.stdout


# --- the gate --------------------------------------------------------------------------------------------------


def needs(**results):
    out = {}
    for name, value in results.items():
        if isinstance(value, tuple):
            out[name] = {"result": value[0], "outputs": {"docs-only": value[1]}}
        else:
            out[name] = {"result": value, "outputs": {}}
    return out


def gate(n, required="", skippable="tofu", classifier="classify"):
    return ci_gate.verdict(n, required.split(), skippable.split(), classifier)[0]


def test_gate_all_success_is_green():
    assert gate(needs(classify=("success", "false"), tofu="success", python="success")) == []


def test_gate_a_docs_only_skip_of_the_named_job_is_green():
    problems, notes = ci_gate.verdict(
        needs(classify=("success", "true"), tofu="skipped", python="success"), [], ["tofu"], "classify"
    )
    assert problems == [] and any("tofu" in n for n in notes)


def test_gate_a_skip_without_a_docs_only_verdict_fails():
    assert gate(needs(classify=("success", "false"), tofu="skipped", python="success"))


def test_gate_a_skip_when_the_classifier_failed_or_was_skipped_fails():
    assert gate(needs(classify=("failure", "true"), tofu="skipped"))
    assert gate(needs(classify=("skipped", "true"), tofu="skipped"))
    assert gate(needs(classify=("cancelled", "true"), tofu="skipped"))


def test_gate_a_skip_of_any_other_job_fails_even_on_a_docs_only_change():
    assert gate(needs(classify=("success", "true"), tofu="skipped", python="skipped"))
    assert gate(needs(classify=("success", "true"), tofu="skipped", security="skipped"))


@pytest.mark.parametrize("bad", ["failure", "cancelled", "skipped", None])
def test_gate_any_non_success_result_fails(bad):
    assert gate(needs(classify=("success", "false"), tofu=bad if bad else "failure", python="success")) != []
    assert gate(needs(classify=("success", "false"), tofu="success", python=bad if bad else "failure")) != []


def test_gate_a_failing_tofu_on_a_docs_only_verdict_still_fails():
    assert gate(needs(classify=("success", "true"), tofu="failure"))
    assert gate(needs(classify=("success", "true"), tofu="cancelled"))


def test_gate_a_required_job_missing_from_needs_fails():
    assert gate(needs(classify=("success", "false"), tofu="success"), required="tofu python")


def test_gate_skippable_jobs_without_a_classifier_in_needs_fail():
    assert gate(needs(tofu="skipped"), classifier="")
    assert gate(needs(tofu="success"), classifier="classify")


def test_gate_the_classifier_cannot_skip_itself():
    assert gate(needs(classify=("skipped", "true")), skippable="classify")


def test_gate_without_skippable_jobs_it_is_the_plain_all_success_gate():
    assert gate(needs(a="success", b="skipped"), skippable="", classifier="") != []
    assert gate(needs(a="success", b="success"), skippable="", classifier="") == []


def run_gate(n, **env):
    full = {**os.environ, "GATE_NEEDS": json.dumps(n), **env}
    return subprocess.run([sys.executable, "-I", str(GATE)], env=full, capture_output=True, text=True, timeout=60)


def test_gate_exit_codes():
    ok = run_gate(
        needs(classify=("success", "true"), tofu="skipped"), GATE_SKIPPABLE="tofu", GATE_CLASSIFIER="classify"
    )
    assert ok.returncode == 0
    bad = run_gate(
        needs(classify=("success", "false"), tofu="skipped"), GATE_SKIPPABLE="tofu", GATE_CLASSIFIER="classify"
    )
    assert bad.returncode == 1 and "tofu: skipped" in bad.stdout
    assert run_gate({}).returncode == 1
    assert (
        subprocess.run(
            [sys.executable, "-I", str(GATE)], env={"PATH": os.environ["PATH"]}, capture_output=True, timeout=60
        ).returncode
        == 1
    )


# --- the composite actions are thin wrappers that pass everything by env ---------------------------------------


@pytest.mark.parametrize("name", ["classify-changes", "ci-gate"])
def test_the_actions_pass_inputs_by_env_and_call_their_script(name):
    doc = load(REPO / ".github" / "actions" / name / "action.yml")
    (step,) = doc["runs"]["steps"]
    assert "${{" not in step["run"]
    script = "classify_changes.py" if name == "classify-changes" else "ci_gate.py"
    assert script in step["run"] and "python3 -I" in step["run"]


# --- tofu-ci: the matrix is opt-in and the gate stays honest ---------------------------------------------------


def tofu():
    return load(WORKFLOWS / "tofu-ci.yml")


def test_tofu_matrix_is_off_by_default_and_test_still_is():
    inputs = tofu()[True]["workflow_call"]["inputs"]
    assert inputs["test-matrix"]["default"] is False and inputs["test-matrix"]["type"] == "boolean"
    assert inputs["test"]["default"] is False


def test_tofu_test_job_is_a_matrix_that_never_cancels_its_legs_and_keeps_its_name():
    jobs = tofu()["jobs"]
    test = jobs["test"]
    assert test["strategy"]["fail-fast"] is False
    assert test["needs"] == "test-dirs"
    assert test["name"] == "${{ matrix.leg.name }}"
    assert test["permissions"] == {"contents": "read"}
    assert jobs["test-dirs"]["permissions"] == {}


def run_plan(directories: str, per_directory: str, tmp_path: Path):
    step = step_named(tofu()["jobs"]["test-dirs"], "List the legs")
    out = tmp_path / "out"
    env = {**os.environ, "DIRECTORIES": directories, "PER_DIRECTORY": per_directory, "GITHUB_OUTPUT": str(out)}
    done = subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True, timeout=60)
    legs = None
    if out.exists():
        legs = json.loads(out.read_text().split("legs=", 1)[1].splitlines()[0])
    return done, legs


@pytest.mark.parametrize("per_directory", ["true", "false"])
@pytest.mark.parametrize("bad", ["/tmp", "..", "a/../b", "./a/..", "a//b", "-x", "ok /tmp", "a/"])
def test_tofu_directories_must_stay_inside_the_repository_in_both_modes(tmp_path, bad, per_directory):
    done, legs = run_plan(bad, per_directory, tmp_path)
    assert done.returncode != 0 and legs is None and "::error::" in done.stdout


def test_tofu_the_default_and_nested_directories_are_accepted(tmp_path):
    done, legs = run_plan(". stacks/aws/00-foundation modules/a_b.c", "true", tmp_path)
    assert done.returncode == 0 and [leg["dirs"] for leg in legs] == [".", "stacks/aws/00-foundation", "modules/a_b.c"]


def test_tofu_off_is_one_leg_named_test_holding_every_directory(tmp_path):
    done, legs = run_plan("a b  c", "false", tmp_path)
    assert done.returncode == 0 and legs == [{"dirs": "a b c", "name": "test"}]


def test_tofu_on_is_one_leg_per_directory(tmp_path):
    done, legs = run_plan("stacks/a modules/b", "true", tmp_path)
    assert done.returncode == 0
    assert legs == [
        {"dirs": "stacks/a", "name": "test (stacks/a)"},
        {"dirs": "modules/b", "name": "test (modules/b)"},
    ]


@pytest.mark.parametrize("bad", ["", "   ", "-rf", "a;b", "a$(x)", 'a"b'])
def test_tofu_a_bad_directory_list_fails_the_job(tmp_path, bad):
    done, legs = run_plan(bad, "true", tmp_path)
    assert done.returncode != 0 and legs is None


def run_tofu_gate(results: dict, test_requested: bool):
    step = step_named(tofu()["jobs"]["ci-green"], "Every job passed")
    needs_json = {k: {"result": v, "outputs": {}} for k, v in results.items()}
    env = {
        **os.environ,
        "RESULTS": json.dumps(needs_json),
        "TEST_REQUESTED": "true" if test_requested else "false",
    }
    return subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True, timeout=60)


BASE = {"fmt": "success", "validate": "success", "tflint": "success", "trivy": "success", "plan": "skipped"}


def test_tofu_gate_green_when_every_leg_passed():
    assert run_tofu_gate({**BASE, "test-dirs": "success", "test": "success"}, True).returncode == 0


@pytest.mark.parametrize("bad", ["failure", "cancelled", "skipped"])
def test_tofu_gate_fails_on_a_failed_cancelled_or_missing_matrix_result(bad):
    """GitHub reports a matrix job as failure when any leg failed and cancelled when any was cancelled; a leg that
    never ran leaves the job skipped (list job failed) or absent. None may pass when tests were asked for."""
    done = run_tofu_gate({**BASE, "test-dirs": "success", "test": bad}, True)
    assert done.returncode == 1 and "test" in done.stdout
    done = run_tofu_gate({**BASE, "test-dirs": bad, "test": "skipped"}, True)
    assert done.returncode == 1


def test_tofu_gate_a_skipped_test_is_fine_only_when_tests_were_not_asked_for():
    assert run_tofu_gate({**BASE, "test-dirs": "skipped", "test": "skipped"}, False).returncode == 0
    assert run_tofu_gate({**BASE, "test-dirs": "skipped", "test": "skipped"}, True).returncode == 1


def test_tofu_gate_a_job_missing_from_the_needs_cannot_hide():
    gate_job = tofu()["jobs"]["ci-green"]
    assert set(gate_job["needs"]) == set(tofu()["jobs"]) - {"ci-green"}
    assert "test-dirs" in gate_job["needs"]


def test_tofu_gate_other_failures_still_fail():
    assert (
        run_tofu_gate({**BASE, "validate": "failure", "test-dirs": "success", "test": "success"}, True).returncode == 1
    )


# --- python-ci: xdist is opt-in and touches only pytest --------------------------------------------------------


def python_ci():
    return load(WORKFLOWS / "python-ci.yml")


def test_xdist_is_off_by_default_with_a_pinned_version():
    inputs = python_ci()[True]["workflow_call"]["inputs"]
    assert inputs["xdist"]["default"] is False and inputs["xdist"]["type"] == "boolean"
    assert inputs["xdist-workers"]["default"] == "auto"
    assert "xdist-version" not in inputs, "a free-form version cannot coexist with the hash lock"


def test_xdist_reaches_pytest_through_the_environment_not_the_callers_command():
    job = python_ci()["jobs"]["test"]
    run = step_named(job, "Run tests")
    assert run["run"] == 'bash -eo pipefail -c "$COMMAND"', "the caller's command must run exactly as written"
    expr = run["env"]["PYTEST_ADDOPTS"]
    assert "inputs.xdist" in expr and "format('-n {0}', inputs.xdist-workers)" in expr and expr.endswith("|| '' }}")
    install = step_named(job, "Install pytest-xdist")
    assert install["if"] == "inputs.xdist"
    names = [s.get("name") for s in job["steps"]]
    assert names.index("Install dependencies") < names.index("Install pytest-xdist") < names.index("Run tests")


def run_xdist_install(tmp_path, workers):
    """The real step under bash, with a `python` that records its arguments and the requirements file it was given."""
    step = step_named(python_ci()["jobs"]["test"], "Install pytest-xdist")
    stub = 'python() { echo "pip: $*"; cat "$RUNNER_TEMP/xdist-requirements.txt"; }; export -f python;'
    env = {**os.environ, **step["env"], "WORKERS": workers, "RUNNER_TEMP": str(tmp_path)}
    return subprocess.run(["bash", "-c", stub + step["run"]], env=env, capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize("workers", ["auto", "logical", "4", "16"])
def test_xdist_accepts_a_worker_count_and_installs_only_from_the_hash_lock(tmp_path, workers):
    done = run_xdist_install(tmp_path, workers)
    assert done.returncode == 0
    assert "pip: -m pip install --require-hashes --no-deps --only-binary=:all: -r" in done.stdout
    assert "pytest-xdist==3.8.0" in done.stdout and "execnet==" in done.stdout


@pytest.mark.parametrize("workers", ["0", "auto --foo", "-n 4", "", "4;id", "$(id)"])
def test_xdist_refuses_anything_pytest_could_read_as_another_option(tmp_path, workers):
    done = run_xdist_install(tmp_path, workers)
    assert done.returncode == 1 and "pip:" not in done.stdout


def test_xdist_is_installed_with_require_hashes_from_the_lock_and_no_input_reaches_pip():
    step = step_named(python_ci()["jobs"]["test"], "Install pytest-xdist")
    run = step["run"]
    assert "--require-hashes" in run and "--no-deps" in run and "--only-binary=:all:" in run
    assert "inputs." not in run and "VERSION" not in str(step["env"]) and "REQUESTED" not in str(step["env"])
    lock = (REPO / ".github" / "requirements" / "pytest-xdist.txt").read_text()
    assert step["env"]["REQUIREMENTS"] == lock, "run scripts/tool_locks.py"
    assert (REPO / ".github" / "requirements" / "pytest-xdist.in").read_text().strip() == "pytest-xdist==3.8.0"
    entries = [e for e in re.split(r"\n(?=[A-Za-z0-9])", "\n".join(ln for ln in lock.splitlines() if ln[:1] != "#"))]
    assert {e.split("==")[0] for e in entries} == {"pytest-xdist", "execnet"}, "xdist and its one dependency, no pytest"
    for entry in entries:
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", entry), f"no hash: {entry.splitlines()[0]}"


def test_a_default_caller_sees_an_empty_addopts():
    """With xdist off the expression is `false && ... || ''`: the empty string, so PYTEST_ADDOPTS adds nothing."""
    expr = step_named(python_ci()["jobs"]["test"], "Run tests")["env"]["PYTEST_ADDOPTS"]
    assert expr.startswith("${{ inputs.xdist && ") and expr.endswith(" || '' }}")


def test_gate_an_empty_or_malformed_needs_input_fails_with_a_clear_message():
    for raw, words in [
        ("", "is empty"),
        ("   ", "is empty"),
        ("not json", "cannot read"),
        ("[]", "JSON object"),
        ("{}", "JSON object"),
    ]:
        done = subprocess.run(
            [sys.executable, "-I", str(GATE)],
            env={"PATH": os.environ["PATH"], "GATE_NEEDS": raw},
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert done.returncode == 1 and "::error title=ci-gate::" in done.stdout and words in done.stdout, raw


def test_gate_a_needs_entry_that_is_not_an_object_fails_without_a_traceback():
    done = run_gate({"a": "success"})
    assert done.returncode == 1 and "Traceback" not in done.stderr


def test_the_ci_gate_needs_input_has_no_default_and_no_expression():
    doc = load(REPO / ".github" / "actions" / "ci-gate" / "action.yml")
    spec = doc["inputs"]["needs"]
    assert spec["required"] is True and "default" not in spec
    assert "${{" not in spec["description"]
