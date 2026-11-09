"""security.yml `gitleaks-scope`: scope the secret scan of a pull request to the pull request (issue #260).

The scan used to run over every ref, so one key-shaped fixture on an unmerged branch turned the scan red on every
other pull request. `pr-commits` (the default) narrows a pull request's history scan to `base..head` and adds a scan
of the checked-out tree; `all-refs` is the opt-in for the old every-ref scan. Only the `pull_request` event ever
narrows: push, schedule, workflow_dispatch and everything else scan the full history whatever the input says, so a
branch protection against a leak entering the default branch never gets weaker. An unknown value fails the job
(fail closed).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
from urllib.request import Request, urlopen

import pytest
from test_workflows import README, REPO, WORKFLOWS, jobs, load, steps_of, triggers

DOC = load(WORKFLOWS / "security.yml")
INPUTS = triggers(DOC)["workflow_call"]["inputs"]
GITLEAKS = jobs(DOC)["gitleaks"]
VALIDATE = "Validate the gitleaks-scope input"
RESOLVE = "Resolve the gitleaks scan scope"
CANARY = "Check that the scan catches a planted key"
COMMITS = "Scan the commits (gitleaks)"
TREE = "Scan the working tree (gitleaks)"

INVALID = [
    "",
    " ",
    "\n",
    "PR-COMMITS",
    "Pr-Commits",
    "ALL-REFS",
    "All-Refs",
    "pr-commits ",
    " all-refs",
    "all-refs\n",
    "pr-commits\nall-refs",
    "pr_commits",
    "all",
    "all-refs,pr-commits",
    "true",
    "false",
    "none",
    "--all",
    "$(id)",
    "`id`",
    "${{ inputs.gitleaks }}",
    "${GITLEAKS_SCOPE}",
    "all-refs​",  # zero-width space
    "all-rеfs",  # Cyrillic e
]
PLAIN_ARGS = "--redact --no-banner --exit-code 1"
EVENTS = ["pull_request", "push", "schedule", "workflow_dispatch", "pull_request_target", "merge_group", "release", ""]


def step(name: str) -> dict:
    return next(s for s in steps_of(GITLEAKS) if s.get("name") == name)


def sh(*args: str, cwd) -> str:
    done = subprocess.run(
        list(args),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )
    return done.stdout.strip()


def commit(repo, name: str, content: str | None, message: str) -> str:
    if content is None:
        sh("git", "rm", "-q", name, cwd=repo)
    else:
        (repo / name).write_text(content)
        sh("git", "add", name, cwd=repo)
    sh("git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", "commit", "-q", "-m", message, cwd=repo)
    return sh("git", "rev-parse", "HEAD", cwd=repo)


def planted() -> str:
    # Built at run time so no credential-shaped literal sits in this file.
    return "aws_access_key_id = {}{}\naws_secret_access_key = {}\n".format(
        "AKIA", "IOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzq3x9KpZmQ"
    )


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    """base (clean) <- head (clean); a sibling branch carries a key and is not part of the pull request."""
    r = tmp_path_factory.mktemp("scope-repo")
    sh("git", "init", "-q", "-b", "main", cwd=r)
    base = commit(r, "a.txt", "one\n", "base")
    sh("git", "checkout", "-q", "-b", "pr", cwd=r)
    head = commit(r, "b.txt", "two\n", "head")
    sh("git", "checkout", "-q", "-b", "elsewhere", base, cwd=r)
    commit(r, "leak.txt", planted(), "an unmerged fixture")
    sh("git", "checkout", "-q", "pr", cwd=r)
    return r, base, head


def run_step(name: str, env: dict, cwd=None, out=None):
    prefixes = (
        "GITLEAKS_",
        "TREE_SCAN",
        "SCAN_ARGS",
        "EVENT_NAME",
        "BASE_SHA",
        "HEAD_SHA",
        "HASH_MANIFEST",
        "RUNNER_TEMP",
        "GITHUB_WORKSPACE",
    )
    clean = {k: v for k, v in os.environ.items() if not k.startswith(prefixes)}
    if out is not None:
        clean["GITHUB_OUTPUT"] = str(out)
    clean.update(env)
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step(name)["run"]],
        capture_output=True,
        text=True,
        env=clean,
        cwd=cwd or REPO,
        timeout=60,
    )


def core(out: dict) -> dict:
    return {k: out[k] for k in ("log_opts", "tree")}


def resolve(repo_info, scope: str, event: str, tmp_path, base=None, head=None, paths=None):
    r, b, h = repo_info
    out = tmp_path / "out"
    out.write_text("")
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir(exist_ok=True)
    done = run_step(
        RESOLVE,
        {
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_WORKSPACE": str(r),
            "GITLEAKS_SCOPE": scope,
            "EVENT_NAME": event,
            "BASE_SHA": b if base is None else base,
            "HEAD_SHA": h if head is None else head,
            **({} if paths is None else {"HASH_MANIFEST_PATHS": paths}),
        },
        cwd=r,
        out=out,
    )
    return done, dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)


# --- the input ----------------------------------------------------------------


def test_the_input_is_a_string_that_defaults_to_the_pull_request_range():
    spec = INPUTS["gitleaks-scope"]
    assert spec["type"] == "string"
    assert spec["default"] == "pr-commits", "a caller that sets nothing scans only its pull request's commits"
    assert "pr-commits" in spec["description"] and "all-refs" in spec["description"]


def test_the_input_is_documented_in_the_readme_and_the_default_is_stated():
    text = README.read_text()
    row = next((line for line in text.splitlines() if line.startswith("| `gitleaks-scope` |")), "")
    assert row, "gitleaks-scope is not documented in the README"
    assert "`all-refs`" in row and "pr-commits" in row and "default" in row.lower()
    assert row.split("|")[2].strip() == "`pr-commits`", "the README states the real default"


# --- the validate step ----------------------------------------------------------


def test_the_validate_step_runs_before_anything_that_uses_the_value():
    names = [s.get("name") for s in steps_of(GITLEAKS)]
    assert names.index(VALIDATE) < names.index(RESOLVE) < names.index(CANARY) < names.index(COMMITS)
    assert str(steps_of(GITLEAKS)[0].get("uses", "")).startswith("step-security/harden-runner@")
    checkout = next(
        i for i, s in enumerate(steps_of(GITLEAKS)) if str(s.get("uses", "")).startswith("actions/checkout@")
    )
    assert 0 < names.index(VALIDATE) < checkout, "validate after harden-runner, before the clone is fetched"
    s = step(VALIDATE)
    assert "if" not in s and s["env"] == {"GITLEAKS_SCOPE": "${{ inputs.gitleaks-scope }}"}


@pytest.mark.parametrize("value", ["pr-commits", "all-refs"])
def test_validate_accepts_exactly_the_two_values(value):
    done = run_step(VALIDATE, {"GITLEAKS_SCOPE": value})
    assert done.returncode == 0, done.stderr + done.stdout


@pytest.mark.parametrize("value", INVALID)
def test_validate_rejects_every_other_value(value):
    done = run_step(VALIDATE, {"GITLEAKS_SCOPE": value})
    assert done.returncode == 1, repr(value)
    assert "::error title=gitleaks-scope::" in done.stdout
    assert "pr-commits" in done.stdout and "all-refs" in done.stdout
    if value.strip():
        assert value not in done.stdout.replace("pr-commits", "").replace("all-refs", ""), "the value is not echoed"


def test_validate_rejects_an_unset_value():
    done = run_step(VALIDATE, {})
    assert done.returncode == 1 and "::error title=gitleaks-scope::" in done.stdout


# --- the decision table: event x input -> effective log-opts ----------------------


@pytest.mark.parametrize("event", EVENTS)
def test_all_refs_is_always_the_full_history(event, repo, tmp_path):
    done, out = resolve(repo, "all-refs", event, tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert core(out) == {"log_opts": "--all", "tree": "false"}


@pytest.mark.parametrize("event", [e for e in EVENTS if e != "pull_request"])
def test_pr_commits_never_narrows_outside_a_pull_request(event, repo, tmp_path):
    # push (the default branch included), schedule, workflow_dispatch, any other event: full history, whatever is set.
    done, out = resolve(repo, "pr-commits", event, tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert core(out) == {"log_opts": "--all", "tree": "false"}


def test_pr_commits_on_a_pull_request_scans_base_to_head_and_the_tree(repo, tmp_path):
    _, base, head = repo
    done, out = resolve(repo, "pr-commits", "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert core(out) == {"log_opts": f"{base}..{head}", "tree": "true"}


@pytest.mark.parametrize("event", EVENTS)
def test_the_declared_default_resolves_like_pr_commits_for_every_event(event, repo, tmp_path):
    # What a caller that sets nothing gets: the default value is fed to the resolve step as-is.
    default = INPUTS["gitleaks-scope"]["default"]
    _, base, head = repo
    done, out = resolve(repo, default, event, tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    if event == "pull_request":
        assert core(out) == {"log_opts": f"{base}..{head}", "tree": "true"}
    else:
        assert core(out) == {"log_opts": "--all", "tree": "false"}, "push, schedule and the rest keep the full history"


def test_all_refs_stays_available_as_the_opt_in(repo, tmp_path):
    done, out = resolve(repo, "all-refs", "pull_request", tmp_path)
    assert done.returncode == 0 and core(out) == {"log_opts": "--all", "tree": "false"}


def test_the_decision_table_in_one_place(repo, tmp_path):
    _, base, head = repo
    table = {}
    for event in ("pull_request", "push", "schedule", "workflow_dispatch"):
        for scope in ("pr-commits", "all-refs"):
            done, out = resolve(repo, scope, event, tmp_path)
            assert done.returncode == 0
            table[(event, scope)] = out["log_opts"]
    assert table == {
        ("pull_request", "pr-commits"): f"{base}..{head}",
        ("pull_request", "all-refs"): "--all",
        ("push", "pr-commits"): "--all",
        ("push", "all-refs"): "--all",
        ("schedule", "pr-commits"): "--all",
        ("schedule", "all-refs"): "--all",
        ("workflow_dispatch", "pr-commits"): "--all",
        ("workflow_dispatch", "all-refs"): "--all",
    }


@pytest.mark.parametrize("event", EVENTS)
@pytest.mark.parametrize("value", INVALID)
def test_resolve_fails_closed_on_an_unknown_value_for_every_event(event, value, repo, tmp_path):
    done, out = resolve(repo, value, event, tmp_path)
    assert done.returncode == 1, (event, value)
    assert "log_opts" not in out, "an unknown value must not leave a narrowed scope behind"


def test_resolve_with_no_value_at_all_fails_closed(repo, tmp_path):
    r, _, _ = repo
    done = run_step(RESOLVE, {"EVENT_NAME": "push"}, cwd=r, out=tmp_path / "o")
    assert done.returncode == 1


@pytest.mark.parametrize(
    "base,head",
    [
        ("", None),
        (None, ""),
        ("not-a-sha", None),
        (None, "HEAD"),
        (None, "main"),
        ("0" * 40, None),  # well formed, not in the clone
        (None, "f" * 40),
        ("$(id)", None),
        (None, "abc; id"),
        ("-" + "a" * 39, None),
        (None, "a" * 39),
        (None, "A" * 40),  # upper case is not what the API sends
    ],
)
def test_pr_commits_fails_closed_when_an_end_of_the_range_is_unusable(base, head, repo, tmp_path):
    done, out = resolve(repo, "pr-commits", "pull_request", tmp_path, base=base, head=head)
    assert done.returncode == 1, (base, head)
    assert "::error title=gitleaks-scope::" in done.stdout
    assert "log_opts" not in out, "it must not fall back to a narrower or empty scope"


def test_pr_commits_does_not_need_good_shas_outside_a_pull_request(repo, tmp_path):
    done, out = resolve(repo, "pr-commits", "push", tmp_path, base="", head="")
    assert done.returncode == 0 and out["log_opts"] == "--all"


# --- no expression injection ------------------------------------------------------


def test_the_new_steps_read_every_value_from_env_never_from_an_expression():
    for name in (VALIDATE, RESOLVE, CANARY, COMMITS, TREE):
        body = step(name)["run"]
        assert "${{" not in body, f"{name}: an expression inside run:"
        assert "eval " not in body and "bash -c" not in body
    assert step(RESOLVE)["env"] == {
        "GITLEAKS_SCOPE": "${{ inputs.gitleaks-scope }}",
        "EVENT_NAME": "${{ github.event_name }}",
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "HASH_MANIFEST_PATHS": "${{ inputs.gitleaks-hash-manifest-paths }}",
    }
    assert step(COMMITS)["env"] == {
        "LOG_OPTS": "${{ steps.scope.outputs.log_opts }}",
        "SCAN_ARGS": "${{ steps.scope.outputs.scan_args }}",
    }
    assert step(COMMITS)["run"].count('--log-opts="$LOG_OPTS"') == 1
    assert '--log-opts="--all"' not in step(COMMITS)["run"]


# --- the scans are wired as designed ---------------------------------------------


def test_the_tree_scan_runs_only_for_a_narrowed_pull_request_and_even_after_a_failed_history_scan():
    s = step(TREE)
    assert s["if"] == "always() && steps.scope.outputs.tree == 'true'"
    assert 'gitleaks dir "${args[@]}" .' in s["run"]
    assert step(RESOLVE)["id"] == "scope"
    names = [x.get("name") for x in steps_of(GITLEAKS)]
    assert names.index(COMMITS) < names.index(TREE)
    assert "if" not in step(COMMITS), "the history scan is never conditional"


def test_the_clone_has_both_ends_of_the_range():
    checkout = next(s for s in steps_of(GITLEAKS) if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["fetch-depth"] == 0, "base and head must both be present, so the whole history is fetched"
    assert "git cat-file -e" in step(RESOLVE)["run"]


# --- the canary keeps working in both modes ----------------------------------------


def test_the_canary_follows_the_resolved_scope():
    s = step(CANARY)
    assert s["env"] == {
        "TREE_SCAN": "${{ steps.scope.outputs.tree }}",
        "SCAN_ARGS": "${{ steps.scope.outputs.scan_args }}",
    }
    assert '"$status" -ne 1' in s["run"]


def test_canary_and_real_scans_use_the_one_argument_list_built_in_the_resolve_step():
    # G3-2: one constructed list (config, ignore file, redact, exit code) for the canary and for both real scans.
    for name in (CANARY, COMMITS, TREE):
        assert "$SCAN_ARGS" in step(name)["run"], name
        assert step(name)["env"]["SCAN_ARGS"] == "${{ steps.scope.outputs.scan_args }}"
    for name in (COMMITS, TREE):
        assert "--redact" not in step(name)["run"] and "--exit-code" not in step(name)["run"], name
    canary = step(CANARY)["run"]
    assert "--report-format sarif" in canary and "--log-opts=" in canary
    scans = [line for line in canary.splitlines() if "must_catch " in line and "gitleaks" in line]
    assert len(scans) == 3 and all(line.endswith(" .") for line in scans), "the canary scans . like the real scan"


# --- against the real, pinned binary (needs the network) ----------------------------


@pytest.fixture(scope="module")
def gitleaks(tmp_path_factory):
    version, sha = INPUTS["gitleaks-version"]["default"], INPUTS["gitleaks-sha256"]["default"]
    url = f"https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_linux_x64.tar.gz"
    try:
        data = urlopen(Request(url), timeout=60).read()
    except OSError as err:
        pytest.skip(f"no network: {err}")
    assert hashlib.sha256(data).hexdigest() == sha, "the pinned sha256 does not match the release asset"
    bindir = tmp_path_factory.mktemp("gitleaks-bin")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        member = tar.extractfile(tar.getmember("gitleaks"))
        assert member is not None
        (bindir / "gitleaks").write_bytes(member.read())
    (bindir / "gitleaks").chmod(0o755)
    return str(bindir / "gitleaks")


def scan(binary: str, repo, log_opts: str) -> int:
    done = subprocess.run(
        [binary, "git", "--redact", "--no-banner", "--exit-code", "1", f"--log-opts={log_opts}", str(repo)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return done.returncode


def scan_tree(binary: str, repo) -> int:
    done = subprocess.run(
        [binary, "dir", "--redact", "--no-banner", "--exit-code", "1", "."], cwd=repo, capture_output=True, text=True
    )
    return done.returncode


def test_narrowing_bites_and_all_refs_still_sees_the_unmerged_branch(gitleaks, repo):
    r, base, head = repo
    assert scan(gitleaks, r, "--all") == 1, "the key on the unmerged branch is found by the full scan"
    assert scan(gitleaks, r, f"{base}..{head}") == 0, "...and is not part of this pull request"


def test_a_secret_added_and_reverted_inside_the_pull_request_stays_covered(gitleaks, tmp_path):
    r = tmp_path
    sh("git", "init", "-q", "-b", "main", cwd=r)
    base = commit(r, "a.txt", "one\n", "base")
    commit(r, "leak.txt", planted(), "add a key")
    head = commit(r, "leak.txt", None, "revert the key")
    assert not (r / "leak.txt").exists(), "the tree at the head is clean"
    assert scan(gitleaks, r, f"{base}..{head}") == 1, "the history of the range still holds it"


def test_a_secret_already_in_the_base_history_is_outside_the_range(gitleaks, tmp_path):
    # The documented residual: such a commit is the push scan's to catch, not the pull request's.
    r = tmp_path
    sh("git", "init", "-q", "-b", "main", cwd=r)
    commit(r, "leak.txt", planted(), "key already on the base")
    base = commit(r, "a.txt", "one\n", "base")
    head = commit(r, "b.txt", "two\n", "head")
    assert scan(gitleaks, r, f"{base}..{head}") == 0
    assert scan(gitleaks, r, "--all") == 1


def test_a_key_on_a_branch_cut_before_the_base_moved_is_still_in_the_range(gitleaks, tmp_path):
    r = tmp_path
    sh("git", "init", "-q", "-b", "main", cwd=r)
    commit(r, "a.txt", "one\n", "old")
    sh("git", "checkout", "-q", "-b", "pr", cwd=r)
    commit(r, "leak.txt", planted(), "key on the branch")
    head = commit(r, "c.txt", "three\n", "later work")
    sh("git", "checkout", "-q", "main", cwd=r)
    base = commit(r, "b.txt", "two\n", "base moved on")
    assert scan(gitleaks, r, f"{base}..{head}") == 1


def test_the_tree_scan_sees_a_key_in_a_file_and_ignores_git_history(gitleaks, tmp_path):
    r = tmp_path
    sh("git", "init", "-q", "-b", "main", cwd=r)
    commit(r, "leak.txt", planted(), "key")
    assert scan_tree(gitleaks, r) == 1, "the tree scan fails on a key in a file"
    (r / "leak.txt").write_text("clean\n")
    assert scan_tree(gitleaks, r) == 0, "...and does not read the history in .git"


@pytest.mark.parametrize("tree_scan", ["false", "true"])
def test_the_canary_passes_in_both_modes_with_the_real_binary(gitleaks, tree_scan):
    env = {
        **os.environ,
        "PATH": f"{os.path.dirname(gitleaks)}:{os.environ['PATH']}",
        "TREE_SCAN": tree_scan,
        "SCAN_ARGS": PLAIN_ARGS,
    }
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step(CANARY)["run"]], env=env, capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("tree_scan", ["false", "true"])
def test_the_canary_fails_when_the_scanner_catches_nothing(tree_scan, tmp_path):
    # A stand-in scanner that exits 0 on everything: the canary must refuse to trust it, in both modes.
    fake = tmp_path / "gitleaks"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "TREE_SCAN": tree_scan, "SCAN_ARGS": PLAIN_ARGS}
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step(CANARY)["run"]], env=env, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 1 and "was not caught" in done.stdout


# --- G3-1: the scan's configuration comes from the base of a pull request ----------------


ALLOW_ALL = (
    '[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "hide it"\nregexes = ["AKIA[A-Z0-9]+"]\n'
    'paths = ["leak\\\\.txt"]\ncondition = "OR"\n'
)


def cfg_repo(tmp_path, base_files: dict, head_files: dict):
    r = tmp_path / "cfg-repo"
    r.mkdir()
    sh("git", "init", "-q", "-b", "main", cwd=r)
    for name, body in {"a.txt": "one\n", **base_files}.items():
        (r / name).write_text(body)
        sh("git", "add", name, cwd=r)
    sh("git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", "commit", "-q", "-m", "base", cwd=r)
    base = sh("git", "rev-parse", "HEAD", cwd=r)
    sh("git", "checkout", "-q", "-b", "pr", cwd=r)
    for name, body in head_files.items():
        (r / name).write_text(body)
        sh("git", "add", name, cwd=r)
    sh(
        "git",
        "-c",
        "user.email=ci@example.invalid",
        "-c",
        "user.name=ci",
        "commit",
        "--allow-empty",
        "-q",
        "-m",
        "head",
        cwd=r,
    )
    return r, base, sh("git", "rev-parse", "HEAD", cwd=r)


def scan_args_of(out: dict) -> dict:
    """The option=value pairs of the resolved argument list (the plain flags are checked separately)."""
    return dict(p.split("=", 1) for p in out["scan_args"].split() if p.startswith("--") and "=" in p)


@pytest.mark.parametrize("scope", ["all-refs", "pr-commits"])
def test_a_pull_request_scans_with_the_configuration_of_its_base_not_its_head(scope, tmp_path):
    info = cfg_repo(
        tmp_path,
        {".gitleaks.toml": "title = 'base config'\n[extend]\nuseDefault = true\n", ".gitleaksignore": "base-ignore\n"},
        {".gitleaks.toml": ALLOW_ALL, ".gitleaksignore": "head-ignore\n"},
    )
    done, out = resolve(info, scope, "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    args = scan_args_of(out)
    assert open(args["--config"]).read() == "title = 'base config'\n[extend]\nuseDefault = true\n"
    assert open(args["--gitleaks-ignore-path"] + "/.gitleaksignore").read() == "base-ignore\n"
    assert str(info[0]) not in args["--config"] and str(info[0]) not in args["--gitleaks-ignore-path"]
    assert (info[0] / ".gitleaks.toml").read_text() == ALLOW_ALL, "the checkout still holds the head's file"


def test_a_pull_request_whose_base_has_no_config_gets_the_defaults_not_the_heads_file(tmp_path):
    info = cfg_repo(tmp_path, {}, {".gitleaks.toml": ALLOW_ALL, ".gitleaksignore": "head-ignore\n"})
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    args = scan_args_of(out)
    assert "useDefault = true" in open(args["--config"]).read() and "hide it" not in open(args["--config"]).read()
    assert open(args["--gitleaks-ignore-path"] + "/.gitleaksignore").read() == ""


@pytest.mark.parametrize("event", [e for e in EVENTS if e != "pull_request"])
def test_other_events_keep_the_checked_out_configuration(event, tmp_path):
    info = cfg_repo(tmp_path, {".gitleaks.toml": "title = 'base'\n"}, {".gitleaks.toml": "title = 'head'\n"})
    done, out = resolve(info, "all-refs", event, tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert scan_args_of(out) == {"--config": str(info[0] / ".gitleaks.toml")}, "as today: the checkout's own file"
    (tmp_path / "x").mkdir()
    bare = cfg_repo(tmp_path / "x", {}, {})
    done, out = resolve(bare, "all-refs", event, tmp_path)
    assert scan_args_of(out) == {}, "no file, no option: the scanner defaults, as today"


def test_the_common_arguments_are_the_same_everywhere(tmp_path):
    info = cfg_repo(tmp_path, {}, {})
    for event in ("pull_request", "push"):
        done, out = resolve(info, "all-refs", event, tmp_path)
        assert out["scan_args"].startswith(PLAIN_ARGS), out["scan_args"]


def test_an_unusable_runner_temp_path_fails_closed(tmp_path):
    info = cfg_repo(tmp_path, {}, {})
    out = tmp_path / "o"
    done = run_step(
        RESOLVE,
        {
            "RUNNER_TEMP": str(tmp_path / "has space"),
            "GITHUB_WORKSPACE": str(info[0]),
            "GITLEAKS_SCOPE": "all-refs",
            "EVENT_NAME": "pull_request",
            "BASE_SHA": info[1],
            "HEAD_SHA": info[2],
        },
        cwd=info[0],
        out=out,
    )
    assert done.returncode == 1 and "::error title=gitleaks-scope::" in done.stdout


def test_the_attack_works_with_the_heads_config_and_fails_with_the_resolved_arguments(gitleaks, tmp_path):
    """A PR adds a key and a config that allowlists it. The head's config hides it; the base's config does not."""
    info = cfg_repo(
        tmp_path,
        {".gitleaks.toml": "title = 'base'\n[extend]\nuseDefault = true\n"},
        {".gitleaks.toml": ALLOW_ALL, "leak.txt": planted()},
    )
    r = info[0]
    head_cfg = subprocess.run(
        [gitleaks, "dir", "--redact", "--no-banner", "--exit-code", "1", "."], cwd=r, capture_output=True, text=True
    )
    assert head_cfg.returncode == 0, "the premise: the head's own config really hides its key"
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    for cmd in (["dir"], ["git", f"--log-opts={out['log_opts']}"]):
        fixed = subprocess.run(
            [gitleaks, cmd[0], *out["scan_args"].split(), *cmd[1:], "."], cwd=r, capture_output=True, text=True
        )
        assert fixed.returncode == 1, (cmd, fixed.stdout + fixed.stderr)


def test_the_base_defaults_config_catches_a_key_and_an_empty_ignore_file_hides_nothing(gitleaks, tmp_path):
    info = cfg_repo(tmp_path, {}, {".gitleaks.toml": ALLOW_ALL, "leak.txt": planted()})
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path)
    fixed = subprocess.run(
        [gitleaks, "dir", *out["scan_args"].split(), "."], cwd=info[0], capture_output=True, text=True
    )
    assert fixed.returncode == 1, fixed.stdout + fixed.stderr


def test_a_config_that_hides_the_planted_key_fails_the_canary(gitleaks, tmp_path):
    cfg = tmp_path / "hide.toml"
    cfg.write_text(ALLOW_ALL.replace('paths = ["leak\\\\.txt"]', 'paths = ["planted\\\\.txt"]'))
    env = {
        **os.environ,
        "PATH": f"{os.path.dirname(gitleaks)}:{os.environ['PATH']}",
        "TREE_SCAN": "true",
        "SCAN_ARGS": f"{PLAIN_ARGS} --config={cfg}",
    }
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step(CANARY)["run"]], env=env, capture_output=True, text=True, timeout=120
    )
    assert done.returncode == 1 and "was not caught" in done.stdout, done.stdout + done.stderr


# --- the root .gitleaksignore of the scanned tree (measured with the pinned binary) ------------------------------


def ignore_for(gitleaks: str, r) -> str:
    """The fingerprints that would hide leak.txt in `r` (commit-qualified for git, bare for dir), from the scanner."""
    report = r / "fp.json"
    subprocess.run(
        [gitleaks, "git", "--no-banner", "--redact", "-f", "json", "-r", str(report), "."],
        cwd=r,
        capture_output=True,
        text=True,
    )
    found = [f["Fingerprint"] for f in json.loads(report.read_text())]
    report.unlink()
    return "".join(f"{fp}\n{fp.split(':', 1)[1]}\n" for fp in found)


def test_premise_a_root_ignore_file_in_the_scanned_tree_hides_a_finding_even_with_an_explicit_ignore_path(
    gitleaks, tmp_path
):
    r = tmp_path / "repo"
    r.mkdir()
    sh("git", "init", "-q", "-b", "main", cwd=r)
    commit(r, "leak.txt", planted(), "key")
    ignore = ignore_for(gitleaks, r)
    (r / ".gitleaksignore").write_text(ignore)
    empty = tmp_path / "empty"
    empty.mkdir()
    for cmd in (["git"], ["dir"]):
        done = subprocess.run(
            [gitleaks, *cmd, "--no-banner", "--redact", "--exit-code", "1", f"--gitleaks-ignore-path={empty}", "."],
            cwd=r,
            capture_output=True,
            text=True,
        )
        assert done.returncode == 0, ("the premise: the root file still applies", cmd, done.stdout + done.stderr)


@pytest.mark.parametrize("scope", ["all-refs", "pr-commits"])
def test_a_head_ignore_file_cannot_hide_the_heads_key_from_either_scan(scope, gitleaks, tmp_path):
    """The planted-key canary the review asked for, with the real binary: the head carries a fingerprint-allowlisting
    ignore file and a config that allowlists its key; the resolve step's output must still make both scans exit 1."""
    info = cfg_repo(tmp_path, {".gitleaks.toml": "[extend]\nuseDefault = true\n"}, {"leak.txt": planted()})
    r = info[0]
    ignore = ignore_for(gitleaks, r)
    (r / ".gitleaksignore").write_text(ignore)
    (r / ".gitleaks.toml").write_text(ALLOW_ALL)
    sh("git", "add", ".gitleaksignore", ".gitleaks.toml", cwd=r)
    sh("git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", "commit", "-q", "-m", "hide it", cwd=r)
    head = sh("git", "rev-parse", "HEAD", cwd=r)
    info = (r, info[1], head)
    # What the head's own files do, with the scanner defaults and no resolve step: both scans pass.
    for cmd in (["dir"], ["git", "--log-opts=--all"]):
        plain = subprocess.run(
            [gitleaks, *cmd, "--no-banner", "--redact", "--exit-code", "1", "."], cwd=r, capture_output=True, text=True
        )
        assert plain.returncode == 0, ("premise", cmd)
    done, out = resolve(info, scope, "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    for cmd in (["dir"], ["git", f"--log-opts={out['log_opts']}"]):
        fixed = subprocess.run(
            [gitleaks, cmd[0], *out["scan_args"].split(), *cmd[1:], "."], cwd=r, capture_output=True, text=True
        )
        assert fixed.returncode == 1, (scope, cmd, fixed.stdout + fixed.stderr)


def test_the_root_ignore_file_of_the_checkout_becomes_the_bases_copy(tmp_path):
    info = cfg_repo(tmp_path, {".gitleaksignore": "base-line\n"}, {".gitleaksignore": "head-line\n"})
    done, out = resolve(info, "all-refs", "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert (info[0] / ".gitleaksignore").read_text() == "base-line\n"
    assert "::warning" in done.stdout and ".gitleaksignore" in done.stdout, "the change is made visible"


def test_a_head_ignore_file_is_removed_when_the_base_has_none(tmp_path):
    info = cfg_repo(tmp_path, {}, {".gitleaksignore": "head-line\n"})
    done, _ = resolve(info, "pr-commits", "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert not (info[0] / ".gitleaksignore").exists() and not (info[0] / ".gitleaksignore").is_symlink()


def test_a_symlinked_head_ignore_file_is_replaced_not_written_through(tmp_path):
    info = cfg_repo(tmp_path, {".gitleaksignore": "base-line\n"}, {})
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched\n")
    (info[0] / ".gitleaksignore").unlink()
    (info[0] / ".gitleaksignore").symlink_to(outside)
    done, _ = resolve(info, "all-refs", "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert outside.read_text() == "untouched\n"
    assert not (info[0] / ".gitleaksignore").is_symlink()
    assert (info[0] / ".gitleaksignore").read_text() == "base-line\n"


@pytest.mark.parametrize("event", [e for e in EVENTS if e != "pull_request"])
def test_other_events_leave_the_checkouts_ignore_file_alone(event, tmp_path):
    info = cfg_repo(tmp_path, {".gitleaksignore": "base-line\n"}, {".gitleaksignore": "head-line\n"})
    done, _ = resolve(info, "all-refs", event, tmp_path)
    assert done.returncode == 0
    assert (info[0] / ".gitleaksignore").read_text() == "head-line\n"


# --- gitleaks-hash-manifest-paths: the narrow allowlist for content-hash manifests (issue #290) ----------------------

MANIFEST = "assets/manifest.json"
OTHER_MANIFEST = "assets/icons.json"
# A SHA-256 in an asset manifest, on a line keyed "discord": what the default discord-api-token rule reads as a token.
MANIFEST_BODY = '{\n  "discord.svg": "' + hashlib.sha256(b"discord.svg").hexdigest() + '"\n}\n'
BASE_CONFIG = "title = 'base config'\n[extend]\nuseDefault = true\n"


def manifest_repo(tmp_path, head_files: dict, base_files: dict | None = None):
    (tmp_path / "assets").mkdir(exist_ok=True)
    info = cfg_repo(tmp_path, {".gitleaks.toml": BASE_CONFIG} if base_files is None else base_files, {})
    r = info[0]
    for name, body in head_files.items():
        (r / name).parent.mkdir(parents=True, exist_ok=True)
        (r / name).write_text(body)
        sh("git", "add", name, cwd=r)
    sh("git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", "commit", "-q", "-m", "manifests", cwd=r)
    return r, info[1], sh("git", "rev-parse", "HEAD", cwd=r)


def scan_codes(gitleaks: str, info, out: dict) -> list[int]:
    """Exit codes of the resolved history scan and tree scan, built exactly as the job builds them."""
    codes = []
    for cmd in (["git", f"--log-opts={out['log_opts']}"], ["dir"]):
        done = subprocess.run(
            [gitleaks, cmd[0], *out["scan_args"].split(), *cmd[1:], "."], cwd=info[0], capture_output=True, text=True
        )
        codes.append(done.returncode)
    return codes


def findings(gitleaks: str, info, out: dict, tmp_path) -> list[dict]:
    """The tree scan's findings as the job would run it (JSON report instead of the exit code)."""
    report = tmp_path / "findings.json"
    subprocess.run(
        [gitleaks, "dir", *out["scan_args"].split(), "-f", "json", "-r", str(report), "."],
        cwd=info[0],
        capture_output=True,
        text=True,
    )
    return json.loads(report.read_text())


def test_the_hash_manifest_input_is_a_string_that_defaults_to_empty_and_is_documented():
    spec = INPUTS["gitleaks-hash-manifest-paths"]
    assert spec["type"] == "string" and spec["default"] == "", "no allowlist unless a caller asks for one"
    row = next((x for x in README.read_text().splitlines() if x.startswith("| `gitleaks-hash-manifest-paths` |")), "")
    assert row, "gitleaks-hash-manifest-paths is not documented in the README"
    assert "discord-api-token" in row and "64" in row and "base" in row and "empty" in row.lower()


def test_without_paths_there_is_no_overlay_and_the_arguments_are_what_they_were(repo, tmp_path):
    _, plain = resolve(repo, "pr-commits", "pull_request", tmp_path)
    for value in ("", "\n\n"):  # unset, empty, and blank lines only: nothing to allow
        done, out = resolve(repo, "pr-commits", "pull_request", tmp_path, paths=value)
        assert done.returncode == 0, done.stderr + done.stdout
        assert out["scan_args"] == plain["scan_args"] and "overlay" not in out["scan_args"]
        assert "hash-manifest-paths=0" in done.stdout


def test_the_overlay_extends_the_base_commits_config_on_a_pull_request_and_allows_one_rule_only(tmp_path):
    info = manifest_repo(tmp_path, {MANIFEST: MANIFEST_BODY, ".gitleaks.toml": ALLOW_ALL})
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path, paths=f"{MANIFEST}\n{OTHER_MANIFEST}\n")
    assert done.returncode == 0, done.stderr + done.stdout
    args = scan_args_of(out)
    overlay = open(args["--config"]).read()
    assert args["--config"].endswith("/gitleaks-overlay/overlay.toml")
    base_copy = str(tmp_path / "runner" / "gitleaks-base-config" / "gitleaks.toml")
    assert f"path = '{base_copy}'" in overlay, "layered on the base commit's copy, never the checkout's file"
    assert open(base_copy).read() == BASE_CONFIG
    assert str(info[0]) not in overlay
    assert 'targetRules = ["discord-api-token"]' in overlay and 'condition = "AND"' in overlay
    assert "regexes = ['''^[a-f0-9]{64}$''']" in overlay
    assert "paths = ['''^assets/manifest\\.json$''', '''^assets/icons\\.json$''']" in overlay
    assert overlay.count("[[allowlists]]") == 1


@pytest.mark.parametrize("config", [None, "title = 'checkout'\n[extend]\nuseDefault = true\n"])
@pytest.mark.parametrize("event", [e for e in EVENTS if e != "pull_request"])
def test_other_events_layer_the_overlay_on_the_checkouts_config_or_the_defaults(event, config, tmp_path):
    info = manifest_repo(tmp_path, {MANIFEST: MANIFEST_BODY, **({".gitleaks.toml": config} if config else {})}, {})
    if not config:
        assert not (info[0] / ".gitleaks.toml").exists()
    done, out = resolve(info, "pr-commits", event, tmp_path, paths=MANIFEST)
    assert done.returncode == 0, done.stderr + done.stdout
    overlay = open(scan_args_of(out)["--config"]).read()
    if config:
        assert f"path = '{info[0] / '.gitleaks.toml'}'" in overlay
    else:
        defaults = tmp_path / "runner" / "gitleaks-overlay" / "defaults.toml"
        assert f"path = '{defaults}'" in overlay and "useDefault = true" in defaults.read_text()


INVALID_PATHS = [
    "/assets/manifest.json",  # absolute
    "assets/manifest.json/",  # directory form
    "../assets/manifest.json",
    "assets/../manifest.json",
    "assets/./manifest.json",
    "./manifest.json",
    "assets//manifest.json",
    ".",
    "..",
    "assets/*.json",  # no globs
    "assets/manifest?.json",
    "assets/[m].json",
    "assets/(a|b).json",  # no regular expressions
    "assets/manifest.json$",
    "assets/ma nifest.json",
    " assets/manifest.json",
    "assets/manifest.json ",
    " ",
    "assets\\manifest.json",
    "assets/manifest'.json",
    'assets/manifest".json',
    "''']\n[[allowlists]]\nregexes=['''.*",  # a try at breaking out of the generated TOML
    "assets/$(id).json",
    "assets/`id`.json",
    "assets/${HOME}.json",
    "assets/manifest.json\r",
    "assets/mänifest.json",
    "assets/manifest​.json",  # zero-width space
]


@pytest.mark.parametrize("bad", INVALID_PATHS)
def test_an_unusable_path_fails_closed_with_no_overlay(bad, repo, tmp_path):
    for value in (bad, f"{MANIFEST}\n{bad}\n"):  # alone, and behind a good line
        done, out = resolve(repo, "pr-commits", "pull_request", tmp_path, paths=value)
        assert done.returncode == 1, repr(value)
        assert "::error title=gitleaks-scope::gitleaks-hash-manifest-paths" in done.stdout
        assert "scan_args" not in out, "a bad list must not leave a scan configuration behind"


def test_more_than_one_hundred_paths_fail_closed(repo, tmp_path):
    ok = "\n".join(f"assets/m{i}.json" for i in range(100))
    done, out = resolve(repo, "pr-commits", "pull_request", tmp_path, paths=ok)
    assert done.returncode == 0, done.stderr + done.stdout
    done, out = resolve(repo, "pr-commits", "pull_request", tmp_path, paths=ok + "\nassets/m100.json")
    assert done.returncode == 1 and "scan_args" not in out


def test_the_hash_manifest_value_is_read_from_env_never_from_an_expression():
    assert "${{" not in step(RESOLVE)["run"]
    assert "IFS= read -r entry" in step(RESOLVE)["run"] and "eval " not in step(RESOLVE)["run"]


def test_premise_the_default_rule_flags_a_hash_in_a_manifest_and_the_overlay_allows_exactly_that(gitleaks, tmp_path):
    info = manifest_repo(tmp_path, {MANIFEST: MANIFEST_BODY})
    plain = resolve(info, "pr-commits", "pull_request", tmp_path)[1]
    assert scan_codes(gitleaks, info, plain) == [1, 1], "the false positive of issue #290, with the defaults"
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path, paths=MANIFEST)
    assert done.returncode == 0, done.stderr + done.stdout
    assert scan_codes(gitleaks, info, out) == [0, 0], "...gone for the listed manifest, in the history and the tree"


def test_every_listed_path_is_allowed(gitleaks, tmp_path):
    info = manifest_repo(tmp_path, {MANIFEST: MANIFEST_BODY, OTHER_MANIFEST: MANIFEST_BODY})
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path, paths=f"{MANIFEST}\n{OTHER_MANIFEST}")
    assert scan_codes(gitleaks, info, out) == [0, 0]
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path, paths=MANIFEST)
    assert scan_codes(gitleaks, info, out) == [1, 1], "a file that is not listed is still reported"


@pytest.mark.parametrize(
    "where",
    [
        "other.json",  # not listed
        "x/assets/manifest.json",  # the listed path as a suffix: the start anchor
        "assets/manifest.json.bak",  # the listed path as a prefix: the end anchor
        "assets/manifestXjson",  # the dot is a dot, not any character
        "Assets/manifest.json",  # case
        "assets/sub/manifest.json",
    ],
)
def test_a_hash_anywhere_but_the_listed_path_is_still_reported(where, gitleaks, tmp_path):
    info = manifest_repo(tmp_path, {where: MANIFEST_BODY})
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path, paths=MANIFEST)
    assert done.returncode == 0, done.stderr + done.stdout
    assert scan_codes(gitleaks, info, out) == [1, 1], where


def test_another_rule_in_a_listed_file_is_still_reported(gitleaks, tmp_path):
    # The allowlist is for the one rule: an AWS-shaped key in the same file is not hidden.
    info = manifest_repo(tmp_path, {MANIFEST: MANIFEST_BODY + planted()})
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path, paths=MANIFEST)
    assert scan_codes(gitleaks, info, out) == [1, 1]
    # ...and the finding is the AWS key, not the hash.
    rules = {f["RuleID"] for f in findings(gitleaks, info, out, tmp_path)}
    assert rules and "discord-api-token" not in rules, rules


def test_a_pull_request_cannot_allowlist_itself_with_its_own_config_or_ignore_file(gitleaks, tmp_path):
    # The list is the caller's; the config that is layered is the base's. The head's own allowlist is not read, so a key
    # it adds is reported even though the head's config (which the scanner would otherwise load) hides it.
    info = manifest_repo(tmp_path, {"leak.txt": planted(), MANIFEST: MANIFEST_BODY, ".gitleaks.toml": ALLOW_ALL})
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path, paths=MANIFEST)
    assert done.returncode == 0, done.stderr + done.stdout
    assert scan_codes(gitleaks, info, out) == [1, 1]
    found = {f["File"] for f in findings(gitleaks, info, out, tmp_path)}
    assert found == {"leak.txt"}, "the key is reported; only the listed manifest's hash is allowed"


@pytest.mark.parametrize("tree_scan", ["false", "true"])
def test_the_canary_still_passes_with_the_overlay_in_the_arguments(tree_scan, gitleaks, tmp_path):
    info = manifest_repo(tmp_path, {MANIFEST: MANIFEST_BODY})
    done, out = resolve(info, "pr-commits", "pull_request", tmp_path, paths=MANIFEST)
    env = {
        **os.environ,
        "PATH": f"{os.path.dirname(gitleaks)}:{os.environ['PATH']}",
        "TREE_SCAN": tree_scan,
        "SCAN_ARGS": out["scan_args"],
    }
    canary = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step(CANARY)["run"]], env=env, capture_output=True, text=True, timeout=120
    )
    assert canary.returncode == 0, canary.stdout + canary.stderr


# --- commit-bound .gitleaksignore entries under the narrowed scan (issue #336) ----------------------------------------
#
# gitleaks writes a history finding as `commit:file:rule:line`. The tree scan has no commit, so it can only match the
# `file:rule:line` form: with the default `pr-commits` scope a commit-bound entry no longer hides anything there. The
# job cannot rewrite the entries (that would let an old review hide a new finding on a reused line), so it says which
# lines are affected, by line number, file and rule only, and the docs name the two forms that work.

IGNORE_NOTE = "Report commit-bound .gitleaksignore entries"
COMMIT_A = "0123456789abcdef0123456789abcdef01234567"
COMMIT_B = "fedcba9876543210fedcba9876543210fedcba98"


def ignore_note(tmp_path, body: bytes | None, tree: str = "true"):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    if body is not None:
        (ws / ".gitleaksignore").write_bytes(body)
    summary = tmp_path / "summary.md"
    done = run_step(
        IGNORE_NOTE,
        {"TREE_SCAN": tree, "GITHUB_WORKSPACE": str(ws), "GITHUB_STEP_SUMMARY": str(summary)},
        cwd=ws,
    )
    return done, (summary.read_text() if summary.exists() else "")


def test_the_ignore_note_step_sits_between_the_resolve_step_and_the_scans_and_reads_only_env():
    names = [x.get("name") for x in steps_of(GITLEAKS)]
    assert names.index(RESOLVE) < names.index(IGNORE_NOTE) < names.index(COMMITS)
    s = step(IGNORE_NOTE)
    assert s["env"] == {"TREE_SCAN": "${{ steps.scope.outputs.tree }}"}
    assert "${{" not in s["run"] and "eval " not in s["run"]
    assert "continue-on-error" not in s, "the note is informational and must not be the thing that hides a failure"


def test_commit_bound_entries_are_reported_by_line_file_and_rule_never_by_commit(tmp_path):
    body = (
        "# reviewed 2026-11-01\n"
        f"{COMMIT_A}:docs/example.md:generic-api-key:12\n"
        "\n"
        "docs/example.md:generic-api-key:12\n"
        f"{COMMIT_B}:src/fixture.py:aws-access-token:7\r\n"
    )
    done, summary = ignore_note(tmp_path, body.encode())
    assert done.returncode == 0, done.stdout + done.stderr
    out = done.stdout
    assert "::warning title=gitleaks::" in out
    assert "2 commit-bound" in out
    assert "line 2" in out and "docs/example.md" in out and "generic-api-key" in out
    assert "line 5" in out and "src/fixture.py" in out and "aws-access-token" in out
    assert "line 4" not in out, "the tree-form entry works under both scopes and is not reported"
    for text in (out, summary):
        assert COMMIT_A not in text and COMMIT_B not in text and COMMIT_A[:7] not in text, "commits are never printed"
    assert "2 commit-bound" in summary


@pytest.mark.parametrize(
    "body",
    [
        None,
        b"",
        b"# only a comment\n",
        b"docs/example.md:generic-api-key:12\nsrc/a.py:aws-access-token:3\n",
        b"not a fingerprint at all\n",
    ],
)
def test_no_commit_bound_entry_means_no_note(body, tmp_path):
    done, summary = ignore_note(tmp_path, body)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "::warning" not in done.stdout and summary == ""


def test_the_note_is_for_the_narrowed_scan_only(tmp_path):
    done, summary = ignore_note(tmp_path, f"{COMMIT_A}:a.md:generic-api-key:1\n".encode(), tree="false")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "::warning" not in done.stdout and summary == "", "a full-history scan still matches the entries"


def test_an_odd_byte_in_an_entry_is_not_echoed_into_a_workflow_command(tmp_path):
    body = f"{COMMIT_A}:evil%0A::error::x.md:rule:3\n{COMMIT_B}:ok.md:rule-b:4\n"
    done, _ = ignore_note(tmp_path, body.encode())
    assert done.returncode == 0, done.stdout + done.stderr
    assert "::error" not in done.stdout and "%0A" not in done.stdout
    assert "2 commit-bound" in done.stdout and "ok.md" in done.stdout


def test_the_note_never_fails_the_job_on_a_large_or_odd_file(tmp_path):
    body = "".join(f"{COMMIT_A}:f{i}.md:generic-api-key:{i}\n" for i in range(1, 400)).encode() + bytes([0, 255, 10])
    done, _ = ignore_note(tmp_path, body)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "399 commit-bound" in done.stdout
    assert done.stdout.count("line ") <= 50, "the list is capped so a huge file cannot flood the log"


def detail_repo(gitleaks: str, tmp_path):
    """A repo whose only commit holds a reviewed fixture key; returns the repo, its commit-bound and tree-form ids."""
    r = tmp_path / "repo"
    r.mkdir()
    sh("git", "init", "-q", "-b", "main", cwd=r)
    commit(r, "leak.txt", planted(), "reviewed fixture key")
    report = r / "fp.json"
    subprocess.run(
        [gitleaks, "git", "--no-banner", "--redact", "-f", "json", "-r", str(report), "."], cwd=r, capture_output=True
    )
    fp = json.loads(report.read_text())[0]["Fingerprint"]
    report.unlink()
    return r, fp, fp.split(":", 1)[1]


def run_scans(gitleaks: str, r, log_opts: str, ignore_dir) -> tuple[int, int]:
    tail = ["--no-banner", "--redact", "--exit-code", "1", f"--gitleaks-ignore-path={ignore_dir}"]
    hist = subprocess.run(
        [gitleaks, "git", *tail, f"--log-opts={log_opts}", "."], cwd=r, capture_output=True, text=True
    )
    tree = subprocess.run([gitleaks, "dir", *tail, "."], cwd=r, capture_output=True, text=True)
    return hist.returncode, tree.returncode


def test_premise_a_commit_bound_entry_hides_the_history_finding_but_not_the_tree_finding(gitleaks, tmp_path):
    r, commit_form, tree_form = detail_repo(gitleaks, tmp_path)
    assert commit_form.count(":") == 3 and tree_form.count(":") == 2
    ign = tmp_path / "ign"
    ign.mkdir()
    (ign / ".gitleaksignore").write_text(commit_form + "\n")
    assert not (r / ".gitleaksignore").exists()
    assert run_scans(gitleaks, r, "--all", ign) == (0, 1), "reviewed in history, failing in the tree scan (#336)"


def test_the_tree_form_entry_hides_the_finding_in_both_scans_and_survives_a_squash(gitleaks, tmp_path):
    r, commit_form, tree_form = detail_repo(gitleaks, tmp_path)
    old = sh("git", "rev-parse", "HEAD", cwd=r)
    ign = tmp_path / "ign"
    ign.mkdir()
    (ign / ".gitleaksignore").write_text(tree_form + "\n")
    assert run_scans(gitleaks, r, "--all", ign) == (0, 0)
    # a squash: the same tree under a brand new commit id; the old id is gone from the history
    sh("git", "checkout", "-q", "--orphan", "squashed", cwd=r)
    sh("git", "-c", "user.email=ci@example.invalid", "-c", "user.name=ci", "commit", "-q", "-m", "squash", cwd=r)
    assert sh("git", "rev-parse", "HEAD", cwd=r) != old and commit_form.split(":", 1)[0] == old
    assert run_scans(gitleaks, r, "--all", ign) == (0, 0), "the tree form does not name a commit"
    (ign / ".gitleaksignore").write_text(commit_form + "\n")
    assert run_scans(gitleaks, r, "--all", ign)[0] == 1, "the commit-bound entry is orphaned by the squash"


def test_the_tree_form_entry_hides_nothing_else_a_new_leak_in_a_pull_request_commit_is_still_caught(gitleaks, tmp_path):
    r, _, tree_form = detail_repo(gitleaks, tmp_path)
    base = sh("git", "rev-parse", "HEAD", cwd=r)
    sh("git", "checkout", "-q", "-b", "pr", cwd=r)
    other = planted().replace("AKIA", "ASIA")
    commit(r, "new_leak.txt", other, "a new key in the pull request")
    commit(r, "new_leak.txt", "gone\n", "removed again")
    head = sh("git", "rev-parse", "HEAD", cwd=r)
    ign = tmp_path / "ign"
    ign.mkdir()
    (ign / ".gitleaksignore").write_text(tree_form + "\n")
    hist, tree = run_scans(gitleaks, r, f"{base}..{head}", ign)
    assert hist == 1, "the key added and removed inside the pull request is caught by the range scan"
    assert tree == 0, "the reviewed file stays ignored in the tree and the removed one is gone"
    commit(r, "new_leak.txt", other, "and back again")
    assert run_scans(gitleaks, r, f"{base}..HEAD", ign)[1] == 1, "a leak left in the tree is caught by the tree scan"


def test_a_toml_allowlist_by_path_and_rule_works_in_the_tree_scan_and_hides_only_that_pair(gitleaks, tmp_path):
    r, _, _ = detail_repo(gitleaks, tmp_path)
    cfg = tmp_path / "gitleaks.toml"
    cfg.write_text(
        '[extend]\nuseDefault = true\n\n[[allowlists]]\ndescription = "documented placeholder key"\n'
        "targetRules = [\"generic-api-key\"]\npaths = ['''^leak\\.txt$''']\n"
    )
    empty = tmp_path / "empty"
    empty.mkdir()

    def tree_code(config):
        args = ["--no-banner", "--redact", "--exit-code", "1", f"--config={config}", f"--gitleaks-ignore-path={empty}"]
        done = subprocess.run([gitleaks, "dir", *args, "."], cwd=r, capture_output=True, text=True)
        return done.returncode

    assert tree_code(cfg) == 0, "the path and rule pair is allowed in the tree scan, whatever the commit"
    other_path = tmp_path / "other.toml"
    other_path.write_text(cfg.read_text().replace("^leak", "^elsewhere"))
    assert tree_code(other_path) == 1, "another path is not allowed"
    other_rule = tmp_path / "rule.toml"
    other_rule.write_text(cfg.read_text().replace("generic-api-key", "aws-access-token"))
    assert tree_code(other_rule) == 1, "another rule is not allowed"


def test_the_readme_and_the_changelog_carry_the_migration_note():
    readme = README.read_text()
    assert "commit-bound" in readme and "all-refs" in readme
    # The entry sits in Unreleased until the next release cut moves it under a version heading, so find it by its own
    # heading wherever it lives now instead of pinning the test to one section.
    changelog = (REPO / "CHANGELOG.md").read_text()
    entries = [e for e in changelog.split("\n### ")[1:] if "issue #336" in e.split("\n", 1)[0]]
    assert len(entries) == 1, "exactly one changelog entry carries the issue #336 migration note"
    entry = entries[0]
    assert "commit-bound" in entry
    owner = changelog.split("\n### " + entry.split("\n", 1)[0], 1)[0].rsplit("\n## ", 1)[1].split("\n", 1)[0]
    assert owner == "Unreleased" or owner.startswith("v"), f"the entry sits under a release heading, got {owner!r}"
