"""security.yml `gitleaks-scope`: scope the secret scan of a pull request to the pull request (issue #260).

The scan used to run over every ref, so one key-shaped fixture on an unmerged branch turned the scan red on every
other pull request. `pr-commits` narrows a pull request's history scan to `base..head` and adds a scan of the
checked-out tree; `all-refs` (the default) is today's behavior. Only the `pull_request` event ever narrows: push,
schedule, workflow_dispatch and everything else scan the full history whatever the input says, so a branch protection
against a leak entering the default branch never gets weaker. An unknown value fails the job (fail closed).
"""

from __future__ import annotations

import hashlib
import io
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


def resolve(repo_info, scope: str, event: str, tmp_path, base=None, head=None):
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
        },
        cwd=r,
        out=out,
    )
    return done, dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)


# --- the input ----------------------------------------------------------------


def test_the_input_is_a_string_that_defaults_to_all_refs():
    spec = INPUTS["gitleaks-scope"]
    assert spec["type"] == "string"
    assert spec["default"] == "all-refs", "a caller that sets nothing must keep scanning every ref"
    assert "pr-commits" in spec["description"] and "all-refs" in spec["description"]


def test_the_input_is_documented_in_the_readme_and_the_default_is_stated():
    text = README.read_text()
    row = next((line for line in text.splitlines() if line.startswith("| `gitleaks-scope` |")), "")
    assert row, "gitleaks-scope is not documented in the README"
    assert "`all-refs`" in row and "pr-commits" in row and "default" in row.lower()


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
    import json

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
