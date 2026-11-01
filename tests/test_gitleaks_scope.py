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
    prefixes = ("GITLEAKS_", "TREE_SCAN", "EVENT_NAME", "BASE_SHA", "HEAD_SHA")
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


def resolve(repo_info, scope: str, event: str, tmp_path, base=None, head=None):
    r, b, h = repo_info
    out = tmp_path / "out"
    out.write_text("")
    done = run_step(
        RESOLVE,
        {
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
    assert out == {"log_opts": "--all", "tree": "false"}


@pytest.mark.parametrize("event", [e for e in EVENTS if e != "pull_request"])
def test_pr_commits_never_narrows_outside_a_pull_request(event, repo, tmp_path):
    # push (the default branch included), schedule, workflow_dispatch, any other event: full history, whatever is set.
    done, out = resolve(repo, "pr-commits", event, tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert out == {"log_opts": "--all", "tree": "false"}


def test_pr_commits_on_a_pull_request_scans_base_to_head_and_the_tree(repo, tmp_path):
    _, base, head = repo
    done, out = resolve(repo, "pr-commits", "pull_request", tmp_path)
    assert done.returncode == 0, done.stderr + done.stdout
    assert out == {"log_opts": f"{base}..{head}", "tree": "true"}


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
    assert step(COMMITS)["env"] == {"LOG_OPTS": "${{ steps.scope.outputs.log_opts }}"}
    assert step(COMMITS)["run"].count('--log-opts="$LOG_OPTS"') == 1
    assert '--log-opts="--all"' not in step(COMMITS)["run"]


# --- the scans are wired as designed ---------------------------------------------


def test_the_tree_scan_runs_only_for_a_narrowed_pull_request_and_even_after_a_failed_history_scan():
    s = step(TREE)
    assert s["if"] == "always() && steps.scope.outputs.tree == 'true'"
    assert "gitleaks dir " in s["run"] and "--exit-code 1" in s["run"] and "--redact" in s["run"]
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
    assert s["env"] == {"TREE_SCAN": "${{ steps.scope.outputs.tree }}"}
    assert '"$status" -ne 1' in s["run"]


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
    env = {**os.environ, "PATH": f"{os.path.dirname(gitleaks)}:{os.environ['PATH']}", "TREE_SCAN": tree_scan}
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
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "TREE_SCAN": tree_scan}
    done = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step(CANARY)["run"]], env=env, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == 1 and "was not caught" in done.stdout
