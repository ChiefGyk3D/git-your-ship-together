"""Run the Doppler decide script under bash, the way a runner would.

The YAML tests prove the script is the same in seven places and is fed the
right inputs. This one runs the script for push, schedule, dispatch, pull request
and other non-PR events across the ref shapes below, and pins what it does:
a secret is fetched on a trusted ref, on an allow-listed event. Every case here was
run against the old script first, where the untrusted ones came back `oidc`.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
ACTION = REPO / ".github" / "actions" / "doppler-secrets" / "action.yml"


def script() -> str:
    doc = yaml.safe_load(ACTION.read_text())
    return doc["runs"]["steps"][0]["run"]


def decide_outputs(tmp_path: Path, **env: str) -> tuple[int, dict[str, str], str]:
    """Run the decide step; return (exit code, every GITHUB_OUTPUT pair, combined output)."""
    output = tmp_path / "github_output"
    output.write_text("")
    base = {
        "IDENTITY_ID": "00000000-0000-0000-0000-000000000000",
        "TOKEN": "",
        "PROJECT": "demo",
        "CONFIG": "ci",
        "REQUIRED": "false",
        "TRUSTED_ONLY": "true",
        "IS_FORK": "false",
        "EVENT": "push",
        "REF": "refs/heads/main",
        "DEFAULT_BRANCH": "main",
        "GITHUB_OUTPUT": str(output),
        "PATH": os.environ["PATH"],
    }
    base.update(env)
    proc = subprocess.run(["bash", "-c", script()], env=base, capture_output=True, text=True)
    written = dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)
    return proc.returncode, written, proc.stdout + proc.stderr


def decide(tmp_path: Path, **env: str) -> tuple[int, str, str]:
    """Run the decide step; return (exit code, mode written to GITHUB_OUTPUT, combined output)."""
    code, written, out = decide_outputs(tmp_path, **env)
    return code, written.get("mode", ""), out


TRUSTED = [
    pytest.param({"EVENT": "push", "REF": "refs/heads/main", "DEFAULT_BRANCH": "main"}, id="push-default-branch"),
    pytest.param({"EVENT": "push", "REF": "refs/heads/master", "DEFAULT_BRANCH": "master"}, id="push-master-default"),
    pytest.param({"EVENT": "push", "REF": "refs/tags/v1.2.3", "DEFAULT_BRANCH": "main"}, id="push-version-tag"),
    pytest.param({"EVENT": "push", "REF": "refs/tags/v10.20.300", "DEFAULT_BRANCH": "main"}, id="push-multidigit-tag"),
    pytest.param(
        {"EVENT": "schedule", "REF": "refs/heads/main", "DEFAULT_BRANCH": ""}, id="schedule-without-repo-payload"
    ),
    pytest.param(
        {"EVENT": "workflow_dispatch", "REF": "refs/heads/main", "DEFAULT_BRANCH": "main"}, id="dispatch-default-branch"
    ),
]

NOT_A_RELEASE_TAG = {
    "tag-anything": "refs/tags/anything",
    "tag-v1": "refs/tags/v1",
    "tag-v1.2": "refs/tags/v1.2",
    "tag-four-parts": "refs/tags/v1.2.3.4",
    "tag-traversal": "refs/tags/v1.2.3/../x",
    "tag-subpath": "refs/tags/v1.2.3/x",
    "tag-capital-v": "refs/tags/V1.2.3",
    "tag-no-v": "refs/tags/1.2.3",
    "tag-prerelease": "refs/tags/v1.2.3-rc.1",
    "tag-suffix": "refs/tags/v1.2.3x",
    "tag-newline": "refs/tags/v1.2.3\nx",
    "tag-trailing-newline": "refs/tags/v1.2.3\n",
    "tag-leading-newline": "refs/tags/\nv1.2.3",
    "tag-space": "refs/tags/v1.2.3 x",
    "tag-empty": "refs/tags/",
    "tag-glob": "refs/tags/v*.*.*",
    "tag-nondigit": "refs/tags/va.b.c",
    "branch-like-tag": "refs/heads/v1.2.3",
    "bare-tag-name": "v1.2.3",
    "tag-prefix-twice": "refs/tags/refs/tags/v1.2.3",
}

UNTRUSTED = [
    pytest.param({"EVENT": "pull_request", "REF": "refs/pull/7/merge", "DEFAULT_BRANCH": "main"}, id="pull-request"),
    pytest.param(
        {"EVENT": "pull_request_target", "REF": "refs/heads/main", "DEFAULT_BRANCH": "main"}, id="pull-request-target"
    ),
    pytest.param({"EVENT": "push", "REF": "refs/heads/feature", "DEFAULT_BRANCH": "main"}, id="push-other-branch"),
    pytest.param(
        {"EVENT": "workflow_dispatch", "REF": "refs/heads/feature", "DEFAULT_BRANCH": "main"},
        id="dispatch-other-branch",
    ),
    pytest.param({"EVENT": "push", "REF": "refs/heads/main", "DEFAULT_BRANCH": ""}, id="push-unknown-default-branch"),
    pytest.param(
        {"EVENT": "push", "REF": "refs/heads/main-2", "DEFAULT_BRANCH": "main"}, id="push-branch-with-default-prefix"
    ),
    # Only a semantic version release tag (vMAJOR.MINOR.PATCH, the shape this
    # repository's own tags have) is trusted; every other tag name is not, and
    # neither is a branch spelled like one.
    *[
        pytest.param({"EVENT": event, "REF": ref, "DEFAULT_BRANCH": "main"}, id=f"{event}-{label}")
        for event in ("push", "workflow_dispatch")
        for label, ref in NOT_A_RELEASE_TAG.items()
    ],
]


@pytest.mark.parametrize("env", TRUSTED)
def test_a_trusted_ref_fetches(tmp_path, env):
    code, mode, out = decide(tmp_path, **env)
    assert code == 0 and mode == "oidc", out


@pytest.mark.parametrize("env", UNTRUSTED)
def test_an_untrusted_ref_fetches_nothing_and_says_why(tmp_path, env):
    code, mode, out = decide(tmp_path, **env)
    assert code == 0 and mode == "none", out
    assert "trusted-refs-only" in out and "no secrets are fetched" in out


@pytest.mark.parametrize("env", UNTRUSTED)
def test_an_untrusted_ref_never_fails_even_when_required(tmp_path, env):
    """`required` means "a configured secret must be present", not "fetch on every ref"."""
    code, mode, out = decide(tmp_path, REQUIRED="true", **env)
    assert code == 0 and mode == "none", out


def test_a_fork_pull_request_fetches_nothing_even_with_the_gate_off(tmp_path):
    code, mode, out = decide(
        tmp_path, TRUSTED_ONLY="false", IS_FORK="true", EVENT="pull_request", REF="refs/pull/7/merge"
    )
    assert code == 0 and mode == "none" and "fork" in out, out


def test_the_gate_can_be_switched_off_for_a_same_repository_branch(tmp_path):
    code, mode, out = decide(tmp_path, TRUSTED_ONLY="false", EVENT="push", REF="refs/heads/feature")
    assert code == 0 and mode == "oidc", out


def test_the_service_token_path_is_gated_the_same_way(tmp_path):
    code, mode, _ = decide(tmp_path, IDENTITY_ID="", TOKEN="dp.st.example")
    assert (code, mode) == (0, "token")
    code, mode, _ = decide(
        tmp_path, IDENTITY_ID="", TOKEN="dp.st.example", EVENT="pull_request", REF="refs/pull/1/merge"
    )
    assert (code, mode) == (0, "none")


def test_nothing_configured_on_a_trusted_ref_is_a_notice_unless_required(tmp_path):
    code, mode, out = decide(tmp_path, IDENTITY_ID="", TOKEN="")
    assert (code, mode) == (0, "none") and "not configured" in out
    code, mode, out = decide(tmp_path, IDENTITY_ID="", TOKEN="", REQUIRED="true")
    assert code == 1 and "needs one" in out


def test_missing_project_or_config_fails_only_when_a_fetch_would_happen(tmp_path):
    code, _, out = decide(tmp_path, PROJECT="")
    assert code == 1 and "project and config are required" in out
    code, mode, _ = decide(tmp_path, PROJECT="", EVENT="pull_request", REF="refs/pull/1/merge")
    assert (code, mode) == (0, "none")


# --- case-insensitive matching inherited from the environment -------------------------------------


@pytest.mark.parametrize("ref", ["refs/tags/V1.2.3", "refs/Tags/v1.2.3", "refs/tags/V1.2.3\n"])
def test_an_inherited_nocasematch_does_not_make_a_tag_trusted(tmp_path, ref):
    """BASHOPTS=nocasematch in the runner environment must not widen the tag shape."""
    code, mode, out = decide(tmp_path, BASHOPTS="nocasematch:nocaseglob", EVENT="push", REF=ref)
    assert code == 0 and mode == "none", out


def test_an_inherited_nocasematch_still_trusts_a_real_release_tag(tmp_path):
    code, mode, out = decide(tmp_path, BASHOPTS="nocasematch:nocaseglob", EVENT="push", REF="refs/tags/v1.2.3")
    assert code == 0 and mode == "oidc", out


def test_an_inherited_nocasematch_does_not_break_the_event_names(tmp_path):
    code, mode, out = decide(tmp_path, BASHOPTS="nocasematch", EVENT="PULL_REQUEST", REF="refs/pull/1/merge")
    assert code == 0 and mode == "none", out


# --- the untrusted-tag output: a tag the gate refused ---------------------------------------------


@pytest.mark.parametrize("event", ["push", "workflow_dispatch"])
@pytest.mark.parametrize("label", [k for k, v in NOT_A_RELEASE_TAG.items() if v.startswith("refs/tags/")])
def test_a_refused_tag_is_flagged_for_the_caller(tmp_path, event, label):
    """A consumer that was asked for a secret-backed feature fails on this; see the next tests."""
    code, written, out = decide_outputs(tmp_path, EVENT=event, REF=NOT_A_RELEASE_TAG[label])
    assert code == 0 and written["mode"] == "none" and written.get("untrusted-tag") == "true", out


@pytest.mark.parametrize(
    "env",
    [
        {"EVENT": "push", "REF": "refs/tags/v1.2.3"},
        {"EVENT": "push", "REF": "refs/heads/main"},
        {"EVENT": "push", "REF": "refs/heads/feature"},
        {"EVENT": "push", "REF": "refs/heads/v1.2.3"},
        {"EVENT": "schedule", "REF": "refs/heads/main"},
        {"EVENT": "pull_request", "REF": "refs/pull/7/merge"},
        {"EVENT": "pull_request", "REF": "refs/pull/7/merge", "IS_FORK": "true"},
        {"EVENT": "pull_request_target", "REF": "refs/heads/main"},
        {"EVENT": "push", "REF": "refs/tags/v1.2.3-rc.1", "TRUSTED_ONLY": "false"},
    ],
    ids=["release-tag", "default", "other-branch", "branch-like-tag", "schedule", "pr", "fork-pr", "prt", "gate-off"],
)
def test_every_other_case_is_not_flagged(tmp_path, env):
    code, written, out = decide_outputs(tmp_path, **env)
    assert code == 0 and written.get("untrusted-tag") == "false", out


# --- the consumers: a requested secret-backed feature fails closed on a refused tag ---------------

WORKFLOWS = REPO / ".github" / "workflows"
REFUSED = "ref is not a vMAJOR.MINOR.PATCH release tag: Doppler secrets are not fetched"


def step_script(workflow: str, name: str, job: str | None = None) -> dict:
    doc = yaml.safe_load((WORKFLOWS / workflow).read_text())
    found = [
        step
        for jname, j in doc["jobs"].items()
        if job in (None, jname)
        for step in j.get("steps", [])
        if step.get("name") == name
    ]
    assert len(found) == 1, (workflow, name, len(found))
    return found[0]


def run_step(tmp_path: Path, step: dict, **env: str) -> tuple[int, dict[str, str], str]:
    output = tmp_path / "step_output"
    output.write_text("")
    full = {"GITHUB_OUTPUT": str(output), "PATH": os.environ["PATH"], **env}
    proc = subprocess.run(["bash", "-c", step["run"]], env=full, capture_output=True, text=True)
    written = {}
    for line in output.read_text().splitlines():
        if "=" in line and not line.startswith(("images<<", "EOF")):
            key, value = line.split("=", 1)
            written[key] = value
    return proc.returncode, written, proc.stdout + proc.stderr


def snyk_check() -> dict:
    return step_script("security.yml", "Check for SNYK_TOKEN", job="snyk")


def names_step() -> dict:
    return step_script("container-release.yml", "Resolve image names")


def test_the_consumers_are_wired_to_the_decide_outputs():
    for step in (snyk_check(), names_step()):
        env = step["env"]
        assert env["UNTRUSTED_TAG"] == "${{ steps.doppler.outputs.untrusted-tag }}"
        assert env["REF"] == "${{ github.ref }}"


def test_snyk_requested_on_a_refused_tag_fails_naming_the_ref(tmp_path):
    code, written, out = run_step(tmp_path, snyk_check(), UNTRUSTED_TAG="true", REF="refs/tags/v1.2.3-rc.1")
    assert code == 1 and "::error" in out and "refs/tags/v1.2.3-rc.1" in out and REFUSED in out, out
    assert written.get("present") != "true"


@pytest.mark.parametrize("flag", ["false", ""])
def test_snyk_without_a_token_on_any_other_ref_still_warns_and_skips(tmp_path, flag):
    code, written, out = run_step(tmp_path, snyk_check(), UNTRUSTED_TAG=flag, REF="refs/heads/main")
    assert code == 0 and written == {"present": "false"} and "::warning" in out, out


def test_snyk_with_a_token_proceeds(tmp_path):
    code, written, _ = run_step(tmp_path, snyk_check(), UNTRUSTED_TAG="false", REF="refs/tags/v1.2.3", SNYK_TOKEN="x")
    assert code == 0 and written == {"present": "true"}


NAMES_ENV = {
    "REPOSITORY": "Owner/Repo",
    "IMAGE_NAME": "",
    "DOCKERHUB_REPOSITORY": "",
    "REF": "refs/tags/v1.2.3-rc.1",
}


def test_docker_hub_requested_on_a_refused_tag_fails_naming_the_ref(tmp_path):
    env = {**NAMES_ENV, "PUSH": "true", "DOCKERHUB": "true", "UNTRUSTED_TAG": "true"}
    code, written, out = run_step(tmp_path, names_step(), **env)
    assert code == 1 and "::error" in out and "refs/tags/v1.2.3-rc.1" in out and REFUSED in out, out
    assert "dockerhub" not in written


def test_ghcr_only_on_a_refused_tag_stays_allowed(tmp_path):
    """dockerhub false: the decide step does not run, the flag is empty, and no Doppler secret was asked for."""
    for flag in ("", "true"):
        env = {**NAMES_ENV, "PUSH": "true", "DOCKERHUB": "false", "UNTRUSTED_TAG": flag}
        code, written, out = run_step(tmp_path, names_step(), **env)
        assert code == 0 and written["dockerhub"] == "" and "::error" not in out, out


def test_a_pull_request_build_that_does_not_push_is_not_failed_by_the_flag(tmp_path):
    env = {**NAMES_ENV, "PUSH": "false", "DOCKERHUB": "true", "UNTRUSTED_TAG": "true"}
    code, _, out = run_step(tmp_path, names_step(), **env)
    assert code == 0 and "::error" not in out, out


@pytest.mark.parametrize("ref", ["refs/tags/v1.2.3", "refs/heads/main"])
def test_docker_hub_on_a_trusted_ref_is_unchanged(tmp_path, ref):
    base = {**NAMES_ENV, "PUSH": "true", "DOCKERHUB": "true", "UNTRUSTED_TAG": "false", "REF": ref}
    code, written, out = run_step(tmp_path, names_step(), DOCKERHUB_USERNAME="u", DOCKERHUB_TOKEN="t", **base)
    assert code == 0 and written["dockerhub"] == "docker.io/u/repo", out
    code, written, out = run_step(tmp_path, names_step(), **base)
    assert code == 0 and written["dockerhub"] == "" and "::warning" in out, out


# --- pull_request_target: pinned as it is, not as one might wish ----------------------------------


def test_pull_request_target_with_the_gate_off_still_fetches(tmp_path):
    """PINS CURRENT BEHAVIOR; do not read it as closed. IS_FORK is computed for `pull_request` only, so
    `pull_request_target` from a fork with `trusted-refs-only: false` selects OIDC. project-sync relies on this;
    docs/wiki/Secrets-Doppler-and-OIDC.md ("pull_request_target is different") states the requirement: the
    workflow must never check out or run the pull request's code."""
    code, mode, out = decide(tmp_path, TRUSTED_ONLY="false", EVENT="pull_request_target", REF="refs/heads/main")
    assert code == 0 and mode == "oidc", out


def test_pull_request_target_with_the_gate_on_fetches_nothing(tmp_path):
    code, mode, out = decide(tmp_path, TRUSTED_ONLY="true", EVENT="pull_request_target", REF="refs/heads/main")
    assert code == 0 and mode == "none", out


# --- events: an explicit allow-list (#238, trusted-ref gate hardening) ------------------------------

NON_PR_EVENTS = ["issues", "issue_comment", "repository_dispatch", "workflow_run", "workflow_call"]
EXTRA_EVENTS = ["release", "merge_group", "discussion", "check_run", "made_up_event", ""]


@pytest.mark.parametrize("event", NON_PR_EVENTS + EXTRA_EVENTS)
@pytest.mark.parametrize("ref", ["refs/heads/main", "refs/tags/v1.2.3"])
def test_an_event_off_the_allow_list_is_refused_even_on_a_trusted_ref(tmp_path, event, ref):
    """CHANGED in #238: this used to pin `oidc` (the old rule was a ref rule, not an event allow-list)."""
    code, mode, out = decide(tmp_path, EVENT=event, REF=ref)
    assert code == 0 and mode == "none", out
    assert "trusted-refs-only" in out and "no secrets are fetched" in out


@pytest.mark.parametrize("event", NON_PR_EVENTS)
def test_an_event_off_the_allow_list_fetches_with_the_gate_off(tmp_path, event):
    code, mode, out = decide(tmp_path, TRUSTED_ONLY="false", EVENT=event, REF="refs/heads/main")
    assert code == 0 and mode == "oidc", out


@pytest.mark.parametrize("event", NON_PR_EVENTS)
def test_those_events_still_get_nothing_off_a_trusted_ref(tmp_path, event):
    code, mode, out = decide(tmp_path, EVENT=event, REF="refs/heads/feature")
    assert code == 0 and mode == "none", out


@pytest.mark.parametrize("event", ["PUSH", "Push", "push ", "push\n", "Schedule"])
def test_event_names_match_exactly(tmp_path, event):
    code, mode, out = decide(tmp_path, EVENT=event, REF="refs/heads/main")
    assert code == 0 and mode == "none", out


# --- trusted-refs-only is parsed strictly -----------------------------------------------------------


@pytest.mark.parametrize("value", ["true", "TRUE", "True", "tRuE"])
def test_the_gate_is_on_for_any_casing_of_true(tmp_path, value):
    code, mode, out = decide(tmp_path, TRUSTED_ONLY=value, EVENT="push", REF="refs/heads/feature")
    assert code == 0 and mode == "none", out


@pytest.mark.parametrize("value", ["false", "FALSE", "False"])
def test_the_gate_is_off_for_any_casing_of_false(tmp_path, value):
    code, mode, out = decide(tmp_path, TRUSTED_ONLY=value, EVENT="push", REF="refs/heads/feature")
    assert code == 0 and mode == "oidc", out


@pytest.mark.parametrize("value", ["", "ture", "yes", "1", "0", "on", "off", " true", "true ", "true\n", "no", "null"])
@pytest.mark.parametrize("event", ["push", "pull_request"])
def test_any_other_gate_value_stops_the_job_and_never_means_off(tmp_path, value, event):
    code, written, out = decide_outputs(tmp_path, TRUSTED_ONLY=value, EVENT=event, REF="refs/heads/feature")
    assert code == 1 and "mode" not in written, out
    assert "::error" in out and "trusted-refs-only" in out


def test_a_bad_gate_value_stops_a_fork_pull_request_too(tmp_path):
    code, _, out = decide(tmp_path, TRUSTED_ONLY="TRU", IS_FORK="true", EVENT="pull_request", REF="refs/pull/7/merge")
    assert code == 1, out


# --- a release tag must be on the default branch's history, when the job can show it -----------------


def git(cwd: Path, *args: str) -> str:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    return subprocess.run(["git", "-C", str(cwd), *args], env=env, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """A workspace with origin/main at `main_sha`, and one commit `side_sha` that is not on main."""
    work = tmp_path / "ws"
    work.mkdir()
    git(work, "init", "-q", "-b", "main")
    git(work, "commit", "-q", "--allow-empty", "-m", "one")
    git(work, "commit", "-q", "--allow-empty", "-m", "two")
    main_sha = git(work, "rev-parse", "HEAD")
    git(work, "update-ref", "refs/remotes/origin/main", main_sha)
    git(work, "checkout", "-q", "-b", "side", "HEAD~1")
    git(work, "commit", "-q", "--allow-empty", "-m", "side")
    side_sha = git(work, "rev-parse", "HEAD")
    return work, main_sha, git(work, "rev-parse", "HEAD~1"), side_sha


TAG = {"EVENT": "push", "REF": "refs/tags/v1.2.3", "DEFAULT_BRANCH": "main"}


def test_a_tag_on_the_default_branch_history_is_trusted(tmp_path, repo):
    work, main_sha, parent_sha, _ = repo
    for sha in (main_sha, parent_sha):
        code, written, out = decide_outputs(tmp_path, GITHUB_WORKSPACE=str(work), GITHUB_SHA=sha, **TAG)
        assert code == 0 and written["mode"] == "oidc" and written["untrusted-tag"] == "false", out


def test_a_tag_off_the_default_branch_history_is_refused_and_flagged(tmp_path, repo):
    work, _, _, side_sha = repo
    code, written, out = decide_outputs(tmp_path, GITHUB_WORKSPACE=str(work), GITHUB_SHA=side_sha, **TAG)
    assert code == 0 and written["mode"] == "none" and written["untrusted-tag"] == "true", out
    assert "trusted-refs-only" in out and "default branch" in out


def test_the_ancestry_check_does_not_touch_the_gate_off_path(tmp_path, repo):
    work, _, _, side_sha = repo
    code, written, out = decide_outputs(
        tmp_path, GITHUB_WORKSPACE=str(work), GITHUB_SHA=side_sha, TRUSTED_ONLY="false", **TAG
    )
    assert code == 0 and written["mode"] == "oidc", out


def test_a_tag_that_cannot_be_checked_keeps_the_name_rule_and_says_so(tmp_path):
    """RESIDUAL (README): with no checkout or no history the job cannot show where the tag points."""
    code, written, out = decide_outputs(tmp_path, GITHUB_WORKSPACE=str(tmp_path / "nothing"), GITHUB_SHA="a" * 40, **TAG)
    assert code == 0 and written["mode"] == "oidc" and "::notice" in out and "not verified" in out, out


def test_an_unknown_tag_shape_is_still_refused_before_any_ancestry_check(tmp_path, repo):
    work, main_sha, _, _ = repo
    code, written, _ = decide_outputs(
        tmp_path, GITHUB_WORKSPACE=str(work), GITHUB_SHA=main_sha, **{**TAG, "REF": "refs/tags/v1.2.3-rc.1"}
    )
    assert code == 0 and written["mode"] == "none" and written["untrusted-tag"] == "true"


def test_a_shallow_workspace_cannot_verify_and_never_refuses(tmp_path, repo):
    """Round 2: a shallow history can answer "not an ancestor" when ancestry is only unknown."""
    work, main_sha, _, side_sha = repo
    (work / ".git" / "shallow").write_text(main_sha + "\n")
    code, written, out = decide_outputs(tmp_path, GITHUB_WORKSPACE=str(work), GITHUB_SHA=side_sha, **TAG)
    assert code == 0 and written["mode"] == "oidc" and written["untrusted-tag"] == "false", out
    assert "not verified" in out


@pytest.mark.parametrize("status", [2, 3, 128, 255])
def test_a_git_error_from_the_ancestry_check_is_not_verified_and_never_refuses(tmp_path, repo, status):
    work, _, _, side_sha = repo
    shim = tmp_path / "shim"
    shim.mkdir()
    real = subprocess.run(["which", "git"], capture_output=True, text=True, check=True).stdout.strip()
    (shim / "git").write_text(
        f'#!/bin/bash\nfor a in "$@"; do [ "$a" = merge-base ] && exit {status}; done\nexec {real} "$@"\n'
    )
    (shim / "git").chmod(0o755)
    code, written, out = decide_outputs(
        tmp_path, GITHUB_WORKSPACE=str(work), GITHUB_SHA=side_sha, PATH=f"{shim}:{os.environ['PATH']}", **TAG
    )
    assert code == 0 and written["mode"] == "oidc" and "not verified" in out, out


def test_only_a_clean_exit_one_refuses(tmp_path, repo):
    """The negative case for the two tests above: the same shim returning 1 does refuse."""
    work, _, _, side_sha = repo
    shim = tmp_path / "shim"
    shim.mkdir()
    real = subprocess.run(["which", "git"], capture_output=True, text=True, check=True).stdout.strip()
    (shim / "git").write_text(f'#!/bin/bash\nfor a in "$@"; do [ "$a" = merge-base ] && exit 1; done\nexec {real} "$@"\n')
    (shim / "git").chmod(0o755)
    code, written, out = decide_outputs(
        tmp_path, GITHUB_WORKSPACE=str(work), GITHUB_SHA=side_sha, PATH=f"{shim}:{os.environ['PATH']}", **TAG
    )
    assert code == 0 and written["mode"] == "none" and written["untrusted-tag"] == "true", out
