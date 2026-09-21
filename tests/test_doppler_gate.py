"""Run the Doppler decide script under bash, the way a runner would.

The YAML tests prove the script is the same in five places and is fed the
right inputs. This one proves the script itself does what the README says:
a secret is fetched on a trusted ref and on nothing else. Every case here was
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


def decide(tmp_path: Path, **env: str) -> tuple[int, str, str]:
    """Run the decide step; return (exit code, mode written to GITHUB_OUTPUT, combined output)."""
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
    mode = ""
    for line in output.read_text().splitlines():
        if line.startswith("mode="):
            mode = line.split("=", 1)[1]
    return proc.returncode, mode, proc.stdout + proc.stderr


TRUSTED = [
    pytest.param({"EVENT": "push", "REF": "refs/heads/main", "DEFAULT_BRANCH": "main"}, id="push-default-branch"),
    pytest.param({"EVENT": "push", "REF": "refs/heads/master", "DEFAULT_BRANCH": "master"}, id="push-master-default"),
    pytest.param({"EVENT": "push", "REF": "refs/tags/v1.2.3", "DEFAULT_BRANCH": "main"}, id="push-tag"),
    pytest.param(
        {"EVENT": "schedule", "REF": "refs/heads/main", "DEFAULT_BRANCH": ""}, id="schedule-without-repo-payload"
    ),
    pytest.param(
        {"EVENT": "workflow_dispatch", "REF": "refs/heads/main", "DEFAULT_BRANCH": "main"}, id="dispatch-default-branch"
    ),
]

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
