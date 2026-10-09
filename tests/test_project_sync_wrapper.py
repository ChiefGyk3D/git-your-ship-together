"""project-sync.yml is a thin wrapper around safo: the inputs callers pass, the pin and the plumbing.

The sync logic lives in ChiefGyk3D/scrum-around-and-find-out and is tested there. What stays here is the
contract with callers: every input they pass today is still accepted, the Action is called by commit with a
version comment, the App key still arrives from Doppler over OIDC, and nothing but safo mints a token or
holds a script.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "project-sync.yml"

# The inputs callers pass today. Removing or renaming one breaks a caller; adding one is fine.
CALLER_INPUTS = {
    "project-url",
    "status-field",
    "status-open-issue",
    "status-open-pr",
    "status-draft-pr",
    "status-done",
    "done-date-field",
    "reconcile",
    "app-owner",
    "default-area-field",
    "default-area",
    "dry-run",
    "client-id",
    "app-id",
    "pull-request-events",
    "egress-policy",
    "allowed-endpoints",
    "extra-allowed-endpoints",
    "doppler-project",
    "doppler-config",
    "doppler-identity-id",
    "doppler-trusted-refs-only",
    "timeout-minutes",
}
# The inputs of safo's action.yml this wrapper may pass, frozen here.
SAFO_INPUTS = {
    "mode",
    "board-file",
    "client-id",
    "app-id",
    "private-key",
    "app-owner",
    "repositories",
    "token",
    "allow-token-for-org",
    "dry-run",
    "python-version",
    "status-body-file",
    "status-state",
    "project-url",
    "status-field",
    "status-open-issue",
    "status-open-pr",
    "status-draft-pr",
    "status-done",
    "done-date-field",
    "default-area-field",
    "default-area",
}


def doc() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def steps() -> list[dict]:
    return doc()["jobs"]["sync"]["steps"]


def safo_step() -> dict:
    return next(s for s in steps() if str(s.get("uses", "")).startswith("ChiefGyk3D/scrum-around-and-find-out@"))


def test_every_input_a_caller_passes_today_is_still_accepted():
    inputs = set(doc()[True]["workflow_call"]["inputs"])  # PyYAML reads the bare key `on` as True
    assert CALLER_INPUTS <= inputs, f"callers would break: {sorted(CALLER_INPUTS - inputs)}"


def test_safo_is_called_by_commit_with_a_version_comment():
    match = re.search(
        r"uses: ChiefGyk3D/scrum-around-and-find-out@([0-9a-f]{40}) # v0\.1\.0\n", WORKFLOW.read_text()
    )
    assert match and match[1] != "0123456789abcdef0123456789abcdef01234567"
    expected = (REPO / "tests" / "safo-release-commit.txt").read_text().strip()
    assert re.fullmatch(r"[0-9a-f]{40}", expected) and match[1] == expected


def test_nothing_but_safo_mints_a_token_or_holds_a_script():
    assert not any("create-github-app-token" in str(s.get("uses", "")) for s in steps())
    assert not any("run" in s and ("python3 -" in s["run"] or "PROJECT_SYNC_PY" in s["run"]) for s in steps())
    assert not (REPO / "scripts" / "project_sync.py").exists()


def test_the_step_passes_only_inputs_safos_action_declares():
    passed = set(safo_step()["with"])
    assert passed <= SAFO_INPUTS, f"safo's action has no input {sorted(passed - SAFO_INPUTS)}"


def test_every_caller_input_that_means_something_to_safo_reaches_it():
    with_ = safo_step()["with"]
    for name in (
        "project-url",
        "status-field",
        "status-open-issue",
        "status-open-pr",
        "status-draft-pr",
        "status-done",
        "done-date-field",
        "default-area-field",
        "default-area",
        "dry-run",
        "client-id",
        "app-id",
        "app-owner",
    ):
        assert with_[name] == "${{ inputs." + name + " }}", name


def test_the_mode_follows_the_event_and_reconcile_false_is_a_no_op_on_schedule():
    step = safo_step()
    assert "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'" in step["with"]["mode"]
    assert "'reconcile' || 'sync'" in step["with"]["mode"]
    assert "inputs.reconcile" in step["if"] and "'schedule'" in step["if"]


def test_the_token_is_limited_to_the_calling_repository_and_the_key_comes_from_doppler():
    with_ = safo_step()["with"]
    assert with_["repositories"] == "${{ github.event.repository.name }}"
    assert with_["private-key"] == "${{ env.PROJECTS_APP_PRIVATE_KEY }}"
    assert any(str(s.get("uses", "")).startswith("dopplerhq/secrets-fetch-action@") for s in steps())


def test_harden_runner_runs_first_and_the_default_list_lets_safo_install_pyyaml():
    first = steps()[0]
    assert first["uses"].startswith("step-security/harden-runner@")
    default = doc()[True]["workflow_call"]["inputs"]["allowed-endpoints"]["default"].split()
    assert {"api.github.com:443", "api.doppler.com:443", "pypi.org:443", "files.pythonhosted.org:443"} <= set(default)
