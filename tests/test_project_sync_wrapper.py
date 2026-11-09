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
    "repositories",
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
    "trusted-ref",
    "allow-fork-pull-request-target",
    "allow-fork-repository",
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
    match = re.search(r"uses: ChiefGyk3D/scrum-around-and-find-out@([0-9a-f]{40}) # v0\.2\.0\n", WORKFLOW.read_text())
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


def test_the_token_is_limited_to_the_named_repositories_else_the_calling_one_and_the_key_comes_from_doppler():
    with_ = safo_step()["with"]
    # a caller whose board belongs to another account names that account's repositories; otherwise the calling one
    assert with_["repositories"] == "${{ inputs.repositories || github.event.repository.name }}"
    assert with_["private-key"] == "${{ env.PROJECTS_APP_PRIVATE_KEY }}"
    assert any(str(s.get("uses", "")).startswith("dopplerhq/secrets-fetch-action@") for s in steps())


def test_harden_runner_runs_first_and_the_default_list_lets_safo_install_pyyaml():
    # The egress policy check is the one step that runs before harden-runner; it touches no network.
    assert steps()[0]["name"] == "Validate the egress policy inputs"
    first = steps()[1]
    assert first["uses"].startswith("step-security/harden-runner@")
    default = doc()[True]["workflow_call"]["inputs"]["allowed-endpoints"]["default"].split()
    assert {"api.github.com:443", "api.doppler.com:443", "pypi.org:443", "files.pythonhosted.org:443"} <= set(default)


SAFO_ACTION_PREFIX = "ChiefGyk3D/scrum-around-and-find-out@"
FILE_INPUTS = ("board-file", "status-body-file")


def checkout_missing_before_safo(workflow: dict) -> list[str]:
    """Jobs that pass board-file or status-body-file to safo without an actions/checkout step before it.

    From v0.2.0 safo reads those files from git at the trusted revision, so the repository must be checked out
    first. Collects every job of the workflow loosely; the caller asserts strictly.
    """
    bad = []
    for name, job in (workflow.get("jobs") or {}).items():
        seen_checkout = False
        for step in job.get("steps") or []:
            uses = str(step.get("uses", ""))
            if uses.startswith("actions/checkout@"):
                seen_checkout = True
            elif uses.startswith(SAFO_ACTION_PREFIX):
                passed = step.get("with") or {}
                if any(passed.get(i) for i in FILE_INPUTS) and not seen_checkout:
                    bad.append(name)
    return bad


def test_checkout_precedes_safo_wherever_a_file_input_is_passed():
    seen = 0
    for path in sorted((REPO / ".github" / "workflows").glob("*.yml")):
        data = yaml.safe_load(path.read_text())
        seen += sum(
            str(s.get("uses", "")).startswith(SAFO_ACTION_PREFIX)
            for job in (data.get("jobs") or {}).values()
            for s in job.get("steps") or []
        )
        assert checkout_missing_before_safo(data) == [], path.name
    assert seen >= 1, "no safo step collected; the guard looked at nothing"


def test_the_checkout_guard_bites():
    safo = {"uses": SAFO_ACTION_PREFIX + "0" * 40, "with": {"mode": "status", "status-body-file": "body.md"}}
    checkout = {"uses": "actions/checkout@" + "1" * 40}
    assert checkout_missing_before_safo({"jobs": {"j": {"steps": [safo]}}}) == ["j"]
    assert checkout_missing_before_safo({"jobs": {"j": {"steps": [safo, checkout]}}}) == ["j"]
    assert checkout_missing_before_safo({"jobs": {"j": {"steps": [checkout, safo]}}}) == []
    board = {"uses": safo["uses"], "with": {"mode": "validate", "board-file": "board.yaml"}}
    assert checkout_missing_before_safo({"jobs": {"j": {"steps": [board]}}}) == ["j"]
    boardless = {"uses": safo["uses"], "with": {"mode": "sync", "project-url": "u"}}
    assert checkout_missing_before_safo({"jobs": {"j": {"steps": [boardless]}}}) == []
