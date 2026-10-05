"""scripts/project_sync.py against recorded GraphQL responses.

No network and no token: the script talks to GitHub through one callable,
`gql(op, variables)`, and these tests hand it a fake that answers each named
operation from a fixture under tests/fixtures/project_sync/ and records every
mutation. What a test asserts is the list of mutations the script asked for,
because that list is what would change the maintainer's board.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "project_sync.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "project_sync"

spec = importlib.util.spec_from_file_location("project_sync", SCRIPT)
ps = importlib.util.module_from_spec(spec)
sys.modules["project_sync"] = ps
spec.loader.exec_module(ps)

PROJECT_ID = "PVT_kwHOASmJts4BlrFt"
URL = "https://github.com/users/ChiefGyk3D/projects/2"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


class FakeGql:
    """Answers operations from fixtures; records the mutations asked for."""

    def __init__(self, **routes):
        self.routes = routes
        self.mutations: list[tuple[str, dict]] = []
        self.calls: list[str] = []

    def __call__(self, op: str, variables: dict) -> dict:
        self.calls.append(op)
        if op in ps.MUTATIONS:
            self.mutations.append((op, variables))
            if op == "AddItem":
                return fixture("add_item")
            return fixture("ok")
        if op not in self.routes:
            raise AssertionError(f"unexpected query {op}")
        route = self.routes[op]
        return route(variables) if callable(route) else fixture(route)


def cfg(**over):
    base = dict(
        project_url=URL,
        status_field="Status",
        status_open_issue="Backlog",
        status_open_pr="In progress",
        status_draft_pr="Backlog",
        status_done="Done",
        done_date_field="Done on",
        reconcile=False,
        default_area_field="",
        default_area="",
        dry_run=False,
    )
    base.update(over)
    return ps.Config(**base)


def project():
    return ps.load_project(FakeGql(ProjectUser="project_user"), URL)


def issue(state="open", closed_at=None):
    return ps.Content(id="I_1", kind="issue", state=state, draft=False, closed_at=closed_at, number=1, repo="o/r")


def pull(state="open", draft=False, closed_at=None):
    return ps.Content(id="PR_1", kind="pr", state=state, draft=draft, closed_at=closed_at, number=2, repo="o/r")


def ids(mutations):
    return [(op, {k: v for k, v in v.items() if k in ("optionId", "date", "fieldId", "itemId")}) for op, v in mutations]


# --- the project and its option ids -----------------------------------------


def test_url_parses_user_and_org_projects():
    assert ps.parse_project_url(URL) == ("user", "ChiefGyk3D", 2)
    assert ps.parse_project_url("https://github.com/orgs/acme/projects/17") == ("org", "acme", 17)
    with pytest.raises(ps.SyncError, match="not a GitHub Projects v2 URL"):
        ps.parse_project_url("https://github.com/ChiefGyk3D/Hammunition")


def test_project_resolves_ids_once_by_name():
    p = project()
    assert p.id == PROJECT_ID
    assert p.field("Status").id == "PVTSSF_status"
    assert p.option_id("Status", "In progress") == "opt_prog"


def test_an_unknown_option_is_refused_by_name_with_a_sentence():
    with pytest.raises(ps.SyncError) as err:
        project().option_id("Status", "Shipped")
    message = str(err.value)
    assert "no option named 'Shipped'" in message and "'Status'" in message
    assert "Backlog, Next, In progress, Blocked, Done" in message
    assert "never edits a field's options" in message


def test_an_unknown_field_is_refused_by_name_with_a_sentence():
    with pytest.raises(ps.SyncError, match="no field named 'Stage'.*Status"):
        project().field("Stage")


def test_validation_names_a_bad_input_before_any_mutation():
    gql = FakeGql()
    with pytest.raises(ps.SyncError, match="no option named 'Finished'"):
        ps.validate(project(), cfg(status_done="Finished"))
    assert gql.mutations == []
    with pytest.raises(ps.SyncError, match="not a date field"):
        ps.validate(project(), cfg(done_date_field="Status"))
    with pytest.raises(ps.SyncError, match="default-area"):
        ps.validate(project(), cfg(default_area_field="Area", default_area=""))
    ps.validate(project(), cfg(done_date_field="", default_area_field="Area", default_area="Hill"))


# --- one event ---------------------------------------------------------------


def test_an_opened_issue_missing_from_the_project_is_added_with_the_open_status():
    gql = FakeGql(ItemLookup="lookup_absent")
    ps.sync_content(gql, cfg(), project(), issue(), "opened")
    assert [op for op, _ in gql.mutations] == ["AddItem", "SetSelect"]
    assert gql.mutations[0][1] == {"projectId": PROJECT_ID, "contentId": "I_1"}
    assert ids(gql.mutations)[1] == (
        "SetSelect",
        {"itemId": "PVTI_new", "fieldId": "PVTSSF_status", "optionId": "opt_backlog"},
    )


def test_an_item_added_gets_the_default_area_and_only_then():
    gql = FakeGql(ItemLookup="lookup_absent")
    ps.sync_content(gql, cfg(default_area_field="Area", default_area="Hill"), project(), issue(), "opened")
    assert ("SetSelect", {"itemId": "PVTI_new", "fieldId": "PVTSSF_area", "optionId": "area_hill"}) in ids(
        gql.mutations
    )
    # Already on the board: Area, set by hand, is left alone.
    gql = FakeGql(ItemLookup="lookup_backlog")
    ps.sync_content(gql, cfg(default_area_field="Area", default_area="Hill"), project(), issue(), "edited")
    assert gql.mutations == []


def test_a_status_already_set_is_left_alone_on_an_open_issue():
    gql = FakeGql(ItemLookup="lookup_backlog")  # the item sits in Next
    ps.sync_content(gql, cfg(), project(), issue(), "opened")
    assert gql.mutations == []


def test_a_reopened_issue_that_was_done_goes_back_to_the_open_status_and_loses_its_date():
    gql = FakeGql(ItemLookup="lookup_done")
    ps.sync_content(gql, cfg(), project(), issue(), "reopened")
    assert [op for op, _ in gql.mutations] == ["SetSelect", "ClearField"]
    assert ids(gql.mutations)[0][1]["optionId"] == "opt_backlog"
    assert gql.mutations[1][1]["fieldId"] == "PVTF_doneon"


def test_an_edit_never_moves_a_done_open_item():
    gql = FakeGql(ItemLookup="lookup_done")
    ps.sync_content(gql, cfg(), project(), issue(), "edited")
    assert gql.mutations == []


def test_an_opened_pull_request_goes_to_the_pr_status_and_a_draft_to_the_draft_status():
    gql = FakeGql(ItemLookup="lookup_absent")
    ps.sync_content(gql, cfg(), project(), pull(), "opened")
    assert ids(gql.mutations)[-1][1]["optionId"] == "opt_prog"
    gql = FakeGql(ItemLookup="lookup_absent")
    ps.sync_content(gql, cfg(), project(), pull(draft=True), "opened")
    assert ids(gql.mutations)[-1][1]["optionId"] == "opt_backlog"


def test_ready_for_review_and_converted_to_draft_move_an_item_already_on_the_board():
    gql = FakeGql(ItemLookup="lookup_backlog")  # in Next
    ps.sync_content(gql, cfg(), project(), pull(), "ready_for_review")
    assert ids(gql.mutations) == [
        ("SetSelect", {"itemId": "PVTI_1", "fieldId": "PVTSSF_status", "optionId": "opt_prog"})
    ]
    gql = FakeGql(ItemLookup="lookup_backlog")
    ps.sync_content(gql, cfg(status_draft_pr="Blocked"), project(), pull(draft=True), "converted_to_draft")
    assert ids(gql.mutations)[0][1]["optionId"] == "opt_blocked"


def test_a_closed_issue_goes_to_done_with_its_close_date():
    gql = FakeGql(ItemLookup="lookup_backlog")
    ps.sync_content(gql, cfg(), project(), issue("closed", "2026-10-03T23:59:00Z"), "closed")
    assert ids(gql.mutations) == [
        ("SetSelect", {"itemId": "PVTI_1", "fieldId": "PVTSSF_status", "optionId": "opt_done"}),
        ("SetDate", {"itemId": "PVTI_1", "fieldId": "PVTF_doneon", "date": "2026-10-03"}),
    ]


def test_a_merged_pull_request_goes_to_done_with_the_merge_date():
    gql = FakeGql(ItemLookup="lookup_backlog")
    ps.sync_content(gql, cfg(), project(), pull("merged", closed_at="2026-10-04T01:02:03Z"), "closed")
    assert ids(gql.mutations)[-1] == ("SetDate", {"itemId": "PVTI_1", "fieldId": "PVTF_doneon", "date": "2026-10-04"})
    assert ids(gql.mutations)[0][1]["optionId"] == "opt_done"


def test_a_closed_item_that_is_not_on_the_board_is_added_as_done():
    gql = FakeGql(ItemLookup="lookup_absent")
    ps.sync_content(gql, cfg(), project(), issue("closed", "2026-10-03T00:00:00Z"), "closed")
    assert [op for op, _ in gql.mutations] == ["AddItem", "SetSelect", "SetDate"]


def test_an_empty_done_date_field_disables_the_date():
    gql = FakeGql(ItemLookup="lookup_backlog")
    ps.sync_content(gql, cfg(done_date_field=""), project(), issue("closed", "2026-10-03T00:00:00Z"), "closed")
    assert [op for op, _ in gql.mutations] == ["SetSelect"]


def test_closing_a_done_item_with_its_date_changes_nothing():
    gql = FakeGql(ItemLookup="lookup_done")
    ps.sync_content(gql, cfg(), project(), issue("closed", "2026-09-01T00:00:00Z"), "closed")
    assert gql.mutations == []


def test_dry_run_client_asks_for_no_mutation(monkeypatch):
    sent = []
    client = ps.Client(
        "tok", "https://example.invalid/graphql", dry_run=True, transport=lambda *a: sent.append(a) or {}
    )
    out = client("SetSelect", {"projectId": "p", "itemId": "i", "fieldId": "f", "optionId": "o"})
    assert sent == [] and out
    assert client.skipped == 1


# --- the event payload -------------------------------------------------------


def test_payload_becomes_content():
    c = ps.content_from_event(
        "pull_request_target",
        {
            "action": "closed",
            "pull_request": {
                "node_id": "PR_x",
                "number": 7,
                "state": "closed",
                "draft": False,
                "merged": True,
                "closed_at": "2026-10-04T00:00:00Z",
                "base": {"repo": {"full_name": "o/r"}},
            },
        },
    )
    assert (c.id, c.kind, c.state, c.closed_at, c.number) == ("PR_x", "pr", "merged", "2026-10-04T00:00:00Z", 7)
    c = ps.content_from_event(
        "issues",
        {
            "action": "opened",
            "issue": {"node_id": "I_x", "number": 3, "state": "open"},
            "repository": {"full_name": "o/r"},
        },
    )
    assert (c.kind, c.state, c.draft) == ("issue", "open", False)


# --- reconcile ---------------------------------------------------------------


def test_reconcile_adds_a_missing_open_issue_and_pr_and_flips_closed_items_to_done():
    gql = FakeGql(
        ProjectItems="project_items",
        RepoIssues="repo_issues",
        RepoPulls="repo_pulls",
    )
    summary = ps.reconcile(gql, cfg(reconcile=True), project(), "ChiefGyk3D/Hammunition")
    got = ids(gql.mutations)
    # I_missing added as Backlog; the draft PR added as the draft status.
    adds = [v for op, v in gql.mutations if op == "AddItem"]
    assert [a["contentId"] for a in adds] == ["I_missing", "PR_draft"]
    selects = [(v["itemId"], v["optionId"]) for op, v in gql.mutations if op == "SetSelect"]
    assert ("PVTI_5", "opt_done") in selects and ("PVTI_6", "opt_done") in selects
    assert ("PVTI_new", "opt_backlog") in selects
    dates = {v["itemId"]: v["date"] for op, v in gql.mutations if op == "SetDate"}
    assert dates == {"PVTI_5": "2026-10-01", "PVTI_6": "2026-10-02"}
    # Untouched: the tracked open issue, the Done item with a date, another repository's item, a draft issue.
    touched = {v["itemId"] for _, v in gql.mutations if "itemId" in v}
    assert not touched & {"PVTI_11", "PVTI_7", "PVTI_8", "PVTI_9"}
    assert summary == {"added": 2, "closed": 2, "reopened": 0, "dated": 0}
    assert got  # something was done


def test_reconcile_never_runs_a_per_item_lookup():
    """Rate-friendly: one walk of the board, not a query per issue."""
    gql = FakeGql(ProjectItems="project_items", RepoIssues="repo_issues", RepoPulls="repo_pulls")
    ps.reconcile(gql, cfg(reconcile=True), project(), "ChiefGyk3D/Hammunition")
    assert "ItemLookup" not in gql.calls


def test_reconcile_follows_pagination():
    page1 = fixture("project_items")
    page1["data"]["node"]["items"]["pageInfo"] = {"hasNextPage": True, "endCursor": "c1"}
    page2 = {"data": {"node": {"items": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}}}}
    seen = []

    def items(v):
        seen.append(v.get("after"))
        return page1 if v.get("after") is None else page2

    gql = FakeGql(ProjectItems=items, RepoIssues="repo_issues", RepoPulls="repo_pulls")
    ps.reconcile(gql, cfg(reconcile=True), project(), "ChiefGyk3D/Hammunition")
    assert seen == [None, "c1"]


# --- configuration -----------------------------------------------------------


def test_main_without_a_token_names_the_secret_and_exits_nonzero(monkeypatch, capsys):
    for key in list(__import__("os").environ):
        if key.startswith(("INPUT_", "PS_")) or key == "PS_TOKEN":
            monkeypatch.delenv(key)
    monkeypatch.setenv("PS_PROJECT_URL", "https://github.com/orgs/N0TST/projects/2")
    monkeypatch.setenv("PS_EVENT_NAME", "issues")
    assert ps.main() == 1
    assert "PS_TOKEN" in capsys.readouterr().out


def test_main_refuses_a_user_owned_project_before_any_api_call(monkeypatch, capsys):
    monkeypatch.setenv("PS_TOKEN", "x")
    monkeypatch.setenv("PS_PROJECT_URL", "https://github.com/users/N0CALL/projects/2")
    monkeypatch.setenv("PS_EVENT_NAME", "issues")
    monkeypatch.setattr(ps, "Client", lambda *a, **k: pytest.fail("API client built for a user project"))
    assert ps.main() == 1
    out = capsys.readouterr().out
    assert "no user-account Projects permission" in out and "permissions-required-for-github-apps" in out


def test_main_accepts_an_organization_project_past_the_check(monkeypatch, capsys):
    monkeypatch.delenv("PS_TOKEN", raising=False)
    monkeypatch.setenv("PS_PROJECT_URL", "https://github.com/orgs/N0TST/projects/2")
    monkeypatch.setenv("PS_EVENT_NAME", "issues")
    monkeypatch.setenv("PS_DRY_RUN", "true")
    assert ps.main() == 0


def test_main_dry_run_without_a_token_is_a_notice_not_a_failure(monkeypatch, capsys):
    monkeypatch.delenv("PS_TOKEN", raising=False)
    monkeypatch.setenv("PS_PROJECT_URL", "https://github.com/orgs/N0TST/projects/2")
    monkeypatch.setenv("PS_EVENT_NAME", "pull_request")
    monkeypatch.setenv("PS_DRY_RUN", "true")
    assert ps.main() == 0
    assert "dry run" in capsys.readouterr().out


# --- the workflow carries the script it was tested with ---------------------


def test_the_workflow_inlines_exactly_this_script():
    """A reusable workflow cannot check out its own commit, so the script is inlined; the copy must not drift."""
    doc = yaml.safe_load((REPO / ".github" / "workflows" / "project-sync.yml").read_text())
    runs = [s["run"] for j in doc["jobs"].values() for s in j["steps"] if "run" in s]
    body = next(r for r in runs if "<<'PROJECT_SYNC_PY'" in r)
    inlined = re.search(r"<<'PROJECT_SYNC_PY'\n(.*)\n\s*PROJECT_SYNC_PY\n", body, re.S).group(1)
    expected = SCRIPT.read_text().rstrip("\n")
    assert inlined == expected, (
        "project-sync.yml's inline script differs from scripts/project_sync.py; run scripts/inline_project_sync.py"
    )


# --- the App is the only credential -------------------------------------------

WORKFLOW = REPO / ".github" / "workflows" / "project-sync.yml"


def _workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def test_no_personal_access_token_path_remains():
    text = WORKFLOW.read_text() + SCRIPT.read_text()
    assert "PROJECTS_TOKEN" not in text and "token-secret-name" not in text and "PS_TOKEN_SECRET_NAME" not in text


def test_inputs_are_the_app_id_and_the_key_secret_name():
    # PyYAML reads the bare key `on` as True.
    inputs = _workflow()[True]["workflow_call"]["inputs"]
    assert inputs["app-id"]["required"] is True
    assert inputs["app-key-secret-name"]["default"] == "PROJECTS_APP_PRIVATE_KEY"
    assert "token-secret-name" not in inputs


def test_the_token_is_minted_by_a_pinned_app_action_scoped_to_the_calling_repository():
    steps = _workflow()["jobs"]["sync"]["steps"]
    mint = next(s for s in steps if s.get("id") == "app")
    assert re.fullmatch(r"actions/create-github-app-token@[0-9a-f]{40}", mint["uses"])
    assert re.search(r"create-github-app-token@[0-9a-f]{40} # v\d+\.\d+\.\d+", WORKFLOW.read_text())
    w = mint["with"]
    assert w["owner"] == "${{ github.repository_owner }}"
    assert w["repositories"] == "${{ github.event.repository.name }}"
    assert w["app-id"] == "${{ inputs.app-id }}"
    assert "skip-token-revoke" not in w  # the action revokes the token at job end
    sync = next(s for s in steps if s.get("name") == "Sync the project")
    assert sync["env"]["PS_TOKEN"] == "${{ steps.app.outputs.token }}"
    # the key never goes into the sync step's environment under its own name
    assert "private-key" not in sync["env"]


def test_doppler_ci_set_reads_a_multiline_value_from_a_file(tmp_path):
    import os
    import subprocess

    stub = tmp_path / "doppler"
    out = tmp_path / "got"
    stub.write_text(f"#!/bin/sh\ncat > {out}\n")
    stub.chmod(0o755)
    pem = tmp_path / "k.pem"
    pem.write_text("-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----\n")
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}
    r = subprocess.run(
        ["bash", str(REPO / "scripts" / "doppler-ci-set.sh"), "--from-file", str(pem), "PROJECTS_APP_PRIVATE_KEY"],
        env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert r.returncode == 0, r.stderr
    assert out.read_text() == "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----"  # trailing newline trimmed by $(...)
    assert "abc" not in r.stdout + r.stderr
