#!/usr/bin/env python3
"""Keep a GitHub Projects v2 board current from issue and pull request events.

Run by .github/workflows/project-sync.yml, which carries a verbatim copy of this
file (tests/test_project_sync.py checks the copy). Standard library only: the
runner has python3, a hash-checked pip install would add a supply chain for
about two hundred lines of HTTP, and `urllib` keeps the token inside this
process instead of on a `gh` command line or in its config. Everything the
script knows about GitHub goes through one callable, `gql(op, variables)`, so
the tests hand it recorded responses.

What it will never do: edit a field (`updateProjectV2Field` regenerates every
option id and wipes the board's values), touch Area, Kind, Priority, Epic or
any field it was not told about on an item that is already on the board, or
print the token.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

GRAPHQL_URL = "https://api.github.com/graphql"


class SyncError(Exception):
    """A problem the operator can fix; printed as one sentence, never a traceback."""


# --- operations ---------------------------------------------------------------

_FIELDS = """
  fields(first: 100) { nodes {
    __typename
    ... on ProjectV2FieldCommon { id name dataType }
    ... on ProjectV2SingleSelectField { options { id name } }
  } }
"""

QUERIES = {
    "ProjectUser": "query ProjectUser($login: String!, $number: Int!) { user(login: $login) { projectV2(number: $number) { id title"
    + _FIELDS
    + "} } }",
    "ProjectOrg": "query ProjectOrg($login: String!, $number: Int!) { organization(login: $login) { projectV2(number: $number) { id title"
    + _FIELDS
    + "} } }",
    # The item's current Status and done date ride along, so a lookup is one request.
    "ItemLookup": """query ItemLookup($id: ID!, $statusField: String!, $doneField: String!, $withDone: Boolean!, $after: String) {
  node(id: $id) {
    ... on Issue { projectItems(first: 50, after: $after) { ...Items } }
    ... on PullRequest { projectItems(first: 50, after: $after) { ...Items } }
  }
}
fragment Items on ProjectV2ItemConnection {
  pageInfo { hasNextPage endCursor }
  nodes {
    id
    project { id }
    status: fieldValueByName(name: $statusField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
    done: fieldValueByName(name: $doneField) @include(if: $withDone) { ... on ProjectV2ItemFieldDateValue { date } }
  }
}""",
    "ProjectItems": """query ProjectItems($id: ID!, $statusField: String!, $doneField: String!, $withDone: Boolean!, $after: String) {
  node(id: $id) {
    ... on ProjectV2 {
      items(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id
          status: fieldValueByName(name: $statusField) { ... on ProjectV2ItemFieldSingleSelectValue { name } }
          done: fieldValueByName(name: $doneField) @include(if: $withDone) { ... on ProjectV2ItemFieldDateValue { date } }
          content {
            __typename
            ... on Issue { id state closedAt repository { nameWithOwner } }
            ... on PullRequest { id state isDraft merged closedAt repository { nameWithOwner } }
          }
        }
      }
    }
  }
}""",
    "RepoIssues": """query RepoIssues($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    issues(states: OPEN, first: 100, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes { id number state closedAt }
    }
  }
}""",
    "RepoPulls": """query RepoPulls($owner: String!, $name: String!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: 100, after: $after) {
      pageInfo { hasNextPage endCursor }
      nodes { id number state isDraft merged closedAt }
    }
  }
}""",
    "AddItem": """mutation AddItem($projectId: ID!, $contentId: ID!) {
  addProjectV2ItemById(input: {projectId: $projectId, contentId: $contentId}) { item { id } }
}""",
    "SetSelect": """mutation SetSelect($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
  ok: updateProjectV2ItemFieldValue(input: {projectId: $projectId, itemId: $itemId, fieldId: $fieldId, value: {singleSelectOptionId: $optionId}}) { clientMutationId }
}""",
    "SetDate": """mutation SetDate($projectId: ID!, $itemId: ID!, $fieldId: ID!, $date: Date!) {
  ok: updateProjectV2ItemFieldValue(input: {projectId: $projectId, itemId: $itemId, fieldId: $fieldId, value: {date: $date}}) { clientMutationId }
}""",
    "ClearField": """mutation ClearField($projectId: ID!, $itemId: ID!, $fieldId: ID!) {
  ok: clearProjectV2ItemFieldValue(input: {projectId: $projectId, itemId: $itemId, fieldId: $fieldId}) { clientMutationId }
}""",
}
MUTATIONS = {"AddItem", "SetSelect", "SetDate", "ClearField"}

Gql = Callable[[str, dict], dict]


# --- the GitHub client ----------------------------------------------------------


def _post(url: str, token: str, body: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "git-your-ship-together-project-sync",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - the URL is fixed https
        return json.load(response)


class Client:
    """`gql(op, variables)`: retries transient failures, skips mutations in a dry run."""

    def __init__(self, token: str, url: str = GRAPHQL_URL, dry_run: bool = False, transport=None):
        self._token, self._url, self.dry_run = token, url, dry_run
        self._transport = transport or _post
        self.skipped = 0

    def __call__(self, op: str, variables: dict) -> dict:
        if op in MUTATIONS and self.dry_run:
            self.skipped += 1
            print(f"dry run: would {op} {json.dumps(variables, sort_keys=True)}")
            return {"data": {"addProjectV2ItemById": {"item": {"id": "DRY_RUN"}}, "ok": {}}}
        for attempt in range(4):
            try:
                out = self._transport(self._url, self._token, {"query": QUERIES[op], "variables": variables})
            except urllib.error.HTTPError as err:
                if err.code in (401, 403):
                    raise SyncError(
                        f"GitHub refused the token ({err.code}) on {op}. It needs user Projects read/write and "
                        "repository Issues and Pull requests read; see the README, 'Keeping a project current'."
                    ) from None
                if err.code in (500, 502, 503, 504) and attempt < 3:
                    time.sleep(2**attempt)
                    continue
                raise SyncError(f"GitHub answered {err.code} to {op}.") from None
            except (urllib.error.URLError, TimeoutError) as err:
                if attempt < 3:
                    time.sleep(2**attempt)
                    continue
                raise SyncError(f"Could not reach GitHub for {op}: {err}.") from None
            if out.get("errors"):
                messages = "; ".join(str(e.get("message", e)) for e in out["errors"])
                if "RATE_LIMITED" in json.dumps(out["errors"]) and attempt < 3:
                    time.sleep(30 * (attempt + 1))
                    continue
                raise SyncError(f"GitHub rejected {op}: {messages}")
            return out
        raise SyncError(f"GitHub kept failing {op}.")


# --- configuration and the project -------------------------------------------


@dataclass(frozen=True)
class Config:
    project_url: str
    status_field: str
    status_open_issue: str
    status_open_pr: str
    status_draft_pr: str
    status_done: str
    done_date_field: str
    reconcile: bool
    default_area_field: str
    default_area: str
    dry_run: bool


@dataclass(frozen=True)
class Field:
    id: str
    name: str
    data_type: str
    options: dict[str, str]


@dataclass(frozen=True)
class Project:
    id: str
    fields: dict[str, Field]

    def field(self, name: str) -> Field:
        if name not in self.fields:
            raise SyncError(
                f"The project has no field named '{name}'. Its fields are: {', '.join(self.fields)}. "
                "Check the input that names it; this workflow never creates or renames a field."
            )
        return self.fields[name]

    def option_id(self, field: str, option: str) -> str:
        found = self.field(field)
        if option not in found.options:
            raise SyncError(
                f"The field '{field}' has no option named '{option}'. Its options are: {', '.join(found.options)}. "
                "Fix the input, or add the option in the project's own settings; this workflow never edits a "
                "field's options, because that regenerates every option id and wipes the board's values."
            )
        return found.options[option]


def parse_project_url(url: str) -> tuple[str, str, int]:
    m = re.fullmatch(r"https://github\.com/(users|orgs)/([A-Za-z0-9-]+)/projects/(\d+)/?", url.strip())
    if not m:
        raise SyncError(
            f"'{url}' is not a GitHub Projects v2 URL. Expected https://github.com/users/<login>/projects/<n> "
            "or https://github.com/orgs/<login>/projects/<n>."
        )
    return ("user" if m[1] == "users" else "org"), m[2], int(m[3])


def load_project(gql: Gql, url: str) -> Project:
    kind, login, number = parse_project_url(url)
    op = "ProjectUser" if kind == "user" else "ProjectOrg"
    owner = gql(op, {"login": login, "number": number})["data"]["user" if kind == "user" else "organization"]
    node = owner and owner["projectV2"]
    if not node:
        raise SyncError(f"No project {number} under {login}, or the token cannot see it.")
    fields = {
        f["name"]: Field(f["id"], f["name"], f.get("dataType", ""), {o["name"]: o["id"] for o in f.get("options") or []})
        for f in node["fields"]["nodes"]
        if f
    }
    return Project(node["id"], fields)


def validate(project: Project, cfg: Config) -> None:
    """Every name the run will use, checked before the first mutation."""
    for name in (cfg.status_open_issue, cfg.status_open_pr, cfg.status_draft_pr, cfg.status_done):
        project.option_id(cfg.status_field, name)
    if cfg.done_date_field and project.field(cfg.done_date_field).data_type != "DATE":
        raise SyncError(f"The field '{cfg.done_date_field}' is not a date field; done-date-field must name one.")
    if bool(cfg.default_area_field) != bool(cfg.default_area):
        raise SyncError("default-area-field and default-area go together: set both or neither.")
    if cfg.default_area_field:
        project.option_id(cfg.default_area_field, cfg.default_area)


# --- items --------------------------------------------------------------------


@dataclass(frozen=True)
class Content:
    id: str
    kind: str  # issue | pr
    state: str  # open | closed | merged
    draft: bool
    closed_at: str | None
    number: int
    repo: str


@dataclass
class Item:
    id: str
    status: str | None
    done: str | None


def _item(node: dict) -> Item:
    return Item(node["id"], (node.get("status") or {}).get("name"), (node.get("done") or {}).get("date"))


def find_item(gql: Gql, cfg: Config, project: Project, content_id: str) -> Item | None:
    after = None
    while True:
        out = gql(
            "ItemLookup",
            {
                "id": content_id,
                "statusField": cfg.status_field,
                "doneField": cfg.done_date_field or "-",
                "withDone": bool(cfg.done_date_field),
                "after": after,
            },
        )["data"]["node"]
        conn = out["projectItems"]
        for node in conn["nodes"]:
            if node["project"]["id"] == project.id:
                return _item(node)
        if not conn["pageInfo"]["hasNextPage"]:
            return None
        after = conn["pageInfo"]["endCursor"]


def target_status(cfg: Config, c: Content, action: str, current: str | None) -> str | None:
    """The status this content should move to, or None to leave it where it is."""
    if c.state in ("closed", "merged"):
        return None if current == cfg.status_done else cfg.status_done
    if c.kind == "issue":
        if current is None or (current == cfg.status_done and action == "reopened"):
            return cfg.status_open_issue
        return None
    wanted = cfg.status_draft_pr if c.draft else cfg.status_open_pr
    if action in ("opened", "ready_for_review", "converted_to_draft", "reopened"):
        return wanted if current != wanted else None
    return wanted if current is None else None


def _date_of(c: Content) -> str:
    return (c.closed_at or datetime.now(UTC).isoformat())[:10]


def sync_content(
    gql: Gql, cfg: Config, project: Project, c: Content, action: str, item: Item | None = None, known_absent: bool = False
) -> list[str]:
    """Bring one issue or pull request's item in line with its state. Returns what it did."""
    done: list[str] = []
    if item is None and not known_absent:
        item = find_item(gql, cfg, project, c.id)
    if item is None:
        added = gql("AddItem", {"projectId": project.id, "contentId": c.id})["data"]["addProjectV2ItemById"]["item"]["id"]
        item = Item(added, None, None)
        done.append(f"added #{c.number}")
        if cfg.default_area_field:
            gql(
                "SetSelect",
                {
                    "projectId": project.id,
                    "itemId": item.id,
                    "fieldId": project.field(cfg.default_area_field).id,
                    "optionId": project.option_id(cfg.default_area_field, cfg.default_area),
                },
            )
            done.append(f"{cfg.default_area_field} = {cfg.default_area}")
    target = target_status(cfg, c, action, item.status)
    if target:
        gql(
            "SetSelect",
            {
                "projectId": project.id,
                "itemId": item.id,
                "fieldId": project.field(cfg.status_field).id,
                "optionId": project.option_id(cfg.status_field, target),
            },
        )
        done.append(f"#{c.number} {cfg.status_field} = {target}")
    if cfg.done_date_field:
        date_id = project.field(cfg.done_date_field).id
        closed = c.state in ("closed", "merged")
        if closed and item.done is None:
            gql("SetDate", {"projectId": project.id, "itemId": item.id, "fieldId": date_id, "date": _date_of(c)})
            done.append(f"#{c.number} {cfg.done_date_field} = {_date_of(c)}")
        elif not closed and target and item.status == cfg.status_done and item.done is not None:
            gql("ClearField", {"projectId": project.id, "itemId": item.id, "fieldId": date_id})
            done.append(f"#{c.number} {cfg.done_date_field} cleared")
    return done


def content_from_event(event_name: str, payload: dict) -> Content:
    repo = (payload.get("repository") or {}).get("full_name", "")
    if "pull_request" in payload:
        pr = payload["pull_request"]
        state = "merged" if pr.get("merged") else pr["state"]
        return Content(pr["node_id"], "pr", state, bool(pr.get("draft")), pr.get("closed_at"), pr["number"], repo)
    if "issue" in payload:
        issue = payload["issue"]
        return Content(issue["node_id"], "issue", issue["state"], False, issue.get("closed_at"), issue["number"], repo)
    raise SyncError(f"The {event_name} event carries neither an issue nor a pull request.")


# --- reconcile ------------------------------------------------------------------


def _pages(gql: Gql, op: str, variables: dict, path: tuple[str, ...]):
    after = None
    while True:
        node = gql(op, {**variables, "after": after})["data"]
        for key in path:
            node = node[key]
        yield from node["nodes"]
        if not node["pageInfo"]["hasNextPage"]:
            return
        after = node["pageInfo"]["endCursor"]


def reconcile(gql: Gql, cfg: Config, project: Project, repo: str) -> dict[str, int]:
    """One walk of the board and one of the repository's open work; no query per item."""
    owner, name = repo.split("/", 1)
    summary = {"added": 0, "closed": 0, "reopened": 0, "dated": 0}
    on_board: dict[str, Item] = {}
    closed_here: list[tuple[Content, Item]] = []
    variables = {
        "id": project.id,
        "statusField": cfg.status_field,
        "doneField": cfg.done_date_field or "-",
        "withDone": bool(cfg.done_date_field),
    }
    for node in _pages(gql, "ProjectItems", variables, ("node", "items")):
        content = node.get("content") or {}
        if content.get("__typename") not in ("Issue", "PullRequest"):
            continue  # a draft issue or an item the token cannot read
        item = _item(node)
        on_board[content["id"]] = item
        if content["repository"]["nameWithOwner"].lower() != repo.lower():
            continue
        state = "merged" if content.get("merged") else content["state"].lower()
        if state in ("closed", "merged"):
            kind = "pr" if content["__typename"] == "PullRequest" else "issue"
            c = Content(content["id"], kind, state, False, content.get("closedAt"), 0, repo)
            closed_here.append((c, item))
    repo_vars = {"owner": owner, "name": name}
    open_work = [
        Content(n["id"], "issue", "open", False, None, n["number"], repo)
        for n in _pages(gql, "RepoIssues", repo_vars, ("repository", "issues"))
    ] + [
        Content(n["id"], "pr", "open", bool(n["isDraft"]), None, n["number"], repo)
        for n in _pages(gql, "RepoPulls", repo_vars, ("repository", "pullRequests"))
    ]
    for c in open_work:
        item = on_board.get(c.id)
        if item is None:
            sync_content(gql, cfg, project, c, "reconcile", known_absent=True)
            summary["added"] += 1
        # An open item already on the board keeps whatever status it has: reconcile never reopens.
    for c, item in closed_here:
        steps = sync_content(gql, cfg, project, c, "closed", item=item)
        summary["closed"] += any("Status" in s or cfg.status_field in s for s in steps)
        summary["dated"] += any(cfg.done_date_field and cfg.done_date_field in s for s in steps) and not any(
            cfg.status_field in s for s in steps
        )
    return summary


# --- entry point --------------------------------------------------------------------


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes")


def config_from_env(env=os.environ) -> Config:
    return Config(
        project_url=env.get("PS_PROJECT_URL", ""),
        status_field=env.get("PS_STATUS_FIELD", "Status"),
        status_open_issue=env.get("PS_STATUS_OPEN_ISSUE", "Backlog"),
        status_open_pr=env.get("PS_STATUS_OPEN_PR", "In progress"),
        status_draft_pr=env.get("PS_STATUS_DRAFT_PR", "Backlog"),
        status_done=env.get("PS_STATUS_DONE", "Done"),
        done_date_field=env.get("PS_DONE_DATE_FIELD", "Done on"),
        reconcile=_bool(env.get("PS_RECONCILE", "false")),
        default_area_field=env.get("PS_DEFAULT_AREA_FIELD", ""),
        default_area=env.get("PS_DEFAULT_AREA", ""),
        dry_run=_bool(env.get("PS_DRY_RUN", "false")),
    )


def main() -> int:
    env = os.environ
    cfg = config_from_env(env)
    event_name = env.get("PS_EVENT_NAME", "")
    secret_name = env.get("PS_TOKEN_SECRET_NAME", "PROJECTS_TOKEN")
    token = env.get(secret_name, "")
    try:
        if not cfg.project_url:
            raise SyncError("project-url is empty.")
        parse_project_url(cfg.project_url)
        if not token:
            if cfg.dry_run:
                print(f"::notice title=project-sync::dry run with no {secret_name}; nothing to read, nothing sent")
                return 0
            raise SyncError(
                f"No token: the environment has no {secret_name}. Put a fine-grained token with user Projects "
                "read/write in the Doppler config the doppler-* inputs name, under that name; see the README, "
                "'Keeping a project current'."
            )
        gql = Client(token, env.get("GITHUB_GRAPHQL_URL", GRAPHQL_URL), dry_run=cfg.dry_run)
        project = load_project(gql, cfg.project_url)
        validate(project, cfg)
        repo = env.get("GITHUB_REPOSITORY", "")
        if event_name in ("schedule", "workflow_dispatch"):
            if cfg.reconcile:
                print(f"reconcile {repo}: {reconcile(gql, cfg, project, repo)}")
            else:
                print(f"{event_name} with reconcile off: nothing to do")
            return 0
        path = env.get("PS_EVENT_PATH") or env.get("GITHUB_EVENT_PATH", "")
        if not path:
            raise SyncError(f"The {event_name} event has no payload file.")
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        content = content_from_event(event_name, payload)
        done = sync_content(gql, cfg, project, content, payload.get("action", ""))
        print("; ".join(done) if done else f"#{content.number}: already current")
        return 0
    except SyncError as err:
        print(f"::error title=project-sync::{err}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
