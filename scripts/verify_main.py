#!/usr/bin/env python3
"""Verify that the head of the default branch has a green run of every required check.

Why it exists: a push made with the job token (a bot's auto-merge, for example) does not start workflow runs, so a
commit can land on the default branch with no CI at all. This script is what `main-verify.yml` runs to notice that,
start CI by workflow_dispatch (the one event the job token may start), and fail loudly if main is still not green.

Stdlib only. Three phases, each one job of the workflow, so the one that may write holds nothing else:

    assess    read the head commit and the required checks on it. All green: verdict `green`, quiet. Any red: fail.
              Some reported, some not yet: verdict `pending`. None reported: wait until the commit is GRACE seconds
              old (CI normally starts within that), then verdict `dispatch` unless a run of the CI workflow for this
              commit is already queued or running (then `pending`).
    dispatch  (`actions: write` is only here) start the CI workflow on the default branch by workflow_dispatch,
              unless the head moved since assess (then the new head is somebody's push and has its own runs).
    confirm   re-read the head and wait, bounded, until every required check has completed. Fail if one is red or
              if any is still missing or running when the wait ends.

Required checks come from the branch protection (`required_status_checks`) when the token can read it, else from
--fallback-contexts. A check run only counts when it comes from the pinned app (the protection's app id when it
names one, else GitHub Actions), so another app cannot satisfy a required name.

Output is counts and context names (printed JSON-escaped, so a name cannot forge a workflow command). Every wait has
a deadline and every request a timeout. The only secret is GITHUB_TOKEN, sent to the API host only; a redirect is
refused. Writes `verdict=` and `sha=` to $GITHUB_OUTPUT when set.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

API = "https://api.github.com"
API_VERSION = "2022-11-28"
ACTIONS_APP_ID = 15368
TIMEOUT = 20
MAX_BYTES = 4 << 20
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
WORKFLOW = re.compile(r"[A-Za-z0-9_.-]{1,100}\.ya?ml")
SHA = re.compile(r"[0-9a-f]{40}")
MAX_CONTEXTS = 20
DEFAULT_GRACE = 600
DEFAULT_POLL = 30
DEFAULT_WAIT = 1500


class ApiError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class Failure(Exception):
    """A verdict that fails the job; the message is the annotation."""


def q(value: object) -> str:
    """A value from outside this script, printed so it cannot forge a log line or a workflow command."""
    return json.dumps(str(value)[:200])


class Api:
    """The few GitHub REST calls this script makes. Tests replace it with a stub that has the same two methods."""

    def __init__(self, base: str, token: str):
        parts = urllib.parse.urlsplit(base)
        loopback = parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost")
        if not (parts.scheme == "https" or loopback) or not parts.hostname:
            raise ValueError("the API base must be https (or http on loopback)")
        self.base = base.rstrip("/")
        self.token = token

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise urllib.error.HTTPError(req.full_url, code, "redirects are refused", headers, fp)

        self.opener = urllib.request.build_opener(NoRedirect)

    def _call(self, method: str, path: str, body: dict | None = None):
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "gyst-main-verify",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        shown = f"{method} {path.split('?')[0]}"
        try:
            with self.opener.open(request, timeout=TIMEOUT) as reply:
                raw = reply.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise ApiError(f"{shown} answered HTTP {exc.code}", exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ApiError(f"{shown} failed ({type(exc).__name__})") from exc
        if len(raw) > MAX_BYTES:
            raise ApiError(f"{shown} returned more than {MAX_BYTES} bytes")
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise ApiError(f"{shown} did not answer JSON") from exc

    def get(self, path: str):
        return self._call("GET", path)

    def post(self, path: str, body: dict):
        return self._call("POST", path, body)


@dataclass(frozen=True)
class Required:
    context: str
    app_id: int


@dataclass
class Tally:
    green: list[str] = field(default_factory=list)
    red: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def reported(self) -> int:
        return len(self.green) + len(self.red) + len(self.pending)

    def counts(self) -> str:
        return (
            f"{len(self.green) + len(self.red) + len(self.pending) + len(self.missing)} required: "
            f"{len(self.green)} green, {len(self.red)} red, {len(self.pending)} running, {len(self.missing)} missing"
        )

    def names(self) -> str:
        bits = []
        for label in ("red", "pending", "missing"):
            names = getattr(self, label)
            if names:
                bits.append(f"{label}: {', '.join(q(n) for n in names)}")
        return "; ".join(bits)


def parse_fallback(text: str) -> list[Required]:
    names = [part.strip() for part in text.split(",") if part.strip()]
    if not names or len(names) > MAX_CONTEXTS:
        raise Failure(f"--fallback-contexts must name between 1 and {MAX_CONTEXTS} comma separated contexts")
    return [Required(name, ACTIONS_APP_ID) for name in dict.fromkeys(names)]


def required_checks(api, repo: str, branch: str, fallback: str) -> tuple[list[Required], str]:
    """(checks, where they came from). The protection when readable and non-empty, else the fallback list."""
    path = f"/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}/protection/required_status_checks"
    try:
        doc = api.get(path)
    except ApiError as exc:
        if exc.status not in (401, 403, 404):
            raise
        return parse_fallback(fallback), f"fallback list (the branch protection is not readable: HTTP {exc.status})"
    found: dict[str, int] = {}
    for item in doc.get("checks") or []:
        if isinstance(item, dict) and isinstance(item.get("context"), str):
            app = item.get("app_id")
            found[item["context"]] = app if isinstance(app, int) and app > 0 else ACTIONS_APP_ID
    for name in doc.get("contexts") or []:
        if isinstance(name, str):
            found.setdefault(name, ACTIONS_APP_ID)
    if not found:
        return parse_fallback(fallback), "fallback list (the branch protection requires no status check)"
    if len(found) > MAX_CONTEXTS:
        raise Failure(f"the branch protection requires more than {MAX_CONTEXTS} checks")
    return [Required(n, a) for n, a in found.items()], "branch protection"


def read_head(api, repo: str, branch: str) -> tuple[str, float]:
    """(commit id, age in seconds) of the branch head."""
    doc = api.get(f"/repos/{repo}/branches/{urllib.parse.quote(branch, safe='')}")
    commit = doc.get("commit") or {}
    sha = commit.get("sha")
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise Failure("the API did not answer a commit id for the default branch")
    stamp = ((commit.get("commit") or {}).get("committer") or {}).get("date")
    try:
        when = datetime.strptime(str(stamp), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return sha, 0.0  # an unreadable date counts as "just now": wait the full grace, never dispatch early
    return sha, max(0.0, (datetime.now(UTC) - when).total_seconds())


def evaluate(api, repo: str, sha: str, required: list[Required]) -> Tally:
    tally = Tally()
    for item in required:
        query = urllib.parse.urlencode({"check_name": item.context, "filter": "latest", "per_page": 100})
        doc = api.get(f"/repos/{repo}/commits/{sha}/check-runs?{query}")
        runs = [
            r
            for r in doc.get("check_runs") or []
            if isinstance(r, dict) and r.get("name") == item.context and (r.get("app") or {}).get("id") == item.app_id
        ]
        if not runs:
            tally.missing.append(item.context)
        elif any(r.get("status") != "completed" for r in runs):
            tally.pending.append(item.context)
        elif all(r.get("conclusion") == "success" for r in runs):
            tally.green.append(item.context)
        else:
            tally.red.append(item.context)
    return tally


def has_live_run(api, repo: str, workflow: str, sha: str) -> bool:
    query = urllib.parse.urlencode({"head_sha": sha, "per_page": 100})
    doc = api.get(f"/repos/{repo}/actions/workflows/{workflow}/runs?{query}")
    return any(isinstance(r, dict) and r.get("status") != "completed" for r in doc.get("workflow_runs") or [])


def fail_red(tally: Tally, sha: str) -> Failure:
    return Failure(f"main head {sha[:12]} has a failing required check ({tally.counts()}; {tally.names()})")


def default_branch(api, repo: str) -> str:
    branch = api.get(f"/repos/{repo}").get("default_branch")
    if not isinstance(branch, str) or not branch:
        raise Failure("the API did not answer the default branch")
    return branch


def assess(api, repo, workflow, fallback, grace, poll, clock, sleep, out) -> str:
    branch = default_branch(api, repo)
    required, source = required_checks(api, repo, branch, fallback)
    sha, age = read_head(api, repo, branch)
    print(f"main head {sha[:12]}, {int(age)}s old; required checks from {source}")
    deadline = clock() + min(max(0.0, grace - age), float(grace))
    while True:
        tally = evaluate(api, repo, sha, required)
        if tally.red:
            raise fail_red(tally, sha)
        if len(tally.green) == len(required):
            print(f"ok   main head {sha[:12]}: {tally.counts()}")
            return finish(out, "green", sha)
        if tally.reported:
            print(f"main head {sha[:12]} is still running: {tally.counts()}")
            return finish(out, "pending", sha)
        if clock() >= deadline:
            break
        sleep(poll)
        newer, _ = read_head(api, repo, branch)
        if newer != sha:  # somebody pushed; that push has its own runs and its own verify
            print(f"main moved from {sha[:12]} to {newer[:12]}; assessing the new head")
            sha = newer
    if has_live_run(api, repo, workflow, sha):
        print(f"main head {sha[:12]}: no required check has reported but a {workflow} run is queued or running")
        return finish(out, "pending", sha)
    print(f"main head {sha[:12]}: {tally.counts()}; no required check reported within {grace}s, dispatching {workflow}")
    return finish(out, "dispatch", sha)


def finish(out: str | None, verdict: str, sha: str) -> str:
    if out:
        with open(out, "a", encoding="utf-8") as handle:
            handle.write(f"verdict={verdict}\nsha={sha}\n")
    return verdict


def dispatch(api, repo, workflow, sha) -> None:
    branch = default_branch(api, repo)
    head, _ = read_head(api, repo, branch)
    if sha and head != sha:
        print(f"main moved from {sha[:12]} to {head[:12]} since the assessment; not dispatching for the old head")
        return
    api.post(f"/repos/{repo}/actions/workflows/{workflow}/dispatches", {"ref": branch})
    print(f"dispatched {workflow} on {branch} (head {head[:12]})")


def confirm(api, repo, fallback, wait, poll, clock, sleep) -> None:
    branch = default_branch(api, repo)
    required, source = required_checks(api, repo, branch, fallback)
    deadline = clock() + wait
    while True:
        sha, _ = read_head(api, repo, branch)
        tally = evaluate(api, repo, sha, required)
        if tally.red:
            raise fail_red(tally, sha)
        if len(tally.green) == len(required):
            print(f"ok   main head {sha[:12]}: {tally.counts()} (required checks from {source})")
            return
        if clock() >= deadline:
            raise Failure(
                f"main head {sha[:12]} has no completed green required check after {wait}s "
                f"({tally.counts()}; {tally.names()})"
            )
        sleep(poll)


def main(argv: list[str], api=None, clock: Callable[[], float] = time.monotonic, sleep=time.sleep) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("phase", choices=("assess", "dispatch", "confirm"))
    parser.add_argument("--fallback-contexts", default="CI green")
    parser.add_argument("--workflow", default="ci.yml")
    parser.add_argument("--sha", default="")
    parser.add_argument("--grace-seconds", type=int, default=DEFAULT_GRACE)
    parser.add_argument("--wait-seconds", type=int, default=DEFAULT_WAIT)
    parser.add_argument("--poll-seconds", type=int, default=DEFAULT_POLL)
    parser.add_argument("--api-base", default=API)
    args = parser.parse_args(argv)
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not REPO.fullmatch(repo):
        parser.error("GITHUB_REPOSITORY is not owner/name")
    if not WORKFLOW.fullmatch(args.workflow):
        parser.error("--workflow must be a workflow file name such as ci.yml")
    if args.sha and not SHA.fullmatch(args.sha):
        parser.error("--sha must be a 40 character commit id")
    if not (0 <= args.grace_seconds <= 3600 and 1 <= args.wait_seconds <= 7200 and 1 <= args.poll_seconds <= 300):
        parser.error("--grace-seconds, --wait-seconds or --poll-seconds is outside its bound")
    try:
        api = api or Api(args.api_base, os.environ.get("GITHUB_TOKEN", ""))
    except ValueError as exc:
        parser.error(str(exc))
    try:
        if args.phase == "assess":
            assess(
                api,
                repo,
                args.workflow,
                args.fallback_contexts,
                args.grace_seconds,
                args.poll_seconds,
                clock,
                sleep,
                os.environ.get("GITHUB_OUTPUT"),
            )
        elif args.phase == "dispatch":
            dispatch(api, repo, args.workflow, args.sha)
        else:
            confirm(api, repo, args.fallback_contexts, args.wait_seconds, args.poll_seconds, clock, sleep)
    except (Failure, ApiError) as exc:
        print(f"::error title=main-verify::{exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
