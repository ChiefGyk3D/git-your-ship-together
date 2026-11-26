#!/usr/bin/env python3
"""Check every repository in baseline/repos.txt against BASELINE.md.

Each check is a question with a yes/no answer read from GitHub's API. A
question the token could not ask - a 403 from a proxy, a 404 on an endpoint
this account does not have - is reported as UNKNOWN, never as a pass: "we
could not check" and "it is fine" are different answers, and the exit code
tells them apart.

    python scripts/audit_baseline.py                 # every repo in baseline/repos.txt
    python scripts/audit_baseline.py owner/repo ...  # just these
    python scripts/audit_baseline.py --allow-unknown # exit 0 on unknowns
    python scripts/audit_baseline.py --expiring 14   # register entries due within 14 days; no token needed
    python scripts/audit_baseline.py --owner-token ChiefGyk3D=TOKEN_A --owner-token Org=TOKEN_B

With `--owner-token OWNER=ENVVAR`, each repository is read with the token held
in ENVVAR for its owner (the weekly audit mints one GitHub App installation
token per owner); an owner with no token, or an empty one, is UNKNOWN, never
read with somebody else's. Without it, one token is used for every owner.
When a repository's owner is an organization, the organization itself is
audited once as well (`org-*` checks, see BASELINE.md "Organizations").

Exit 0: every check passed. Exit 1: at least one FAIL. Exit 2: no FAIL but at
least one UNKNOWN (unless --allow-unknown). The token comes from GITHUB_TOKEN
or GH_TOKEN, else `gh auth token`; it needs admin read on each repository to
see settings, which the owner's own token has.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import email.utils
import http.client
import json
import math
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

API = "https://api.github.com"
GATE = "CI green"  # the last job of every shared `*-ci.yml`; a caller's job `ci:` reports it as `ci / CI green`
REQUIRED_CHECK = f"ci / {GATE}"  # what a caller with no derivable gate is held to
SHARED_REPO = "ChiefGyk3D/git-your-ship-together"
SHARED_REPO_CHECK = GATE  # this repository runs the gate directly, so the check has no `ci /` prefix
REUSABLE_PREFIX = "ChiefGyk3D/git-your-ship-together/"
# A caller job that uses one of the shared CI workflows, or the gate on its own
# (`ci-gate.yml`, which is how a security-only caller gets a `CI green`). The
# release and security workflows have no gate, so a job calling them is not a check.
SHARED_CI_CALL = re.compile(
    r"^\s+uses:\s*" + re.escape(REUSABLE_PREFIX) + r"\.github/workflows/(?:[A-Za-z0-9_-]+-ci|ci-gate)\.ya?ml@"
)
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<action>[^@\s]+)@(?P<ref>\S+)(?P<rest>.*)$")
VERSION_COMMENT = re.compile(r"^\s*#\s*v\d+\.\d+(\.\d+)?\s*$")
IGNORE_VULN = re.compile(r"--ignore-vuln[\s=]+([A-Za-z0-9-]+)")
# Same-line whitespace only: `\s*` would cross the newline of a bare input
# declaration and capture the `type:` line beneath it.
ALLOW_GHSAS = re.compile(r"^[ \t]*dependency-review-allow-ghsas:[ \t]*(\S.*?)[ \t]*$", re.M)
# verify-published.yml's rescan: the same shape, read by the same rule.
RESCAN_IGNORE = re.compile(r"^[ \t]*rescan-ignore-advisories:[ \t]*(\S.*?)[ \t]*$", re.M)
REGISTER = Path(__file__).resolve().parent.parent / "baseline" / "risk-register.yaml"
PRE_COMMIT_HOOK = Path(__file__).resolve().parent.parent / ".githooks" / "pre-commit"

PASS, FAIL, UNKNOWN = "PASS", "FAIL", "UNKNOWN"

# A fetcher answers (status code, decoded JSON body or {}) for an API path.
Fetcher = Callable[[str], tuple[int, dict | list]]


@dataclass(frozen=True)
class Result:
    repo: str
    check: str
    status: str
    detail: str


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: the request carries the token, and no API answer here needs one followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirects)


FETCH_ATTEMPTS = 3
RETRY_WAITS = (1.0, 2.0)  # between attempts; a Retry-After header may lengthen one, never past the cap
RETRY_AFTER_CAP = 10.0
RETRYABLE_STATUS = {429, 500, 502, 503, 504}
_sleep = time.sleep


_now = lambda: dt.datetime.now(dt.UTC)  # noqa: E731 - replaced by tests
MAX_ERROR_BODY = 64 * 1024
MALFORMED_ERROR = "malformed HTTP error"
MAX_BODY = 4 * 1024 * 1024


class _BodyTooLarge(ValueError):
    pass


# Wall-clock limits. The socket timeout bounds one wait, not the request: a peer that sends a byte every
# 29 seconds would otherwise hold the whole sequential audit open. All three are checked against `_clock`.
REQUEST_DEADLINE = 60.0  # one request, body read included
REPO_DEADLINE = 180.0  # every check of one repository, retries and their waits included
AUDIT_DEADLINE = 45 * 60.0  # the whole run; later repositories report UNKNOWN
_clock = time.monotonic
_limits: dict[str, float | None] = {"repo": None, "audit": None}  # absolute `_clock` times


class _DeadlineExceeded(TimeoutError):
    pass


@contextlib.contextmanager
def _alarm(seconds: float):
    """Interrupt whatever is running in this block after `seconds` of real time, as `_DeadlineExceeded`.

    The socket timeout bounds one wait and the chunk check bounds one chunk; neither stops a read that keeps
    receiving a byte now and then, or a slow DNS lookup or connect. A POSIX interval timer does, the same way
    scripts/check_pr_title.py stops a catastrophic regular expression. It needs SIGALRM and the main thread (the
    audit's own); where either is missing the block runs under the chunk checks alone.
    """
    import threading

    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        yield
        return

    def expired(_signum: int, _frame: object) -> None:
        raise _DeadlineExceeded

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, max(0.001, seconds))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _limit(request_seconds: float | None = None) -> float:
    """The earliest of the request, repository and audit deadlines, as an absolute `_clock` time."""
    seconds = REQUEST_DEADLINE if request_seconds is None else request_seconds
    return min([_clock() + seconds, *(v for v in _limits.values() if v is not None)])


def _read_capped(stream: object, cap: int, limit: float | None = None) -> bytes:
    """At most `cap` bytes of a response body, read in chunks against a wall-clock limit.

    One byte more than the cap is an error, not a truncation, and so is a body that is still arriving at the limit.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        if limit is not None and _clock() > limit:
            raise _DeadlineExceeded
        chunk = stream.read(min(8192, cap + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > cap:
            raise _BodyTooLarge


def _error_body(err: urllib.error.HTTPError, token: str, limit: float | None = None) -> dict | list:
    """An HTTP error's body, or a fixed message naming only the class of whatever went wrong reading it."""
    try:
        raw = _read_capped(err, MAX_ERROR_BODY, limit)
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"message": raw.decode("utf-8")[:200]}
    except (OSError, http.client.HTTPException, UnicodeError, ValueError) as bad:
        return {"message": f"HTTP error body unreadable: {type(bad).__name__}"}
    if isinstance(body, dict) and "message" in body:
        if type(body["message"]) is not str:
            body["message"] = MALFORMED_ERROR
        elif token:
            body["message"] = body["message"].replace(token, "***")  # a server that echoes the token
    return body


def _retry_after(value: object) -> float | None:
    """Seconds a Retry-After header asks for: ASCII delta-seconds or an HTTP date; None when it is neither."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if re.fullmatch(r"[0-9]{1,6}", value):
        return float(int(value))
    try:
        when = email.utils.parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.UTC)
        return max(0.0, (when - _now()).total_seconds())
    except Exception:  # any malformed date: the normal backoff applies
        return None


def _retry_wait(attempt: int, headers: object) -> float:
    wait = RETRY_WAITS[min(attempt, len(RETRY_WAITS) - 1)]
    try:
        asked = _retry_after(headers.get("Retry-After")) if headers is not None else None
    except Exception:
        asked = None
    if asked is not None:
        wait = max(wait, asked)
    return min(wait, RETRY_AFTER_CAP)


def _wait(seconds: float) -> bool:
    """Sleep before a retry, unless that would run past the repository or audit deadline (then False)."""
    ends = [v for v in _limits.values() if v is not None]
    if ends and _clock() + seconds >= min(ends):
        return False
    _sleep(seconds)
    return True


def _is_timeout(err: BaseException) -> bool:
    return isinstance(err, TimeoutError) or (
        isinstance(err, urllib.error.URLError) and isinstance(err.reason, TimeoutError)
    )


def github_fetcher(token: str) -> Fetcher:
    def once(path: str, limit: float) -> tuple[int, dict | list, object]:
        req = urllib.request.Request(
            API + path,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with _alarm(limit - _clock()):
            with _OPENER.open(req, timeout=max(1.0, min(30.0, limit - _clock()))) as resp:
                raw = _read_capped(resp, MAX_BODY, limit)
                return resp.status, (json.loads(raw) if raw else {}), resp.headers

    def fetch(path: str) -> tuple[int, dict | list]:
        for attempt in range(FETCH_ATTEMPTS):
            last = attempt == FETCH_ATTEMPTS - 1
            limit = _limit()
            if _clock() >= min(v for v in (_limits["repo"], _limits["audit"], limit) if v is not None):
                return 599, {"message": "transport error: deadline exceeded"}
            try:
                code, body, _ = once(path, limit)
                return code, body
            except urllib.error.HTTPError as err:
                if 300 <= err.code < 400:  # a refused redirect: say so, never echo what the other side sent
                    return err.code, {"message": "redirect refused"}
                if err.code in RETRYABLE_STATUS and not last:
                    if not _wait(_retry_wait(attempt, err.headers)):
                        return 599, {"message": "transport error: deadline exceeded"}
                    continue
                with _alarm(limit - _clock()):
                    return err.code, _error_body(err, token, limit)
            except (OSError, http.client.HTTPException, ValueError) as err:
                # DNS, TLS, reset, timeout, or a 200 that is not JSON. The exception text can hold the
                # request, so only its class is reported, as a status no real answer uses.
                if _is_timeout(err) and not last:
                    if not _wait(_retry_wait(attempt, None)):
                        return 599, {"message": "transport error: deadline exceeded"}
                    continue
                return 599, {"message": f"transport error: {type(err).__name__}"}
        return 599, {"message": "transport error"}  # unreachable; keeps the type checker honest

    return fetch


def find_token() -> str:
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(name):
            return os.environ[name]
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sys.exit("no token: set GITHUB_TOKEN or GH_TOKEN, or log in with `gh auth login`")


def unreadable(code: int, body: dict | list) -> str:
    message = body.get("message", "") if isinstance(body, dict) else ""
    if type(message) is not str:
        message = MALFORMED_ERROR
    return f"HTTP {code}{': ' + message if message else ''}"


# --- the checks -------------------------------------------------------------


def needs(code: int, body: dict | list, permission: str) -> str:
    """An unreadable answer's reason, with the permission that would have made it readable."""
    return f"{unreadable(code, body)}; needs {permission}"


def org_owners(org: str, fetch: Fetcher, cache: dict) -> tuple[list[str] | None, str]:
    """The logins of an organization's owners, read once per run into `cache`, or None and why not."""
    if "owners" not in cache:
        code, body = fetch(f"/orgs/{org}/members?role=admin&per_page=100")
        if code == 200 and isinstance(body, list):
            cache["owners"] = (sorted(m["login"] for m in body if m.get("login")), "")
        else:
            cache["owners"] = (None, needs(code, body, "Organization Members: read"))
    return cache["owners"]


def check_collaborators(repo: str, fetch: Fetcher, owner: str, org: bool = False, cache: dict | None = None) -> Result:
    """Nobody but the owner can push.

    Under a user account the owner is the account, and every affiliation is
    read. Under an organization the repository's owner login is the
    organization, which is not a person: the owners are the organization's
    `role=admin` members, who reach the repository through membership and so
    never appear as direct collaborators, and the people to look for are the
    direct and outside collaborators who are not one of them.
    """
    if not org:
        code, body = fetch(f"/repos/{repo}/collaborators?affiliation=all&per_page=100")
        if code != 200 or not isinstance(body, list):
            return Result(repo, "collaborators", UNKNOWN, unreadable(code, body))
        writers = sorted(
            c["login"] for c in body if c.get("login") != owner and (c.get("permissions") or {}).get("push")
        )
        if writers:
            return Result(repo, "collaborators", FAIL, f"others with write access: {', '.join(writers)}")
        return Result(repo, "collaborators", PASS, f"only {owner} can push")
    owners, why = org_owners(owner, fetch, cache if cache is not None else {})
    if owners is None:
        return Result(repo, "collaborators", UNKNOWN, f"cannot tell who the organization's owners are: {why}")
    people: dict[str, dict] = {}
    for affiliation in ("direct", "outside"):
        code, body = fetch(f"/repos/{repo}/collaborators?affiliation={affiliation}&per_page=100")
        if code != 200 or not isinstance(body, list):
            return Result(repo, "collaborators", UNKNOWN, f"affiliation={affiliation}: {unreadable(code, body)}")
        for c in body:
            people[c.get("login")] = c
    writers = sorted(
        login for login, c in people.items() if login not in owners and (c.get("permissions") or {}).get("push")
    )
    if writers:
        return Result(repo, "collaborators", FAIL, f"others with write access: {', '.join(writers)}")
    return Result(repo, "collaborators", PASS, f"only {owner}'s owners ({', '.join(owners)}) can push")


def expected_gates(text: str) -> set[str]:
    """The `<job> / CI green` checks a caller workflow produces.

    One per job whose `uses:` names a shared `*-ci.yml`: a repository with
    Python and shell calls two workflows from two jobs and must require both
    gates, or the second language merges unchecked. Read by line, the way the
    pin check reads the file, so the script stays free of a YAML dependency.
    """
    gates: set[str] = set()
    job = None
    in_jobs = False
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if re.match(r"^\S", line):  # another top-level key ends the jobs block
            in_jobs = False
            continue
        key = JOB_KEY.match(line)
        if key:
            job = key.group(1)
        elif job and SHARED_CI_CALL.match(line):
            gates.add(f"{job} / {GATE}")
    return gates


def required_checks_for(repo: str, gates: set[str]) -> set[str]:
    if repo.lower() == SHARED_REPO.lower():
        return {SHARED_REPO_CHECK}
    return gates or {REQUIRED_CHECK}


def check_branch_protection(repo: str, fetch: Fetcher, default_branch: str, required: set[str]) -> list[Result]:
    code, body = fetch(f"/repos/{repo}/branches/{default_branch}/protection")
    if code == 404:
        return [Result(repo, "branch-protection", FAIL, f"{default_branch} is not protected")]
    if code != 200 or not isinstance(body, dict):
        return [Result(repo, "branch-protection", UNKNOWN, unreadable(code, body))]
    results = []
    checks = body.get("required_status_checks") or {}
    names = [c.get("context") for c in checks.get("checks") or []] or list(checks.get("contexts") or [])
    missing = sorted(required - set(names))
    if not missing:
        extra = sorted(n for n in names if n not in required)
        results.append(
            Result(repo, "required-check", PASS, f"requires {sorted(required)}" + (f"; also {extra}" if extra else ""))
        )
    else:
        results.append(Result(repo, "required-check", FAIL, f"required checks are {names}; missing {missing}"))
    reviews = body.get("required_pull_request_reviews")
    if not reviews:
        results.append(Result(repo, "pull-request-required", FAIL, "direct pushes to the default branch are allowed"))
    elif not reviews.get("dismiss_stale_reviews"):
        results.append(
            Result(
                repo, "pull-request-required", FAIL, "stale approvals survive new pushes (dismiss_stale_reviews off)"
            )
        )
    else:
        results.append(Result(repo, "pull-request-required", PASS, "pull request required, stale approvals dismissed"))
    force = (body.get("allow_force_pushes") or {}).get("enabled")
    delete = (body.get("allow_deletions") or {}).get("enabled")
    if force or delete:
        results.append(
            Result(
                repo,
                "history-protected",
                FAIL,
                f"force pushes {'allowed' if force else 'blocked'}, deletions {'allowed' if delete else 'blocked'}",
            )
        )
    else:
        results.append(Result(repo, "history-protected", PASS, "no force pushes, no deletion"))
    return results


def check_security_features(repo: str, repo_body: dict) -> list[Result]:
    features = repo_body.get("security_and_analysis")
    wanted = {
        "secret-scanning": "secret_scanning",
        "push-protection": "secret_scanning_push_protection",
        "dependabot-security-updates": "dependabot_security_updates",
    }
    if not isinstance(features, dict):
        return [Result(repo, name, UNKNOWN, "token cannot read security_and_analysis") for name in wanted]
    results = []
    for name, key in wanted.items():
        status = (features.get(key) or {}).get("status")
        results.append(Result(repo, name, PASS if status == "enabled" else FAIL, f"{key}: {status}"))
    return results


def check_private_vulnerability_reporting(repo: str, fetch: Fetcher) -> Result:
    code, body = fetch(f"/repos/{repo}/private-vulnerability-reporting")
    if code != 200 or not isinstance(body, dict):
        return Result(repo, "private-vulnerability-reporting", UNKNOWN, unreadable(code, body))
    on = body.get("enabled") is True
    return Result(repo, "private-vulnerability-reporting", PASS if on else FAIL, "enabled" if on else "disabled")


def check_workflow_token(repo: str, fetch: Fetcher) -> Result:
    code, body = fetch(f"/repos/{repo}/actions/permissions/workflow")
    if code != 200 or not isinstance(body, dict):
        return Result(repo, "workflow-token-read-only", UNKNOWN, unreadable(code, body))
    perms = body.get("default_workflow_permissions")
    approve = body.get("can_approve_pull_request_reviews")
    if perms == "read" and approve is False:
        return Result(
            repo, "workflow-token-read-only", PASS, "GITHUB_TOKEN defaults to read; cannot approve pull requests"
        )
    return Result(
        repo,
        "workflow-token-read-only",
        FAIL,
        f"default_workflow_permissions={perms}, can_approve_pull_request_reviews={approve}",
    )


def check_fork_pr_approval(repo: str, fetch: Fetcher) -> Result:
    code, body = fetch(f"/repos/{repo}/actions/permissions/fork-pr-contributor-approval")
    if code != 200 or not isinstance(body, dict):
        return Result(repo, "fork-pr-approval", UNKNOWN, unreadable(code, body))
    policy = body.get("approval_policy")
    if policy == "all_external_contributors":
        return Result(repo, "fork-pr-approval", PASS, "every outside contributor's workflow run needs approval")
    return Result(repo, "fork-pr-approval", FAIL, f"approval_policy is {policy!r}, want 'all_external_contributors'")


def check_actions_allowlist(repo: str, fetch: Fetcher) -> Result:
    """Only GitHub-owned actions and a named list of third-party ones may run.

    A pull request that adds an action outside the list fails at workflow
    start, whatever its pin says. Marketplace "verified creator" is not a
    list, so it stays off.
    """
    code, body = fetch(f"/repos/{repo}/actions/permissions")
    if code != 200 or not isinstance(body, dict):
        return Result(repo, "actions-allowlist", UNKNOWN, unreadable(code, body))
    allowed = body.get("allowed_actions")
    if allowed != "selected":
        return Result(repo, "actions-allowlist", FAIL, f"allowed_actions is {allowed!r}, want 'selected'")
    code, body = fetch(f"/repos/{repo}/actions/permissions/selected-actions")
    if code != 200 or not isinstance(body, dict):
        return Result(repo, "actions-allowlist", UNKNOWN, unreadable(code, body))
    patterns = body.get("patterns_allowed") or []
    problems = []
    if body.get("github_owned_allowed") is not True:
        problems.append("GitHub-owned actions are not allowed")
    if body.get("verified_allowed") is not False:
        problems.append("Marketplace verified creators are allowed wholesale")
    if not patterns:
        problems.append("no third-party pattern is listed")
    if problems:
        return Result(repo, "actions-allowlist", FAIL, "; ".join(problems))
    return Result(repo, "actions-allowlist", PASS, f"GitHub-owned plus {len(patterns)} named third-party pattern(s)")


def workflow_findings(name: str, text: str) -> list[str]:
    """What BASELINE.md forbids in a caller's workflow file."""
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.match(r"^secrets:\s*inherit\s*$", stripped):
            findings.append(f"{name}:{number}: secrets: inherit")
        match = USES.match(line)
        if not match:
            continue
        action, ref, rest = match["action"], match["ref"], match["rest"]
        if action.startswith("./") or action.startswith("$/"):
            continue  # a local action or workflow has no ref
        if not SHA.match(ref):
            findings.append(f"{name}:{number}: {action} pinned to {ref!r}, not a commit SHA")
        elif action.startswith(REUSABLE_PREFIX) and not VERSION_COMMENT.match(rest):
            findings.append(f"{name}:{number}: {action} has no `# vX.Y.Z` comment naming its tag")
    return findings


def check_auto_merge(repo: str, repo_body: dict) -> Result:
    """Auto-merge has to be allowed by the repository before a workflow can queue one.

    Without it `gh pr merge --auto` fails, and the Dependabot bumps that the
    cooldown and the gate have already cleared sit waiting for a click.
    """
    if "allow_auto_merge" not in repo_body:
        return Result(repo, "auto-merge-enabled", UNKNOWN, "token cannot read allow_auto_merge")
    on = bool(repo_body.get("allow_auto_merge"))
    return Result(repo, "auto-merge-enabled", PASS if on else FAIL, "enabled" if on else "disabled")


# Deleting or moving a v* tag is the one way a caller's pin and its version
# comment can come to disagree without a commit anywhere.
TAG_RULES = {"deletion", "non_fast_forward", "update"}


def check_tag_ruleset(repo: str, fetch: Fetcher) -> Result:
    code, body = fetch(f"/repos/{repo}/rulesets")
    if code != 200 or not isinstance(body, list):
        return Result(repo, "tag-ruleset", UNKNOWN, unreadable(code, body))
    for summary in body:
        if summary.get("target") != "tag" or summary.get("enforcement") != "active":
            continue
        code, full = fetch(f"/repos/{repo}/rulesets/{summary.get('id')}")
        if code != 200 or not isinstance(full, dict):
            return Result(repo, "tag-ruleset", UNKNOWN, unreadable(code, full))
        include = ((full.get("conditions") or {}).get("ref_name") or {}).get("include") or []
        if "refs/tags/v*" not in include:
            continue
        have = {rule.get("type") for rule in full.get("rules") or []}
        missing = TAG_RULES - have
        if missing:
            return Result(repo, "tag-ruleset", FAIL, f"refs/tags/v* ruleset is missing: {', '.join(sorted(missing))}")
        return Result(repo, "tag-ruleset", PASS, "v* tags cannot be deleted, moved or force-pushed")
    return Result(repo, "tag-ruleset", FAIL, "no active ruleset protects refs/tags/v*")


def check_workflows(repo: str, fetch: Fetcher) -> tuple[list[Result], bool, set[str], set[str]]:
    """The workflow checks, whether any workflow reads DOPPLER_IDENTITY_ID, the advisories ignored, and the gates.

    The second value decides whether the identity variable is required: a
    repository whose workflows never pass `doppler-identity-id` (this shared
    repository, or a caller that fetches nothing) has nothing to set.
    """
    code, listing = fetch(f"/repos/{repo}/contents/.github/workflows")
    if code == 404:
        return [Result(repo, "workflows-pinned", FAIL, "no .github/workflows directory")], False, set(), set()
    if code != 200 or not isinstance(listing, list):
        return [Result(repo, "workflows-pinned", UNKNOWN, unreadable(code, listing))], False, set(), set()
    findings: list[str] = []
    callers = 0
    reads_doppler = False
    exceptions: set[str] = set()
    gates: set[str] = set()
    for entry in listing:
        name = entry.get("name", "") if isinstance(entry, dict) else ""
        if type(name) is not str or not name.endswith((".yml", ".yaml")):
            continue
        code, file = fetch(f"/repos/{repo}/contents/.github/workflows/{name}")
        if code != 200:
            return (
                [Result(repo, "workflows-pinned", UNKNOWN, f"{shown(name)}: {unreadable(code, file)}")],
                False,
                set(),
                set(),
            )
        text = contents_text(file, f".github/workflows/{name}")
        if text is None:
            detail = f"{shown(name)}: the contents answer is not a plain base64 UTF-8 file"
            return [Result(repo, "workflows-pinned", UNKNOWN, detail)], False, set(), set()
        if REUSABLE_PREFIX in text:
            callers += 1
        gates |= expected_gates(text)
        # The shared variable, as a whole word: audit.yml reads its own
        # AUDIT_DOPPLER_IDENTITY_ID, which must not count.
        if re.search(r"(?<![A-Z_])DOPPLER_IDENTITY_ID", text):
            reads_doppler = True
        exceptions |= exceptions_in(text)
        findings.extend(workflow_findings(name, text))
    results = []
    if findings:
        results.append(Result(repo, "workflows-pinned", FAIL, "; ".join(findings)))
    else:
        results.append(Result(repo, "workflows-pinned", PASS, "every action SHA-pinned, no secrets: inherit"))
    if callers:
        results.append(
            Result(repo, "uses-shared-workflows", PASS, f"{callers} workflow(s) call git-your-ship-together")
        )
    elif repo.lower() == SHARED_REPO.lower():
        results.append(Result(repo, "uses-shared-workflows", PASS, "this is the shared repository"))
    else:
        results.append(Result(repo, "uses-shared-workflows", FAIL, "no workflow calls git-your-ship-together"))
    return results, reads_doppler, exceptions, gates


def exceptions_in(text: str) -> set[str]:
    """Every advisory ID a workflow tells a scanner to ignore.

    Three shapes: `--ignore-vuln ID` inside pip-audit-extra-args, and the
    comma-separated `dependency-review-allow-ghsas:` and `rescan-ignore-advisories:` inputs. Comment lines are
    skipped so that a reason written beside the line is not read as a second
    exception, and so are `description:` lines: the shared workflow documents
    both inputs with example IDs, which are prose, not exceptions.
    """
    live = "\n".join(
        line
        for line in text.splitlines()
        if not line.lstrip().startswith("#") and not line.lstrip().startswith("description:")
    )
    found = set(IGNORE_VULN.findall(live))
    for match in [*ALLOW_GHSAS.finditer(live), *RESCAN_IGNORE.finditer(live)]:
        value = match.group(1).strip().strip("'\"")
        found |= {part.strip() for part in value.split(",") if part.strip()}
    return found


def load_register(path: Path = REGISTER) -> list[dict]:
    """The risk register's entries. PyYAML is a dev dependency; say so if it is missing."""
    try:
        import yaml
    except ImportError:
        sys.exit("reading the risk register needs PyYAML: pip install -r requirements-dev.txt")
    data = yaml.safe_load(path.read_text()) or {}
    return list(data.get("entries") or [])


def check_risk_exceptions(
    repo: str, exceptions: set[str], register: list[dict], today: dt.date | None = None
) -> Result:
    """Every advisory a repository ignores is in the register, for that repository, and not expired."""
    today = today or dt.date.today()
    if not exceptions:
        return Result(repo, "risk-exceptions", PASS, "no advisory is ignored")
    problems = []
    for advisory in sorted(exceptions):
        entries = [e for e in register if advisory in {e.get("id"), *(e.get("aliases") or [])}]
        if not entries:
            problems.append(f"{advisory} is ignored but not in baseline/risk-register.yaml")
            continue
        entry = entries[0]
        repos = [str(r).lower() for r in (entry.get("repos") or [])]
        if repo.lower() not in repos:
            problems.append(f"{advisory} is registered, but not for {repo}")
            continue
        review_by = entry.get("review_by")
        if not isinstance(review_by, dt.date):
            problems.append(f"{advisory}: review_by is not a date")
        elif review_by < today:
            problems.append(f"{advisory}: review_by {review_by} has passed; renew or remove the exception")
    if problems:
        return Result(repo, "risk-exceptions", FAIL, "; ".join(problems))
    return Result(repo, "risk-exceptions", PASS, f"{len(exceptions)} registered exception(s), none expired")


def expiring_entries(register: list[dict], days: int, today: dt.date) -> list[dict]:
    """Register entries whose `review_by` is `days` or fewer days away, or already past.

    `today` is a parameter, never read from the clock here, so the answer is
    the same in a test as in a run. An entry with no usable date is returned
    too, as already due: a register nobody can read the expiry of is expired.
    """
    due = []
    for entry in register:
        review_by = entry.get("review_by")
        if not isinstance(review_by, dt.date):
            due.append({**entry, "days_left": None})
            continue
        left = (review_by - today).days
        if left <= days:
            due.append({**entry, "days_left": left})
    return sorted(due, key=lambda e: (e["days_left"] is None, e["days_left"] or 0, str(e.get("id"))))


def format_expiring(entries: list[dict]) -> list[str]:
    """One tab-separated line per entry: EXPIRING, id, review_by, days left, repos (comma-joined).

    The workflow that opens the issues reads these with `read`, so no field
    may hold a tab or a newline.
    """
    lines = []
    for e in entries:
        fields = [
            "EXPIRING",
            str(e.get("id", "?")),
            str(e.get("review_by", "unknown")),
            "unknown" if e["days_left"] is None else str(e["days_left"]),
            ",".join(str(r) for r in (e.get("repos") or [])),
        ]
        lines.append("\t".join(" ".join(f.split()) for f in fields))
    return lines


# The owner rule: a new release is held at least this many days before it is proposed.
MIN_COOLDOWN_DAYS = 7
# GitHub's list of ecosystems grows, so a name is checked for shape, not against a copy of that list.
ECOSYSTEM_NAME = re.compile(r"[a-z][a-z0-9-]{0,39}")
# The ecosystems Dependabot documents, for a note only: a name outside this set is reported beside a PASS and
# never fails, so a stale copy cannot fail a good repository. Add a name here when GitHub adds one.
KNOWN_ECOSYSTEMS = frozenset(
    "bazel bun bundler cargo composer conda devcontainers docker docker-compose dotnet-sdk elm github-actions "
    "gitsubmodule gomod gradle helm julia maven mix npm nuget opentofu pip pub rust-toolchain swift terraform uv "
    "vcpkg deno nix pre-commit sbt".split()
)
COOLDOWN_KEYS = ("default-days", "semver-major-days", "semver-minor-days", "semver-patch-days")


# Largest dependabot.yml read, and the deepest nesting accepted. The file comes from another repository, so it
# is semi-trusted input: bounded before and during the parse, and never echoed raw into the report.
MAX_DEPENDABOT_BYTES = 64 * 1024
MAX_YAML_DEPTH = 20
MAX_FIELD_CHARS = 100
COMPLEX = "<complex>"


class UnsafeYaml(Exception):
    """A dependabot.yml that is refused rather than parsed: an alias, anchor, duplicate key, merge key or depth."""


def _safe_loader():
    import yaml

    class Loader(yaml.SafeLoader):
        depth = 0

        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise UnsafeYaml("alias")
            if self.peek_event().anchor is not None:
                raise UnsafeYaml("anchor")
            self.depth += 1
            try:
                if self.depth > MAX_YAML_DEPTH:
                    raise UnsafeYaml("nesting")
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            seen = set()
            for key_node, _ in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge":
                    raise UnsafeYaml("merge key")
                key = self.construct_object(key_node, deep=True)
                try:
                    duplicate = key in seen
                    seen.add(key)
                except TypeError:
                    raise UnsafeYaml("unhashable key") from None
                if duplicate:
                    raise UnsafeYaml("duplicate key")
            return super().construct_mapping(node, deep=deep)

    return Loader


def load_dependabot(raw: bytes) -> object:
    """Parse a fetched dependabot.yml; raise UnsafeYaml (or a parser error) for anything not plainly benign."""
    import yaml

    if len(raw) > MAX_DEPENDABOT_BYTES:
        raise UnsafeYaml("too large")
    return yaml.load(raw.decode(), Loader=_safe_loader())  # noqa: S506 - a SafeLoader subclass


def shown(value: object) -> str:
    """A value taken from a fetched file, made safe to print: str only, one line, no controls, no `::`."""
    if type(value) is not str:
        return COMPLEX
    text = "".join(ch if ch.isprintable() else " " for ch in value)
    text = " ".join(text.split()).replace("::", ": :")
    return text if len(text) <= MAX_FIELD_CHARS else COMPLEX


def one_line(text: str, limit: int = 1000) -> str:
    """Report text with no newline, control character or workflow command in it."""
    text = " ".join("".join(ch if ch.isprintable() else " " for ch in str(text)).split()).replace("::", ": :")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def cooldown_problems(config: object) -> list[str]:
    """What is wrong with the cooldown of each update entry in a parsed dependabot.yml.

    An entry needs `default-days` of at least MIN_COOLDOWN_DAYS, and a
    `semver-*-days` override may not undercut it either: an override replaces
    the default for that kind of bump, so a short one is a short cooldown.
    """
    updates = config.get("updates") if isinstance(config, dict) else None
    if not isinstance(updates, list) or not updates:
        return ["dependabot.yml has no update entries"]
    problems = []
    seen: set[tuple[str, str]] = set()
    version = config.get("version")
    if type(version) is not int or version != 2:
        problems.append("dependabot.yml does not say `version: 2`")
    for index, entry in enumerate(updates):
        if not isinstance(entry, dict):
            problems.append(f"update entry #{index + 1} is not a mapping")
            continue
        ecosystem = entry.get("package-ecosystem")
        if type(ecosystem) is not str or not ECOSYSTEM_NAME.fullmatch(ecosystem):
            problems.append(f"update entry #{index + 1} has no valid package-ecosystem")
            continue
        where = entry.get("directory") if "directory" in entry else entry.get("directories", "/")
        label = f"{ecosystem} in {shown(where)}"
        cooldown = entry.get("cooldown")
        if not isinstance(cooldown, dict):
            problems.append(f"{label} has no cooldown")
            continue
        for key in COOLDOWN_KEYS:
            if key not in cooldown:
                continue
            value = cooldown[key]
            if isinstance(value, bool) or not isinstance(value, int):
                problems.append(f"{label}: cooldown {key} is not a whole number of days")
            elif value < MIN_COOLDOWN_DAYS:
                problems.append(f"{label}: cooldown {key} is {value}, under {MIN_COOLDOWN_DAYS}")
        if "default-days" not in cooldown:
            problems.append(f"{label}: cooldown has no default-days")
        if "exclude" in cooldown:
            exclude = cooldown["exclude"]
            if not _list_of_str(exclude):
                problems.append(f"{label}: cooldown exclude is not a list of names")
            elif exclude:
                problems.append(f"{label}: cooldown exclude exempts dependencies from the cooldown")
        if "include" in cooldown:
            include = cooldown["include"]
            if not _list_of_str(include):
                problems.append(f"{label}: cooldown include is not a list of names")
            elif include != ["*"]:
                problems.append(
                    f'{label}: cooldown include limits the cooldown to some dependencies; use ["*"] or omit it'
                )
        targets = _locations(entry)
        if targets is None:
            problems.append(f"{label}: needs exactly one of directory (a path) or directories (a list of paths)")
            targets = []
        for target in targets:
            if (ecosystem, target) in seen:
                problems.append(f"{ecosystem} in {shown(target)} is configured twice; GitHub rejects that")
            seen.add((ecosystem, target))
    return problems


def _locations(entry: dict) -> list[str] | None:
    """The paths one update entry covers, or None unless it has exactly one valid directory or directories."""
    if ("directory" in entry) == ("directories" in entry):
        return None
    if "directory" in entry:
        path = entry["directory"]
        return [path] if type(path) is str and path.strip() else None
    paths = entry["directories"]
    if not _list_of_str(paths) or not paths or any(not p.strip() for p in paths) or len(set(paths)) != len(paths):
        return None
    return list(paths)


def _list_of_str(value: object) -> bool:
    return type(value) is list and all(type(item) is str for item in value)


def unlisted_ecosystems(config: object) -> list[str]:
    """Ecosystem names that are well-formed but not in KNOWN_ECOSYSTEMS: a note, never a failure."""
    updates = config.get("updates") if isinstance(config, dict) else None
    names = {
        entry["package-ecosystem"]
        for entry in updates or []
        if isinstance(entry, dict)
        and type(entry.get("package-ecosystem")) is str
        and ECOSYSTEM_NAME.fullmatch(entry["package-ecosystem"])
    }
    return sorted(names - KNOWN_ECOSYSTEMS)


def plain_file_bytes(file: object, path: str) -> bytes | None:
    """The bytes of a Contents API answer that is the regular file asked for, whole; None for anything else.

    Not a symlink, submodule or directory; strict base64 (no ignored characters); and the decoded length
    equals the `size` the API reported, so a truncated read is refused. The caller parses these same bytes.
    """
    if not isinstance(file, dict):
        return None
    if file.get("type") != "file" or file.get("encoding") != "base64" or file.get("path") != path:
        return None
    content, size = file.get("content"), file.get("size")
    if type(content) is not str or type(size) is not int:
        return None
    try:
        raw = base64.b64decode(content.replace("\n", ""), validate=True)
    except ValueError:
        return None
    return raw if len(raw) == size else None


def contents_text(file: object, path: str) -> str | None:
    """The UTF-8 text of a Contents API answer that is the regular file `path`, whole; None for anything else.

    Every file the audit reads goes through this: a hostile or broken answer is "could not read", never an exception.
    """
    try:
        raw = plain_file_bytes(file, path)
        return None if raw is None else raw.decode("utf-8")
    except (ValueError, TypeError, UnicodeError, binascii.Error):
        return None


def check_dependabot(repo: str, fetch: Fetcher) -> Result:
    code, file = fetch(f"/repos/{repo}/contents/.github/dependabot.yml")
    if code == 404:
        return Result(repo, "dependabot-config", FAIL, "no .github/dependabot.yml")
    if code != 200:
        return Result(repo, "dependabot-config", UNKNOWN, unreadable(code, file))
    raw = plain_file_bytes(file, ".github/dependabot.yml")
    if raw is None:
        return Result(repo, "dependabot-config", UNKNOWN, "the contents answer is not a plain base64 file")
    try:
        import yaml  # noqa: F401
    except ImportError:
        sys.exit("reading dependabot.yml needs PyYAML: pip install -r requirements-dev.txt")
    try:
        config = load_dependabot(raw)
        problems = cooldown_problems(config)
    except Exception as err:  # a hostile or broken file is "could not tell", never a pass and never a crash
        return Result(repo, "dependabot-config", UNKNOWN, f"dependabot.yml was not read: {type(err).__name__}")
    if problems:
        return Result(
            repo,
            "dependabot-config",
            FAIL,
            "; ".join(problems) + f"; every ecosystem needs cooldown default-days of {MIN_COOLDOWN_DAYS} or more "
            "(examples/dependabot-template.yml)",
        )
    detail = f"every ecosystem holds a release at least {MIN_COOLDOWN_DAYS} days"
    if unlisted := unlisted_ecosystems(config):
        detail += f"; note: {', '.join(unlisted)} not in the known ecosystem list (KNOWN_ECOSYSTEMS)"
    return Result(repo, "dependabot-config", PASS, detail)


def check_pre_commit_hook(repo: str, fetch: Fetcher) -> Result:
    code, file = fetch(f"/repos/{repo}/contents/.githooks/pre-commit")
    if code == 404:
        return Result(repo, "pre-commit-hook", FAIL, "no .githooks/pre-commit")
    if code != 200:
        return Result(repo, "pre-commit-hook", UNKNOWN, unreadable(code, file))
    content = plain_file_bytes(file, ".githooks/pre-commit")
    if content is None:
        return Result(repo, "pre-commit-hook", UNKNOWN, "the contents answer is not a plain base64 file")
    if content != PRE_COMMIT_HOOK.read_bytes():
        return Result(repo, "pre-commit-hook", FAIL, ".githooks/pre-commit does not match the shared hook")
    return Result(repo, "pre-commit-hook", PASS, "present and byte-identical to the shared hook")


def universal_uv_lock(text: str) -> bool:
    """Whether a requirements file's header says `uv pip compile --universal` wrote it."""
    header = []
    for line in text.splitlines():
        if not line.startswith("#"):
            break
        header.append(line)
    head = "\n".join(header)
    return "autogenerated by uv" in head and "--universal" in head


def pip_updated_roots(config: object) -> bool:
    """Whether a parsed dependabot.yml has a `pip` update entry covering the repository root.

    Both `directory` and `directories` are read from the structure, so a flow list, a multiline list or a flow
    mapping cannot hide the root. An entry naming neither covers `/`, as Dependabot treats it.
    """
    updates = config.get("updates") if isinstance(config, dict) else None
    for entry in updates if isinstance(updates, list) else []:
        if not isinstance(entry, dict) or entry.get("package-ecosystem") != "pip":
            continue
        if "directories" in entry:
            places = entry["directories"] if isinstance(entry["directories"], list) else []
        else:
            places = [entry.get("directory", "/")]
        if any(place == "/" for place in places if type(place) is str):
            return True
    return False


def check_dependabot_ecosystem(repo: str, fetch: Fetcher) -> Result:
    """A lock compiled with `uv pip compile --universal` needs Dependabot's `uv` ecosystem."""
    name = "dependabot-ecosystem"
    locks = []
    for lock in ("requirements.txt", "requirements-dev.txt"):
        code, file = fetch(f"/repos/{repo}/contents/{lock}")
        if code == 404:
            continue
        if code != 200:
            return Result(repo, name, UNKNOWN, f"{lock}: {unreadable(code, file)}")
        text = contents_text(file, lock)
        if text is None:
            return Result(repo, name, UNKNOWN, f"{lock}: the contents answer is not a plain base64 UTF-8 file")
        if universal_uv_lock(text):
            locks.append(lock)
    if not locks:
        return Result(repo, name, PASS, "no uv --universal lock; nothing to match")
    code, file = fetch(f"/repos/{repo}/contents/.github/dependabot.yml")
    if code == 404:
        return Result(
            repo, name, FAIL, f"{locks[0]} is a uv --universal lock and there is no dependabot.yml to update it"
        )
    if code != 200:
        return Result(repo, name, UNKNOWN, unreadable(code, file))
    text = contents_text(file, ".github/dependabot.yml")
    if text is None:
        return Result(
            repo, name, UNKNOWN, ".github/dependabot.yml: the contents answer is not a plain base64 UTF-8 file"
        )
    try:
        updated = pip_updated_roots(load_dependabot(text.encode()))
    except Exception as err:  # an unreadable file is "could not tell", never a pass
        return Result(repo, name, UNKNOWN, f".github/dependabot.yml was not read: {type(err).__name__}")
    if updated:
        return Result(
            repo,
            name,
            FAIL,
            f"{locks[0]} is a uv --universal lock but dependabot.yml updates / with the pip ecosystem; "
            "the uv ecosystem is required, because pip re-resolves it for one interpreter and drops marker-gated lines",
        )
    return Result(repo, name, PASS, "the uv --universal lock is not updated by the pip ecosystem")


def check_doppler_variable(repo: str, fetch: Fetcher, reads_doppler: bool) -> Result:
    if not reads_doppler:
        return Result(repo, "doppler-identity", PASS, "no workflow reads DOPPLER_IDENTITY_ID; nothing to set")
    code, body = fetch(f"/repos/{repo}/actions/variables/DOPPLER_IDENTITY_ID")
    if code == 404:
        return Result(repo, "doppler-identity", FAIL, "repository variable DOPPLER_IDENTITY_ID is not set")
    if code != 200 or not isinstance(body, dict):
        return Result(repo, "doppler-identity", UNKNOWN, unreadable(code, body))
    value = str(body.get("value", ""))
    if re.fullmatch(r"[0-9a-fA-F-]{36}", value):
        return Result(repo, "doppler-identity", PASS, "DOPPLER_IDENTITY_ID is set")
    return Result(repo, "doppler-identity", FAIL, "DOPPLER_IDENTITY_ID is set but is not a UUID")


# --- organization checks -----------------------------------------------------

# What an organization hands every repository created (or transferred in) after
# it is set. A transfer into the organization re-applied these over five
# repositories' own settings, which is why they are audited.
NEW_REPO_DEFAULTS = (
    "secret_scanning_enabled_for_new_repositories",
    "secret_scanning_push_protection_enabled_for_new_repositories",
    "dependabot_alerts_enabled_for_new_repositories",
    "dependabot_security_updates_enabled_for_new_repositories",
    "dependency_graph_enabled_for_new_repositories",
)
ORG_ADMIN = "Organization administration: read"


def audit_org(org: str, fetch: Fetcher, cache: dict, repo_results: list[Result]) -> list[Result]:
    """The organization's own posture: the four `org-*` checks, once per organization per run.

    `repo_results` are the results of the organization's audited repositories,
    which decide the one case where the organization's Actions policy may be
    `all`: every repository narrows it itself.
    """
    name = f"{org} (organization)"
    results: list[Result] = []
    code, body = fetch(f"/orgs/{org}")
    readable = code == 200 and isinstance(body, dict)
    # Only an organization's owner (or an App with the administration permission)
    # is sent these fields; their absence is "could not ask", not "off".
    why = needs(code, body, ORG_ADMIN) if not readable else ""
    two_fa = body.get("two_factor_requirement_enabled") if readable and isinstance(body, dict) else None
    if not isinstance(two_fa, bool):
        detail = why or f"two_factor_requirement_enabled was not returned; needs {ORG_ADMIN}"
        results.append(Result(name, "org-2fa-required", UNKNOWN, detail))
    elif two_fa:
        results.append(Result(name, "org-2fa-required", PASS, "two-factor authentication is required of members"))
    else:
        results.append(Result(name, "org-2fa-required", FAIL, "two_factor_requirement_enabled is false"))

    values = {k: body.get(k) for k in NEW_REPO_DEFAULTS} if readable and isinstance(body, dict) else {}
    unread = sorted(k for k in NEW_REPO_DEFAULTS if not isinstance(values.get(k), bool))
    off = sorted(k for k in NEW_REPO_DEFAULTS if values.get(k) is False)
    if unread:
        detail = why or f"not returned: {', '.join(unread)}; needs {ORG_ADMIN}"
        results.append(Result(name, "org-new-repo-defaults", UNKNOWN, detail))
    elif off:
        results.append(Result(name, "org-new-repo-defaults", FAIL, f"off for new repositories: {', '.join(off)}"))
    else:
        results.append(Result(name, "org-new-repo-defaults", PASS, "all five security defaults are on"))

    results.append(check_org_actions_policy(name, org, fetch, repo_results))

    owners, owners_why = org_owners(org, fetch, cache)
    if owners is None:
        results.append(Result(name, "org-owner-collaborators", UNKNOWN, owners_why))
    elif not owners:
        results.append(Result(name, "org-owner-collaborators", FAIL, "the organization has no owner"))
    else:
        results.append(
            Result(
                name,
                "org-owner-collaborators",
                PASS,
                f"{len(owners)} owner(s) ({', '.join(owners)}), counted as owners and not as outside collaborators",
            )
        )
    return results


def check_org_actions_policy(name: str, org: str, fetch: Fetcher, repo_results: list[Result]) -> Result:
    check = "org-actions-policy"
    code, body = fetch(f"/orgs/{org}/actions/permissions")
    if code != 200 or not isinstance(body, dict):
        return Result(name, check, UNKNOWN, needs(code, body, ORG_ADMIN))
    code, wf = fetch(f"/orgs/{org}/actions/permissions/workflow")
    if code != 200 or not isinstance(wf, dict):
        return Result(name, check, UNKNOWN, needs(code, wf, ORG_ADMIN))
    problems = []
    allowed = body.get("allowed_actions")
    note = ""
    if allowed == "selected":
        note = "allowed_actions is 'selected'"
    elif allowed == "all":
        narrowing = [
            r for r in repo_results if r.check == "actions-allowlist" and r.repo.lower().startswith(f"{org.lower()}/")
        ]
        if narrowing and all(r.status == PASS for r in narrowing):
            note = f"allowed_actions is 'all' and every audited repository ({len(narrowing)}) narrows it itself"
        else:
            problems.append("allowed_actions is 'all' and not every audited repository narrows it itself")
    else:
        problems.append(f"allowed_actions is {allowed!r}, want 'selected'")
    default = wf.get("default_workflow_permissions")
    if default != "read":
        problems.append(f"default_workflow_permissions is {default!r}, want 'read'")
    if problems:
        return Result(name, check, FAIL, "; ".join(problems))
    return Result(name, check, PASS, f"{note}; GITHUB_TOKEN defaults to read")


def audit_repo(
    repo: str,
    fetch: Fetcher,
    register: list[dict] | None = None,
    orgs: dict[str, dict] | None = None,
) -> list[Result]:
    """Every repository check. `orgs` collects the organizations seen and the owners read for them."""
    _limits["repo"] = _clock() + REPO_DEADLINE
    try:
        return _audit_repo(repo, fetch, register, orgs)
    except Exception as err:  # noqa: BLE001 - one repository never takes the fleet down; KeyboardInterrupt passes
        return [
            Result(repo, "repository", UNKNOWN, f"the audit raised {type(err).__name__}; the repository was skipped")
        ]
    finally:
        _limits["repo"] = None


def _guarded(repo: str, name: str, call: Callable[[], object]) -> list[Result]:
    """One check's results; an unexpected exception is UNKNOWN for that check alone, naming only its class."""
    try:
        out = call()
        return list(out) if isinstance(out, list) else [out]  # type: ignore[list-item]
    except Exception as err:  # noqa: BLE001 - last resort; KeyboardInterrupt and SystemExit still pass
        return [Result(repo, name, UNKNOWN, f"the check raised {type(err).__name__}; the answer could not be read")]


def _audit_repo(
    repo: str,
    fetch: Fetcher,
    register: list[dict] | None = None,
    orgs: dict[str, dict] | None = None,
) -> list[Result]:
    owner = repo.split("/", 1)[0]
    code, body = fetch(f"/repos/{repo}")
    if code != 200 or not isinstance(body, dict):
        return [Result(repo, "repository", UNKNOWN, unreadable(code, body))]
    owner_info = body.get("owner")
    is_org = isinstance(owner_info, dict) and owner_info.get("type") == "Organization"
    if is_org and orgs is not None:
        orgs.setdefault(owner, {})
    default_branch = body.get("default_branch") if type(body.get("default_branch")) is str else "main"
    # The workflows first: which gates branch protection must require is read from them.
    try:
        workflow_results, reads_doppler, exceptions, gates = check_workflows(repo, fetch)
    except Exception as err:  # noqa: BLE001
        detail = f"the check raised {type(err).__name__}; the answer could not be read"
        workflow_results, reads_doppler, exceptions, gates = (
            [Result(repo, "workflows-pinned", UNKNOWN, detail)],
            False,
            set(),
            set(),
        )
    cache = orgs.get(owner) if orgs is not None else None
    results = _guarded(repo, "collaborators", lambda: check_collaborators(repo, fetch, owner, is_org, cache))
    results += _guarded(
        repo,
        "branch-protection",
        lambda: check_branch_protection(repo, fetch, default_branch, required_checks_for(repo, gates)),
    )
    results += _guarded(repo, "security-features", lambda: check_security_features(repo, body))
    for name, call in (
        ("private-vulnerability-reporting", lambda: check_private_vulnerability_reporting(repo, fetch)),
        ("workflow-token-read-only", lambda: check_workflow_token(repo, fetch)),
        ("fork-pr-approval", lambda: check_fork_pr_approval(repo, fetch)),
        ("actions-allowlist", lambda: check_actions_allowlist(repo, fetch)),
        ("auto-merge-enabled", lambda: check_auto_merge(repo, body)),
        ("tag-ruleset", lambda: check_tag_ruleset(repo, fetch)),
    ):
        results += _guarded(repo, name, call)
    results += workflow_results
    results += _guarded(
        repo,
        "risk-exceptions",
        lambda: check_risk_exceptions(repo, exceptions, register if register is not None else load_register()),
    )
    for name, call in (
        ("dependabot-config", lambda: check_dependabot(repo, fetch)),
        ("dependabot-ecosystem", lambda: check_dependabot_ecosystem(repo, fetch)),
        ("doppler-identity", lambda: check_doppler_variable(repo, fetch, reads_doppler)),
        ("pre-commit-hook", lambda: check_pre_commit_hook(repo, fetch)),
    ):
        results += _guarded(repo, name, call)
    return results


# --- reporting --------------------------------------------------------------


def read_repo_list(path: Path) -> list[str]:
    repos = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            repos.append(line)
    return repos


def render(results: list[Result]) -> str:
    width = max(len(one_line(r.check)) for r in results)
    lines = []
    current = None
    for r in results:
        if r.repo != current:
            current = r.repo
            lines.append(f"\n{one_line(current)}")
        lines.append(f"  {one_line(r.status):<7} {one_line(r.check):<{width}}  {one_line(r.detail)}")
    return "\n".join(lines)


def exit_code(results: list[Result], allow_unknown: bool) -> int:
    if any(r.status == FAIL for r in results):
        return 1
    if any(r.status == UNKNOWN for r in results) and not allow_unknown:
        return 2
    return 0


def parse_owner_tokens(specs: list[str]) -> dict[str, str] | None:
    """`OWNER=ENVVAR` pairs as {owner (lower-case): env var name}; None when none were given."""
    if not specs:
        return None
    out: dict[str, str] = {}
    for spec in specs:
        owner, sep, var = spec.partition("=")
        if not sep or not owner or not var:
            sys.exit(f"--owner-token wants OWNER=ENVVAR, got {spec!r}")
        out[owner.lower()] = var
    return out


def fetcher_for(owner: str, tokens: dict[str, str]) -> Fetcher | None:
    token = os.environ.get(tokens.get(owner.lower(), ""), "")
    return github_fetcher(token) if token else None


def no_token_reason(owner: str, tokens: dict[str, str]) -> str:
    var = tokens.get(owner.lower())
    if var is None:
        return f"no token for owner {owner}: add --owner-token {owner}=ENVVAR (an App installed on {owner})"
    return f"${var} is empty: the token for {owner} was not minted (is the App installed on {owner}?)"


def _deadline_minutes(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {text!r}") from None
    if not math.isfinite(value) or not 1 <= value <= 720:
        raise argparse.ArgumentTypeError("must be a finite number of minutes from 1 to 720")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repos", nargs="*", help="owner/name; default: every line of baseline/repos.txt")
    parser.add_argument("--allow-unknown", action="store_true", help="exit 0 when checks are UNKNOWN but none FAIL")
    parser.add_argument(
        "--expiring",
        type=int,
        metavar="DAYS",
        help="print register entries due within DAYS days or past, tab-separated; no token",
    )
    parser.add_argument(
        "--owner-token",
        action="append",
        default=[],
        metavar="OWNER=ENVVAR",
        help="read OWNER's repositories (and the organization, if it is one) with the token in ENVVAR; repeatable",
    )
    parser.add_argument(
        "--deadline-minutes",
        type=_deadline_minutes,
        default=AUDIT_DEADLINE / 60,
        help="stop starting new repositories after this many minutes, 1 to 720; the rest report UNKNOWN (default: 45)",
    )
    parser.add_argument("--today", type=dt.date.fromisoformat, help="the date --expiring counts from (default: today)")
    parser.add_argument("--list", default=str(Path(__file__).resolve().parent.parent / "baseline" / "repos.txt"))
    args = parser.parse_args(argv)
    if args.expiring is not None:
        for line in format_expiring(expiring_entries(load_register(), args.expiring, args.today or dt.date.today())):
            print(line)
        return 0
    repos = args.repos or read_repo_list(Path(args.list))
    tokens = parse_owner_tokens(args.owner_token)
    default = None if tokens is not None else github_fetcher(find_token())
    register = load_register()
    results: list[Result] = []
    orgs: dict[str, dict] = {}
    by_org: dict[str, list[Result]] = {}
    _limits["audit"] = _clock() + args.deadline_minutes * 60
    for repo in repos:
        owner = repo.split("/", 1)[0]
        if _clock() >= _limits["audit"]:
            results.append(Result(repo, "repository", UNKNOWN, "the audit deadline passed before this repository"))
            continue
        fetch = default or fetcher_for(owner, tokens or {})
        if fetch is None:
            results.append(Result(repo, "repository", UNKNOWN, no_token_reason(owner, tokens or {})))
            continue
        try:
            found = audit_repo(repo, fetch, register, orgs)
        except Exception as err:  # noqa: BLE001 - belt and braces beside audit_repo's own boundary
            found = [Result(repo, "repository", UNKNOWN, f"the audit raised {type(err).__name__}")]
        results.extend(found)
        by_org.setdefault(owner, []).extend(found)
    for org, cache in orgs.items():
        fetch = default or fetcher_for(org, tokens or {})
        if fetch is None:
            results.append(Result(f"{org} (organization)", "org-checks", UNKNOWN, no_token_reason(org, tokens or {})))
            continue
        try:
            results.extend(audit_org(org, fetch, cache, by_org.get(org, [])))
        except Exception as err:  # noqa: BLE001
            results.append(
                Result(f"{org} (organization)", "org-checks", UNKNOWN, f"the audit raised {type(err).__name__}")
            )
    _limits["audit"] = None
    print(render(results))
    fails = sum(r.status == FAIL for r in results)
    unknowns = sum(r.status == UNKNOWN for r in results)
    scope = f"{len(repos)} repositories and {len(orgs)} organization(s)"
    print(f"\n{len(results)} checks over {scope}: {fails} FAIL, {unknowns} UNKNOWN")
    return exit_code(results, args.allow_unknown)


if __name__ == "__main__":
    sys.exit(main())
