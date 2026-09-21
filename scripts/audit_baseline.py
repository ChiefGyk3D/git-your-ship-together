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

Exit 0: every check passed. Exit 1: at least one FAIL. Exit 2: no FAIL but at
least one UNKNOWN (unless --allow-unknown). The token comes from GITHUB_TOKEN
or GH_TOKEN, else `gh auth token`; it needs admin read on each repository to
see settings, which the owner's own token has.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

API = "https://api.github.com"
REQUIRED_CHECK = "ci / CI green"  # the gate job of python-ci.yml, as a caller's `ci:` job reports it
SHARED_REPO = "ChiefGyk3D/git-your-ship-together"
SHARED_REPO_CHECK = "CI green"  # this repository runs the gate directly, so the check has no `ci /` prefix
REUSABLE_PREFIX = "ChiefGyk3D/git-your-ship-together/"
SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<action>[^@\s]+)@(?P<ref>\S+)(?P<rest>.*)$")
VERSION_COMMENT = re.compile(r"^\s*#\s*v\d+\.\d+(\.\d+)?\s*$")

PASS, FAIL, UNKNOWN = "PASS", "FAIL", "UNKNOWN"

# A fetcher answers (status code, decoded JSON body or {}) for an API path.
Fetcher = Callable[[str], tuple[int, dict | list]]


@dataclass(frozen=True)
class Result:
    repo: str
    check: str
    status: str
    detail: str


def github_fetcher(token: str) -> Fetcher:
    def fetch(path: str) -> tuple[int, dict | list]:
        req = urllib.request.Request(
            API + path,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as err:
            raw = err.read()
            try:
                return err.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return err.code, {"message": raw.decode(errors="replace")[:200]}

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
    return f"HTTP {code}{': ' + message if message else ''}"


# --- the checks -------------------------------------------------------------


def check_collaborators(repo: str, fetch: Fetcher, owner: str) -> Result:
    code, body = fetch(f"/repos/{repo}/collaborators?affiliation=all&per_page=100")
    if code != 200 or not isinstance(body, list):
        return Result(repo, "collaborators", UNKNOWN, unreadable(code, body))
    writers = sorted(c["login"] for c in body if c.get("login") != owner and (c.get("permissions") or {}).get("push"))
    if writers:
        return Result(repo, "collaborators", FAIL, f"others with write access: {', '.join(writers)}")
    return Result(repo, "collaborators", PASS, f"only {owner} can push")


def required_check_for(repo: str) -> str:
    return SHARED_REPO_CHECK if repo.lower() == SHARED_REPO.lower() else REQUIRED_CHECK


def check_branch_protection(repo: str, fetch: Fetcher, default_branch: str) -> list[Result]:
    required = required_check_for(repo)
    code, body = fetch(f"/repos/{repo}/branches/{default_branch}/protection")
    if code == 404:
        return [Result(repo, "branch-protection", FAIL, f"{default_branch} is not protected")]
    if code != 200 or not isinstance(body, dict):
        return [Result(repo, "branch-protection", UNKNOWN, unreadable(code, body))]
    results = []
    checks = body.get("required_status_checks") or {}
    names = [c.get("context") for c in checks.get("checks") or []] or list(checks.get("contexts") or [])
    if required in names:
        extra = sorted(n for n in names if n != required)
        results.append(
            Result(repo, "required-check", PASS, f"requires {required!r}" + (f"; also {extra}" if extra else ""))
        )
    else:
        results.append(Result(repo, "required-check", FAIL, f"required checks are {names}, not {required!r}"))
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


def check_workflows(repo: str, fetch: Fetcher) -> tuple[list[Result], bool]:
    """The workflow checks, and whether any workflow reads DOPPLER_IDENTITY_ID.

    The second value decides whether the identity variable is required: a
    repository whose workflows never pass `doppler-identity-id` (this shared
    repository, or a caller that fetches nothing) has nothing to set.
    """
    code, listing = fetch(f"/repos/{repo}/contents/.github/workflows")
    if code == 404:
        return [Result(repo, "workflows-pinned", FAIL, "no .github/workflows directory")], False
    if code != 200 or not isinstance(listing, list):
        return [Result(repo, "workflows-pinned", UNKNOWN, unreadable(code, listing))], False
    findings: list[str] = []
    callers = 0
    reads_doppler = False
    for entry in listing:
        name = entry.get("name", "")
        if not name.endswith((".yml", ".yaml")):
            continue
        code, file = fetch(f"/repos/{repo}/contents/.github/workflows/{name}")
        if code != 200 or not isinstance(file, dict) or "content" not in file:
            return [Result(repo, "workflows-pinned", UNKNOWN, f"{name}: {unreadable(code, file)}")], False
        text = base64.b64decode(file["content"]).decode()
        if REUSABLE_PREFIX in text:
            callers += 1
        if "DOPPLER_IDENTITY_ID" in text:
            reads_doppler = True
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
    return results, reads_doppler


def check_dependabot(repo: str, fetch: Fetcher) -> Result:
    code, file = fetch(f"/repos/{repo}/contents/.github/dependabot.yml")
    if code == 404:
        return Result(repo, "dependabot-config", FAIL, "no .github/dependabot.yml")
    if code != 200 or not isinstance(file, dict) or "content" not in file:
        return Result(repo, "dependabot-config", UNKNOWN, unreadable(code, file))
    text = base64.b64decode(file["content"]).decode()
    if "cooldown" not in text:
        return Result(repo, "dependabot-config", FAIL, "dependabot.yml has no cooldown")
    return Result(repo, "dependabot-config", PASS, "present, with a cooldown")


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


def audit_repo(repo: str, fetch: Fetcher) -> list[Result]:
    owner = repo.split("/", 1)[0]
    code, body = fetch(f"/repos/{repo}")
    if code != 200 or not isinstance(body, dict):
        return [Result(repo, "repository", UNKNOWN, unreadable(code, body))]
    default_branch = body.get("default_branch") or "main"
    results = [check_collaborators(repo, fetch, owner)]
    results += check_branch_protection(repo, fetch, default_branch)
    results += check_security_features(repo, body)
    results.append(check_private_vulnerability_reporting(repo, fetch))
    results.append(check_workflow_token(repo, fetch))
    results.append(check_fork_pr_approval(repo, fetch))
    results.append(check_actions_allowlist(repo, fetch))
    workflow_results, reads_doppler = check_workflows(repo, fetch)
    results += workflow_results
    results.append(check_dependabot(repo, fetch))
    results.append(check_doppler_variable(repo, fetch, reads_doppler))
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
    width = max(len(r.check) for r in results)
    lines = []
    current = None
    for r in results:
        if r.repo != current:
            current = r.repo
            lines.append(f"\n{current}")
        lines.append(f"  {r.status:<7} {r.check:<{width}}  {r.detail}")
    return "\n".join(lines)


def exit_code(results: list[Result], allow_unknown: bool) -> int:
    if any(r.status == FAIL for r in results):
        return 1
    if any(r.status == UNKNOWN for r in results) and not allow_unknown:
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repos", nargs="*", help="owner/name; default: every line of baseline/repos.txt")
    parser.add_argument("--allow-unknown", action="store_true", help="exit 0 when checks are UNKNOWN but none FAIL")
    parser.add_argument("--list", default=str(Path(__file__).resolve().parent.parent / "baseline" / "repos.txt"))
    args = parser.parse_args(argv)
    repos = args.repos or read_repo_list(Path(args.list))
    fetch = github_fetcher(find_token())
    results: list[Result] = []
    for repo in repos:
        results.extend(audit_repo(repo, fetch))
    print(render(results))
    fails = sum(r.status == FAIL for r in results)
    unknowns = sum(r.status == UNKNOWN for r in results)
    print(f"\n{len(results)} checks over {len(repos)} repositories: {fails} FAIL, {unknowns} UNKNOWN")
    return exit_code(results, args.allow_unknown)


if __name__ == "__main__":
    sys.exit(main())
