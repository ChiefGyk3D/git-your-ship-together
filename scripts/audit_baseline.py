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
import datetime as dt
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
GATE = "CI green"  # the last job of every shared `*-ci.yml`; a caller's job `ci:` reports it as `ci / CI green`
REQUIRED_CHECK = f"ci / {GATE}"  # what a caller with no derivable gate is held to
SHARED_REPO = "ChiefGyk3D/git-your-ship-together"
SHARED_REPO_CHECK = GATE  # this repository runs the gate directly, so the check has no `ci /` prefix
REUSABLE_PREFIX = "ChiefGyk3D/git-your-ship-together/"
# A caller job that uses one of the shared CI workflows. The release and
# security workflows have no gate, so a job calling them is not a check.
SHARED_CI_CALL = re.compile(
    r"^\s+uses:\s*" + re.escape(REUSABLE_PREFIX) + r"\.github/workflows/[A-Za-z0-9_-]+-ci\.ya?ml@"
)
JOB_KEY = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(?P<action>[^@\s]+)@(?P<ref>\S+)(?P<rest>.*)$")
VERSION_COMMENT = re.compile(r"^\s*#\s*v\d+\.\d+(\.\d+)?\s*$")
IGNORE_VULN = re.compile(r"--ignore-vuln[\s=]+([A-Za-z0-9-]+)")
# Same-line whitespace only: `\s*` would cross the newline of a bare input
# declaration and capture the `type:` line beneath it.
ALLOW_GHSAS = re.compile(r"^[ \t]*dependency-review-allow-ghsas:[ \t]*(\S.*?)[ \t]*$", re.M)
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
        name = entry.get("name", "")
        if not name.endswith((".yml", ".yaml")):
            continue
        code, file = fetch(f"/repos/{repo}/contents/.github/workflows/{name}")
        if code != 200 or not isinstance(file, dict) or "content" not in file:
            return [Result(repo, "workflows-pinned", UNKNOWN, f"{name}: {unreadable(code, file)}")], False, set(), set()
        text = base64.b64decode(file["content"]).decode()
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

    Two shapes: `--ignore-vuln ID` inside pip-audit-extra-args, and the
    comma-separated `dependency-review-allow-ghsas:` input. Comment lines are
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
    for match in ALLOW_GHSAS.finditer(live):
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


def check_pre_commit_hook(repo: str, fetch: Fetcher) -> Result:
    code, file = fetch(f"/repos/{repo}/contents/.githooks/pre-commit")
    if code == 404:
        return Result(repo, "pre-commit-hook", FAIL, "no .githooks/pre-commit")
    if code != 200 or not isinstance(file, dict) or not isinstance(file.get("content"), str):
        return Result(repo, "pre-commit-hook", UNKNOWN, unreadable(code, file))
    try:
        content = base64.b64decode(file["content"])
    except (ValueError, TypeError):
        return Result(repo, "pre-commit-hook", UNKNOWN, "the hook content is not valid base64")
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


def pip_updated_roots(text: str) -> bool:
    """Whether dependabot.yml has a `pip` update entry for the repository root."""
    items: list[list[str]] = []
    indent = None
    for line in text.splitlines():
        match = re.match(r"^(\s*)-\s", line)
        if match and (indent is None or len(match.group(1)) == indent):
            indent = len(match.group(1))
            items.append([])
        if items:
            items[-1].append(line)
    for item in items:
        values = {}
        for line in item:
            found = re.match(r"^\s*(?:-\s+)?(package-ecosystem|directory):\s*(.*?)\s*$", line)
            if found:
                values[found.group(1)] = re.sub(r"\s+#.*$", "", found.group(2)).strip("\"'")
        if values.get("package-ecosystem") == "pip" and values.get("directory", "/") == "/":
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
        if code != 200 or not isinstance(file, dict) or "content" not in file:
            return Result(repo, name, UNKNOWN, f"{lock}: {unreadable(code, file)}")
        if universal_uv_lock(base64.b64decode(file["content"]).decode()):
            locks.append(lock)
    if not locks:
        return Result(repo, name, PASS, "no uv --universal lock; nothing to match")
    code, file = fetch(f"/repos/{repo}/contents/.github/dependabot.yml")
    if code == 404:
        return Result(
            repo, name, FAIL, f"{locks[0]} is a uv --universal lock and there is no dependabot.yml to update it"
        )
    if code != 200 or not isinstance(file, dict) or "content" not in file:
        return Result(repo, name, UNKNOWN, unreadable(code, file))
    if pip_updated_roots(base64.b64decode(file["content"]).decode()):
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
    owner = repo.split("/", 1)[0]
    code, body = fetch(f"/repos/{repo}")
    if code != 200 or not isinstance(body, dict):
        return [Result(repo, "repository", UNKNOWN, unreadable(code, body))]
    is_org = (body.get("owner") or {}).get("type") == "Organization"
    if is_org and orgs is not None:
        orgs.setdefault(owner, {})
    default_branch = body.get("default_branch") or "main"
    # The workflows first: which gates branch protection must require is read from them.
    workflow_results, reads_doppler, exceptions, gates = check_workflows(repo, fetch)
    results = [check_collaborators(repo, fetch, owner, is_org, orgs.get(owner) if orgs is not None else None)]
    results += check_branch_protection(repo, fetch, default_branch, required_checks_for(repo, gates))
    results += check_security_features(repo, body)
    results.append(check_private_vulnerability_reporting(repo, fetch))
    results.append(check_workflow_token(repo, fetch))
    results.append(check_fork_pr_approval(repo, fetch))
    results.append(check_actions_allowlist(repo, fetch))
    results.append(check_auto_merge(repo, body))
    results.append(check_tag_ruleset(repo, fetch))
    results += workflow_results
    results.append(check_risk_exceptions(repo, exceptions, register if register is not None else load_register()))
    results.append(check_dependabot(repo, fetch))
    results.append(check_dependabot_ecosystem(repo, fetch))
    results.append(check_doppler_variable(repo, fetch, reads_doppler))
    results.append(check_pre_commit_hook(repo, fetch))
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
    for repo in repos:
        owner = repo.split("/", 1)[0]
        fetch = default or fetcher_for(owner, tokens or {})
        if fetch is None:
            results.append(Result(repo, "repository", UNKNOWN, no_token_reason(owner, tokens or {})))
            continue
        found = audit_repo(repo, fetch, register, orgs)
        results.extend(found)
        by_org.setdefault(owner, []).extend(found)
    for org, cache in orgs.items():
        fetch = default or fetcher_for(org, tokens or {})
        if fetch is None:
            results.append(Result(f"{org} (organization)", "org-checks", UNKNOWN, no_token_reason(org, tokens or {})))
            continue
        results.extend(audit_org(org, fetch, cache, by_org.get(org, [])))
    print(render(results))
    fails = sum(r.status == FAIL for r in results)
    unknowns = sum(r.status == UNKNOWN for r in results)
    scope = f"{len(repos)} repositories and {len(orgs)} organization(s)"
    print(f"\n{len(results)} checks over {scope}: {fails} FAIL, {unknowns} UNKNOWN")
    return exit_code(results, args.allow_unknown)


if __name__ == "__main__":
    sys.exit(main())
