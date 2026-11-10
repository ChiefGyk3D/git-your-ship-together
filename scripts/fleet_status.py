#!/usr/bin/env python3
"""fleet_status.py: one page on the state of every repository an owner has, counts only.

For each non-archived, non-fork repository of the owner (more than one owner with --owner, repeated) it reports:

  - the GYST pins found in .github/workflows, each file read through the contents API, against the latest
    release tag of the shared repository: current, behind, unknown (a pin with no `# vX.Y.Z` comment) or none;
  - the number of open Dependabot alerts by severity (counts only; a read the token is refused is `n/a`);
  - whether the default branch is protected (classic protection, or a ruleset) and the exact names of its
    required checks;
  - the conclusion of the newest default-branch push: success, failure, or none.

It writes a markdown table and a JSON file. No advisory text, package name or secret is ever read into either:
the only strings that come from the API into the output are repository and branch names (shape-checked), pin
versions (`vX.Y.Z`), required check names (control characters stripped, length capped) and fixed words.

REST only, standard library only. Every request has a timeout, a transient failure is retried a small number
of times, the rate-limit headers are respected, and a rate limit stops the run with a message and NO report: a
partial table would read as a clean fleet. The token goes to api.github.com only and a redirect is refused.

The default job token of a workflow can read public repositories and nothing of the others' settings; whatever
it cannot read is `n/a`, never a guess. Run it with a token that can read more and the table fills in.

  GITHUB_TOKEN=... python3 scripts/fleet_status.py --owner ChiefGyk3D --markdown fleet.md --json fleet.json

Exit status: 0 a report was written; 1 bad arguments or a failure before any report; 2 stopped by a rate limit
or the request cap.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable

API = "https://api.github.com"
SHARED_REPO = "ChiefGyk3D/git-your-ship-together"
TIMEOUT = 20.0  # seconds, per request
RETRIES = 2  # extra attempts after a transient failure (network error or 5xx)
BACKOFF = (1.0, 3.0)  # seconds before each retry
MAX_PAGES = 10  # pages of 100 for any list: 1000 repositories, 1000 alerts
MAX_REQUESTS = 3000  # the whole run, under the 5000 an hour a token has
MAX_FILE_BYTES = 512 * 1024  # a workflow file larger than this is not read
MAX_CHECK_LEN = 100
SEVERITIES = ("critical", "high", "medium", "low")

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
VERSION = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
# A `uses:` of the shared repository's workflows or actions, with the comment after the pin (if any). A line that
# is itself a comment does not match: the pattern is anchored at the start of the line.
GYST_USES = re.compile(
    r"^\s*(?:-\s*)?uses:\s*" + re.escape(SHARED_REPO) + r"/\.github/(?:workflows|actions)/[^@\s]+@\S+(?P<rest>.*)$"
)
COMMENT_VERSION = re.compile(r"^\s*#\s*(v\d+\.\d+\.\d+)\s*$")

# A transport answers (status, lower-cased headers, body bytes) for a URL, or raises OSError.
Transport = Callable[[str, dict, float], tuple[int, dict, bytes]]


class Stop(Exception):
    """The run cannot go on: a rate limit or the request cap. Carries the exit status and the message."""

    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # a redirect would carry the Authorization header somewhere else


def build_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_NoRedirect)


def urllib_transport(url: str, headers: dict, timeout: float) -> tuple[int, dict, bytes]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with build_opener().open(request, timeout=timeout) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read()
    except urllib.error.HTTPError as err:
        try:
            return err.code, {k.lower(): v for k, v in err.headers.items()}, err.read()
        finally:
            err.close()
    except urllib.error.URLError as err:
        raise OSError(str(err.reason)) from None


class Client:
    """GET JSON from api.github.com: bounded, polite, and the only place the token is used."""

    def __init__(self, transport: Transport, token: str, sleep: Callable[[float], None], max_requests: int):
        self.transport = transport
        self.token = token
        self.sleep = sleep
        self.max_requests = max_requests
        self.requests = 0
        self.exhausted = ""  # set when a response says the budget is spent

    def get(self, path: str):
        """(status, decoded body); status 0 and {} when the network failed after the retries."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "gyst-fleet-status",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        for attempt in range(RETRIES + 1):
            if self.exhausted:
                raise Stop(self.exhausted)
            if self.requests >= self.max_requests:
                raise Stop(f"stopped after {self.requests} requests (--max-requests); no report was written")
            self.requests += 1
            try:
                status, reply_headers, raw = self.transport(API + path, headers, TIMEOUT)
            except OSError:
                status, reply_headers, raw = 0, {}, b""
            body = self.decode(raw)
            self.check_rate_limit(status, reply_headers, body)
            if status == 0 or status >= 500:
                if attempt < RETRIES:
                    self.sleep(BACKOFF[min(attempt, len(BACKOFF) - 1)])
                    continue
                return 0, {}
            return status, body
        return 0, {}  # not reached

    @staticmethod
    def decode(raw: bytes):
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            return {}

    def check_rate_limit(self, status: int, headers: dict, body) -> None:
        message = str(body.get("message", "")).lower() if isinstance(body, dict) else ""
        remaining = headers.get("x-ratelimit-remaining")
        limited = status == 429 or (
            status == 403 and ("rate limit" in message or remaining == "0" or "retry-after" in headers)
        )
        reset = ""
        if headers.get("x-ratelimit-reset", "").isdigit():
            reset = (
                " (resets at "
                + dt.datetime.fromtimestamp(int(headers["x-ratelimit-reset"]), dt.UTC).strftime("%H:%M:%SZ")
                + ")"
            )
        if limited:
            raise Stop(
                f"GitHub rate limit reached{reset}; stopped, no report was written. Run it again after the reset."
            )
        if remaining == "0":
            self.exhausted = (
                f"GitHub rate limit budget is spent{reset}; stopped before the next request, no report was written."
            )


# --- reading one repository ---------------------------------------------------------------------------------


def clean(text: object, limit: int = MAX_CHECK_LEN) -> str:
    """A name from the API made safe to print: control characters out, length capped."""
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()[:limit]


def version_key(tag: str):
    match = VERSION.match(tag)
    return tuple(int(g) for g in match.groups()) if match else None


def workflow_pins(text: str) -> list[str]:
    """The version comment of each GYST `uses:` line, in order; `unknown` where the comment is missing."""
    pins = []
    for line in text.splitlines():
        match = GYST_USES.match(line)
        if match:
            comment = COMMENT_VERSION.match(match["rest"])
            pins.append(comment[1] if comment else "unknown")
    return pins


def pin_status(versions: list[str], latest: str) -> str:
    if not versions:
        return "none"
    keys = [version_key(v) for v in versions]
    if any(k is None for k in keys):
        return "unknown"
    return "behind" if any(k < version_key(latest) for k in keys) else "current"


def read_pins(client: Client, full: str, latest: str) -> dict:
    status, listing = client.get(f"/repos/{full}/contents/.github/workflows")
    if status == 404:
        return {"status": "none", "versions": [], "count": 0}
    if status != 200 or not isinstance(listing, list):
        return {"status": "n/a", "versions": [], "count": 0}
    pins: list[str] = []
    for entry in listing:
        name = entry.get("name", "") if isinstance(entry, dict) else ""
        if entry.get("type") != "file" or not re.fullmatch(r"[A-Za-z0-9._-]+\.ya?ml", name):
            continue
        if not isinstance(entry.get("size"), int) or entry["size"] > MAX_FILE_BYTES:
            continue
        status, doc = client.get(f"/repos/{full}/contents/.github/workflows/{name}")
        if status != 200 or not isinstance(doc, dict) or doc.get("encoding") != "base64":
            return {"status": "n/a", "versions": [], "count": 0}
        try:
            text = base64.b64decode(doc.get("content", "")).decode("utf-8", "replace")
        except ValueError:
            return {"status": "n/a", "versions": [], "count": 0}
        pins += workflow_pins(text)
    versions = sorted({p for p in pins if p != "unknown"}, key=version_key) + (["unknown"] if "unknown" in pins else [])
    return {"status": pin_status(pins, latest), "versions": versions, "count": len(pins)}


def read_alerts(client: Client, full: str):
    """({severity: count}, truncated) or ("n/a", False). Only the severity word of each alert is looked at."""
    counts = dict.fromkeys(SEVERITIES, 0)
    other = 0
    for page in range(1, MAX_PAGES + 1):
        status, body = client.get(f"/repos/{full}/dependabot/alerts?state=open&per_page=100&page={page}")
        if status != 200 or not isinstance(body, list):
            return "n/a", False
        for item in body:
            advisory = item.get("security_advisory") if isinstance(item, dict) else None
            severity = advisory.get("severity") if isinstance(advisory, dict) else None
            if severity in counts:
                counts[severity] += 1
            else:
                other += 1
        if len(body) < 100:
            break
    else:
        return counts | ({"other": other} if other else {}), True
    return counts | ({"other": other} if other else {}), False


def check_names(contexts, checks) -> list[str]:
    names = set()
    for value in list(contexts or []) + [c.get("context") for c in checks or [] if isinstance(c, dict)]:
        if isinstance(value, str) and value:
            names.add(clean(value))
    return sorted(names)


def read_protection(client: Client, full: str, branch: str) -> dict:
    status, body = client.get(f"/repos/{full}/branches/{branch}/protection")
    if status == 200 and isinstance(body, dict):
        required = body.get("required_status_checks") or {}
        return {"status": "protected", "required_checks": check_names(required.get("contexts"), required.get("checks"))}
    if not (status == 404 and isinstance(body, dict) and body.get("message") == "Branch not protected"):
        return {"status": "n/a", "required_checks": []}
    # No classic protection; a ruleset that applies to the branch is protection too.
    status, rules = client.get(f"/repos/{full}/rules/branches/{branch}")
    if status != 200 or not isinstance(rules, list):
        return {"status": "unprotected", "required_checks": []}
    if not rules:
        return {"status": "unprotected", "required_checks": []}
    names: list[str] = []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("type") == "required_status_checks":
            parameters = rule.get("parameters") or {}
            names += [c.get("context") for c in parameters.get("required_status_checks") or [] if isinstance(c, dict)]
    return {"status": "ruleset", "required_checks": check_names(names, None)}


def read_ci(client: Client, full: str, branch: str) -> str:
    """The newest default-branch push: `failure` if any of its completed workflows failed, else `success`."""
    status, body = client.get(f"/repos/{full}/actions/runs?branch={branch}&event=push&status=completed&per_page=30")
    if status != 200 or not isinstance(body, dict):
        return "n/a"
    runs = [r for r in body.get("workflow_runs") or [] if isinstance(r, dict)]
    if not runs:
        return "none"
    newest = [r for r in runs if r.get("head_sha") == runs[0].get("head_sha")]
    conclusions = {r.get("conclusion") for r in newest}
    if conclusions & {"failure", "timed_out", "startup_failure", "cancelled", "action_required"}:
        return "failure"
    return "success" if conclusions <= {"success", "skipped", "neutral"} else "other"


def read_repo(client: Client, full: str, branch: str, latest: str) -> dict:
    alerts, truncated = read_alerts(client, full)
    entry = {
        "repo": full,
        "default_branch": branch,
        "pins": read_pins(client, full, latest),
        "alerts": alerts,
        "protection": read_protection(client, full, branch),
        "ci": read_ci(client, full, branch),
    }
    if truncated:
        entry["alerts_truncated"] = True
    return entry


# --- the fleet -----------------------------------------------------------------------------------------------


def latest_tag(client: Client) -> str:
    status, body = client.get(f"/repos/{SHARED_REPO}/releases/latest")
    if status == 200 and isinstance(body, dict) and version_key(str(body.get("tag_name", ""))):
        return body["tag_name"]
    status, body = client.get(f"/repos/{SHARED_REPO}/tags?per_page=100")
    tags = (
        [t["name"] for t in body if isinstance(t, dict) and version_key(str(t.get("name", "")))]
        if status == 200 and isinstance(body, list)
        else []
    )
    if not tags:
        raise Stop(f"cannot find the latest tag of {SHARED_REPO}; no report was written", 1)
    return max(tags, key=version_key)


def list_repos(client: Client, owner: str) -> list[tuple[str, str]]:
    found = []
    for page in range(1, MAX_PAGES + 1):
        status, body = client.get(f"/users/{owner}/repos?type=owner&per_page=100&page={page}")
        if status != 200 or not isinstance(body, list):
            raise Stop(f"cannot list the repositories of {owner} (HTTP {status}); no report was written", 1)
        for item in body:
            if not isinstance(item, dict) or item.get("archived") or item.get("fork"):
                continue
            name, branch = str(item.get("name", "")), str(item.get("default_branch", ""))
            if NAME.match(name) and BRANCH.match(branch) and ".." not in branch:
                found.append((f"{owner}/{name}", branch))
        if len(body) < 100:
            break
    return sorted(found)


def totals(repos: list[dict]) -> dict:
    alerts = dict.fromkeys(SEVERITIES, 0)
    for r in repos:
        if isinstance(r["alerts"], dict):
            for severity in SEVERITIES:
                alerts[severity] += r["alerts"][severity]
    return {
        "repos": len(repos),
        "pins_behind": sum(r["pins"]["status"] == "behind" for r in repos),
        "unprotected": sum(r["protection"]["status"] == "unprotected" for r in repos),
        "ci_red": sum(r["ci"] == "failure" for r in repos),
        "alerts": alerts,
    }


def cell(text: object) -> str:
    return clean(text).replace("\\", "\\\\").replace("|", "\\|").replace("`", "'")


def render(report: dict) -> str:
    t = report["totals"]
    unreadable = sum(r["alerts"] == "n/a" for r in report["repos"])
    lines = [
        "### Fleet status",
        "",
        f"Owners: {', '.join(cell(o) for o in report['owners'])}. Latest GYST release: {cell(report['latest'])}. "
        f"Generated {report['generated_at']}. `n/a` means the token could not read it.",
        "",
        f"{t['repos']} repositories: {t['pins_behind']} behind on pins, "
        f"{t['unprotected']} with an unprotected default branch, "
        f"{t['ci_red']} with a red default branch; open alerts "
        + ", ".join(f"{t['alerts'][s]} {s}" for s in SEVERITIES)
        + (f" (alerts not readable for {unreadable} of them)" if unreadable else "")
        + ".",
        "",
        "| Repo | GYST pins | Alerts (C/H/M/L) | Default branch | Required checks | Newest push |",
        "|---|---|---|---|---|---|",
    ]
    for r in report["repos"]:
        pins = r["pins"]
        pin_cell = pins["status"] + (f" ({', '.join(pins['versions'])})" if pins["versions"] else "")
        alerts = r["alerts"]
        alert_cell = (
            "n/a"
            if alerts == "n/a"
            else "/".join(str(alerts[s]) for s in SEVERITIES) + (" (truncated)" if r.get("alerts_truncated") else "")
        )
        checks = r["protection"]["required_checks"]
        lines.append(
            f"| {cell(r['repo'])} | {cell(pin_cell)} | {alert_cell} | {cell(r['protection']['status'])} | "
            f"{cell(', '.join(checks)) if checks else '-'} | {cell(r['ci'])} |"
        )
    return "\n".join(lines) + "\n"


def run(client: Client, owners: list[str], now: dt.datetime) -> dict:
    latest = latest_tag(client)
    repos = [read_repo(client, full, branch, latest) for owner in owners for full, branch in list_repos(client, owner)]
    return {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "latest": latest,
        "owners": owners,
        "totals": totals(repos),
        "repos": repos,
    }


def main(
    argv: list[str] | None = None,
    transport: Transport = urllib_transport,
    sleep: Callable[[float], None] = time.sleep,
    environ: dict | None = None,
    now: dt.datetime | None = None,
) -> int:
    parser = argparse.ArgumentParser(description="Fleet status: pins, alert counts, protection and CI, counts only.")
    parser.add_argument(
        "--owner", action="append", help="user or organization to report on (repeatable; default ChiefGyk3D)"
    )
    parser.add_argument("--json", dest="json_path", help="write the JSON report here")
    parser.add_argument("--markdown", help="write the markdown table here (default: standard output)")
    parser.add_argument("--max-requests", type=int, default=MAX_REQUESTS)
    args = parser.parse_args(argv)
    owners = args.owner or ["ChiefGyk3D"]
    if not all(NAME.match(o) for o in owners) or args.max_requests < 1:
        print("fleet_status: an owner must be a GitHub login; --max-requests must be positive", file=sys.stderr)
        return 1
    env = os.environ if environ is None else environ
    token = env.get("GITHUB_TOKEN") or env.get("GH_TOKEN") or ""
    if not token:
        print(
            "fleet_status: no GITHUB_TOKEN or GH_TOKEN; unauthenticated reads allow 60 requests an hour",
            file=sys.stderr,
        )
    client = Client(transport, token, sleep, args.max_requests)
    try:
        report = run(client, owners, now or dt.datetime.now(dt.UTC))
    except Stop as stop:
        print(f"fleet_status: {stop}", file=sys.stderr)
        return stop.code
    table = render(report)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(table)
    else:
        sys.stdout.write(table)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
