"""scripts/fleet_status.py and fleet-status.yml: the fleet report, counts only, run against a stubbed GitHub.

No test touches the network. A fake transport answers by path, so every fixture is a repository as GitHub would
describe it: current, behind, unprotected, one whose Dependabot alerts the token cannot read, and a rate limit.
Advisory text, package names and the token are planted in the answers; the report must carry none of them.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "fleet_status.py"
WORKFLOW = REPO / ".github" / "workflows" / "fleet-status.yml"

spec = importlib.util.spec_from_file_location("fleet_status", SCRIPT)
fs = importlib.util.module_from_spec(spec)
sys.modules["fleet_status"] = fs
spec.loader.exec_module(fs)

API = "https://api.github.com"
OWNER = "ChiefGyk3D"
GYST = "ChiefGyk3D/git-your-ship-together"
LATEST = "v1.2.0"
TOKEN = "ghs_PLANTEDTOKENVALUE0123456789"
SHA = "d5d9556afeeb06f78419b91ecb5d146e789c6d51"
PLANTED_TEXT = "PLANTED-ADVISORY-SUMMARY remote code execution in planted-package"
PLANTED_PACKAGE = "planted-package"
CALLERS = f"{GYST}/.github/workflows"


def workflow_text(*pins: str) -> str:
    lines = ["name: CI", "on: [push]", "permissions:", "  contents: read", "jobs:"]
    for n, version in enumerate(pins):
        lines += [f"  job{n}:", f"    uses: {CALLERS}/python-ci.yml@{SHA} # {version}"]
    return "\n".join(lines) + "\n"


def content(text: str) -> dict:
    return {
        "type": "file",
        "size": len(text),
        "encoding": "base64",
        "content": base64.encodebytes(text.encode()).decode(),
    }


class Reply:
    def __init__(self, status: int = 200, body=None, headers: dict | None = None):
        self.status = status
        self.body = {} if body is None else body
        self.headers = {"x-ratelimit-remaining": "4000", **(headers or {})}


def denied(message: str = "Resource not accessible by integration") -> Reply:
    return Reply(403, {"message": message, "documentation_url": "https://docs.github.com/rest"})


def alert(severity: str) -> dict:
    return {
        "number": 1,
        "state": "open",
        "security_advisory": {"severity": severity, "summary": PLANTED_TEXT},
        "security_vulnerability": {"severity": severity, "package": {"name": PLANTED_PACKAGE}},
    }


def repo_entry(name: str, **extra) -> dict:
    return {
        "full_name": f"{OWNER}/{name}",
        "name": name,
        "default_branch": "main",
        "archived": False,
        "fork": False,
    } | extra


def run(conclusion: str, sha: str = "a" * 40, event: str = "push") -> dict:
    return {"status": "completed", "conclusion": conclusion, "event": event, "head_sha": sha, "name": "CI"}


class FakeGitHub:
    """A transport: answers by path (query ignored) and records every call."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.calls: list[tuple[str, dict, float]] = []

    def __call__(self, url: str, headers: dict, timeout: float):
        self.calls.append((url, dict(headers), timeout))
        assert url.startswith(API + "/"), f"a request left api.github.com: {url}"
        path, _, query = url[len(API) :].partition("?")
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        reply = self.routes.get(path, Reply(404, {"message": "Not Found"}))
        if callable(reply):
            reply = reply(params)
        if isinstance(reply, list):  # pages
            page = int(params.get("page", "1"))
            reply = Reply(200, reply[page - 1] if page <= len(reply) else [])
        if isinstance(reply, BaseException):
            raise reply
        return reply.status, reply.headers, json.dumps(reply.body).encode()

    def paths(self) -> list[str]:
        return [u[len(API) :].split("?")[0] for u, _, _ in self.calls]


def repo_routes(name: str, *, workflows: dict | None, alerts, protection: Reply, runs: Reply, rules=None) -> dict:
    base = f"/repos/{OWNER}/{name}"
    routes: dict = {
        f"{base}/dependabot/alerts": alerts,
        f"{base}/branches/main/protection": protection,
        f"{base}/rules/branches/main": rules if rules is not None else Reply(200, []),
        f"{base}/actions/runs": runs,
    }
    if workflows is None:
        routes[f"{base}/contents/.github/workflows"] = Reply(404, {"message": "Not Found"})
    else:
        routes[f"{base}/contents/.github/workflows"] = Reply(
            200, [{"name": n, "path": f".github/workflows/{n}", "type": "file", "size": 100} for n in workflows]
        )
        for n, text in workflows.items():
            routes[f"{base}/contents/.github/workflows/{n}"] = Reply(200, content(text))
    return routes


def fleet() -> dict:
    routes: dict = {
        f"/users/{OWNER}/repos": [
            [
                repo_entry("current"),
                repo_entry("behind"),
                repo_entry("unprotected"),
                repo_entry("denied"),
                repo_entry("old-archive", archived=True),
                repo_entry("a-fork", fork=True),
            ]
        ],
        f"/repos/{GYST}/releases/latest": Reply(200, {"tag_name": LATEST, "name": PLANTED_TEXT}),
    }
    routes |= repo_routes(
        "current",
        workflows={"ci.yml": workflow_text(LATEST, LATEST)},
        alerts=Reply(200, []),
        protection=Reply(
            200,
            {"required_status_checks": {"checks": [{"context": "CI green", "app_id": 1}], "contexts": ["CI green"]}},
        ),
        runs=Reply(200, {"workflow_runs": [run("success")]}),
    )
    routes |= repo_routes(
        "behind",
        workflows={"ci.yml": workflow_text("v1.0.0", LATEST), "notes.txt": "x", "release.yml": workflow_text("v1.1.0")},
        alerts=[[alert("critical"), alert("high"), alert("high"), alert("medium"), alert("low"), alert("low")]],
        protection=Reply(200, {"required_status_checks": {"contexts": ["ci / CI green", "lint"]}}),
        runs=Reply(
            200, {"workflow_runs": [run("success", "b" * 40), run("failure", "b" * 40), run("success", "c" * 40)]}
        ),
    )
    routes |= repo_routes(
        "unprotected",
        workflows=None,
        alerts=Reply(200, []),
        protection=Reply(404, {"message": "Branch not protected"}),
        runs=Reply(200, {"workflow_runs": [run("failure")]}),
    )
    routes |= repo_routes(
        "denied",
        workflows={"ci.yml": workflow_text(LATEST)},
        alerts=denied(),
        protection=denied(),
        runs=Reply(200, {"workflow_runs": []}),
    )
    return routes


def go(tmp_path, routes=None, extra=None, sleeps=None, token=TOKEN):
    """Run the script's main against a fake; returns (exit code, FakeGitHub, markdown, json document or None)."""
    fake = FakeGitHub(routes if routes is not None else fleet())
    md, js = tmp_path / "report.md", tmp_path / "report.json"
    env = {"GITHUB_TOKEN": token} if token else {}
    code = fs.main(
        ["--markdown", str(md), "--json", str(js), *(extra or [])],
        transport=fake,
        sleep=(sleeps.append if sleeps is not None else (lambda _s: None)),
        environ=env,
    )
    return code, fake, md.read_text() if md.exists() else None, json.loads(js.read_text()) if js.exists() else None


def by_name(doc: dict) -> dict:
    return {r["repo"].split("/")[1]: r for r in doc["repos"]}


# --- the report -------------------------------------------------------------------------------------------------


def test_the_fleet_is_listed_without_archived_repos_and_forks(tmp_path):
    code, fake, md, doc = go(tmp_path)
    assert code == 0
    assert sorted(by_name(doc)) == ["behind", "current", "denied", "unprotected"]
    assert "old-archive" not in md and "a-fork" not in md
    assert not [p for p in fake.paths() if "old-archive" in p or "a-fork" in p], "an excluded repo was read"
    assert doc["latest"] == LATEST and doc["owners"] == [OWNER]


def test_a_current_repo_is_current_and_clean(tmp_path):
    _, _, _, doc = go(tmp_path)
    r = by_name(doc)["current"]
    assert r["pins"] == {"status": "current", "versions": [LATEST], "count": 2}
    assert r["alerts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert r["protection"] == {"status": "protected", "required_checks": ["CI green"]}
    assert r["ci"] == "success"


def test_a_behind_repo_names_every_version_and_counts_alerts_by_severity(tmp_path):
    _, _, _, doc = go(tmp_path)
    r = by_name(doc)["behind"]
    assert r["pins"] == {"status": "behind", "versions": ["v1.0.0", "v1.1.0", "v1.2.0"], "count": 3}
    assert r["alerts"] == {"critical": 1, "high": 2, "medium": 1, "low": 2}
    assert r["protection"]["required_checks"] == ["ci / CI green", "lint"], "exact names, sorted"
    # the newest head commit failed in one workflow: that is a red main, not the older green one
    assert r["ci"] == "failure"


def test_an_unprotected_repo_is_reported_unprotected_with_no_checks(tmp_path):
    _, _, _, doc = go(tmp_path)
    r = by_name(doc)["unprotected"]
    assert r["protection"] == {"status": "unprotected", "required_checks": []}
    assert r["pins"] == {"status": "none", "versions": [], "count": 0}
    assert r["ci"] == "failure"


def test_a_ruleset_counts_as_protection(tmp_path):
    routes = fleet()
    routes |= repo_routes(
        "unprotected",
        workflows=None,
        alerts=Reply(200, []),
        protection=Reply(404, {"message": "Branch not protected"}),
        rules=Reply(
            200,
            [
                {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "CI green"}]}},
                {"type": "deletion"},
            ],
        ),
        runs=Reply(200, {"workflow_runs": []}),
    )
    _, _, _, doc = go(tmp_path, routes)
    assert by_name(doc)["unprotected"]["protection"] == {"status": "ruleset", "required_checks": ["CI green"]}


def test_an_access_denied_read_is_na_never_a_guess(tmp_path):
    _, _, md, doc = go(tmp_path)
    r = by_name(doc)["denied"]
    assert r["alerts"] == "n/a" and r["protection"] == {"status": "n/a", "required_checks": []}
    assert r["pins"]["status"] == "current", "a readable part of the same repo is still reported"
    assert r["ci"] == "none"
    assert "alerts not readable for 1 of them" in md, "the totals line must say they are not the whole fleet"
    row = next(line for line in md.splitlines() if "denied" in line and line.startswith("|"))
    assert row.count("n/a") >= 2
    # the 404 of a repo whose protection is not readable is not "unprotected"
    routes = fleet()
    routes[f"/repos/{OWNER}/denied/branches/main/protection"] = Reply(404, {"message": "Not Found"})
    _, _, _, doc = go(tmp_path, routes)
    assert by_name(doc)["denied"]["protection"]["status"] == "n/a"


def test_a_pin_newer_than_the_latest_tag_is_not_behind():
    assert fs.pin_status(["v1.3.0"], "v1.2.0") == "current"
    assert fs.pin_status(["v1.2.0", "v1.10.0"], "v1.10.0") == "behind", "1.2 < 1.10 numerically"
    assert fs.pin_status([], "v1.2.0") == "none"
    assert fs.pin_status(["v1.2.0", "unknown"], "v1.2.0") == "unknown"


def test_pins_are_read_from_gyst_uses_lines_only():
    text = "\n".join(
        [
            f"      - uses: {GYST}/.github/actions/ci-gate@{SHA} # v1.1.0",
            f"    uses: {CALLERS}/security.yml@{SHA} # v1.2.0",
            "    uses: ./.github/workflows/local.yml",
            f"    uses: actions/checkout@{SHA} # v9.9.9",
            f"    uses: someone-else/git-your-ship-together/.github/workflows/x.yml@{SHA} # v8.8.8",
            f"    uses: {CALLERS}/bash-ci.yml@{SHA}",
            f"# uses: {CALLERS}/python-ci.yml@{SHA} # v0.0.1",
        ]
    )
    assert fs.workflow_pins(text) == ["v1.1.0", "v1.2.0", "unknown"]


def test_one_pin_without_a_version_comment_makes_the_repo_unknown_not_current(tmp_path):
    routes = fleet()
    routes |= repo_routes(
        "current",
        workflows={"ci.yml": workflow_text(LATEST) + f"  x:\n    uses: {CALLERS}/bash-ci.yml@{SHA}\n"},
        alerts=Reply(200, []),
        protection=Reply(200, {}),
        runs=Reply(200, {"workflow_runs": []}),
    )
    _, _, _, doc = go(tmp_path, routes)
    assert by_name(doc)["current"]["pins"]["status"] == "unknown"


def test_the_latest_tag_falls_back_to_the_highest_semver_tag(tmp_path):
    routes = fleet()
    routes[f"/repos/{GYST}/releases/latest"] = Reply(404, {"message": "Not Found"})
    routes[f"/repos/{GYST}/tags"] = Reply(
        200, [{"name": "v1.9.0"}, {"name": "v1.10.0"}, {"name": "latest"}, {"name": "v1.2.0"}]
    )
    _, _, _, doc = go(tmp_path, routes)
    assert doc["latest"] == "v1.10.0"
    assert by_name(doc)["current"]["pins"]["status"] == "behind"


def test_no_latest_tag_is_a_clear_failure_not_a_report(tmp_path, capsys):
    routes = fleet()
    routes[f"/repos/{GYST}/releases/latest"] = Reply(404, {"message": "Not Found"})
    code, _, md, doc = go(tmp_path, routes)
    assert code == 1 and md is None and doc is None
    assert "latest" in capsys.readouterr().err


def test_alert_pages_are_followed_and_capped(tmp_path):
    routes = fleet()
    page = [alert("high")] * 100
    routes[f"/repos/{OWNER}/current/dependabot/alerts"] = [page, page, [alert("low")]]
    _, _, _, doc = go(tmp_path, routes)
    assert by_name(doc)["current"]["alerts"] == {"critical": 0, "high": 200, "medium": 0, "low": 1}
    routes[f"/repos/{OWNER}/current/dependabot/alerts"] = lambda params: Reply(200, page)
    _, fake, _, doc = go(tmp_path, routes)
    r = by_name(doc)["current"]
    assert r["alerts"]["high"] == 100 * fs.MAX_PAGES and r["alerts_truncated"] is True
    assert fake.paths().count(f"/repos/{OWNER}/current/dependabot/alerts") == fs.MAX_PAGES


def test_an_unknown_severity_is_counted_as_other_not_dropped(tmp_path):
    routes = fleet()
    routes[f"/repos/{OWNER}/current/dependabot/alerts"] = Reply(200, [alert("catastrophic"), {"state": "open"}])
    _, _, _, doc = go(tmp_path, routes)
    assert by_name(doc)["current"]["alerts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 2}


def test_a_second_owner_is_listed_with_the_same_checks(tmp_path):
    routes = fleet()
    routes["/users/Other-Org/repos"] = [[repo_entry("thing") | {"full_name": "Other-Org/thing"}]]
    routes["/repos/Other-Org/thing/dependabot/alerts"] = Reply(200, [])
    routes["/repos/Other-Org/thing/branches/main/protection"] = Reply(404, {"message": "Branch not protected"})
    code, _, md, doc = go(tmp_path, routes, extra=["--owner", OWNER, "--owner", "Other-Org"])
    assert code == 0 and doc["owners"] == [OWNER, "Other-Org"]
    assert "Other-Org/thing" in {r["repo"] for r in doc["repos"]}


# --- counts only: nothing else leaves ---------------------------------------------------------------------------


def test_no_advisory_text_package_name_or_token_reaches_either_output(tmp_path):
    code, _, md, doc = go(tmp_path)
    assert code == 0
    blob = md + json.dumps(doc) + (tmp_path / "report.json").read_text()
    for planted in (PLANTED_TEXT, "PLANTED-ADVISORY", PLANTED_PACKAGE, TOKEN, "Bearer", "documentation_url"):
        assert planted not in blob, f"{planted!r} leaked into the report"


def test_the_json_has_only_the_documented_shape(tmp_path):
    _, _, _, doc = go(tmp_path)
    assert set(doc) == {"generated_at", "latest", "owners", "totals", "repos"}
    for r in doc["repos"]:
        assert set(r) - {"alerts_truncated"} == {"repo", "default_branch", "pins", "alerts", "protection", "ci"}
    assert doc["totals"] == {
        "repos": 4,
        "pins_behind": 1,
        "unprotected": 1,
        "ci_red": 2,
        "alerts": {"critical": 1, "high": 2, "medium": 1, "low": 2},
    }


def test_the_markdown_is_a_table_with_one_row_per_repo(tmp_path):
    _, _, md, _ = go(tmp_path)
    rows = [
        line
        for line in md.splitlines()
        if line.startswith("| ") and not line.startswith("| Repo") and "---" not in line
    ]
    assert len(rows) == 4
    assert all(line.count("|") == rows[0].count("|") for line in rows), "a cell broke the table"
    assert LATEST in md and "behind" in md and "unprotected" in md


def test_a_hostile_check_name_cannot_break_the_table(tmp_path):
    routes = fleet()
    routes[f"/repos/{OWNER}/current/branches/main/protection"] = Reply(
        200, {"required_status_checks": {"contexts": ["a|b\n| fake | row |", "`x`", "z" * 500]}}
    )
    _, _, md, doc = go(tmp_path, routes)

    def cells(owner_repo: str) -> int:
        row = next(line for line in md.splitlines() if line.startswith("| ") and f"{OWNER}/{owner_repo} " in line)
        return len(re.findall(r"(?<!\\)\|", row))

    assert cells("current") == cells("behind")
    assert "\n| fake" not in md
    assert all(len(c) <= fs.MAX_CHECK_LEN for c in by_name(doc)["current"]["protection"]["required_checks"])


# --- bounded, polite network ------------------------------------------------------------------------------------


def test_every_request_has_a_timeout_goes_to_api_github_and_carries_the_token_only_there(tmp_path):
    _, fake, _, _ = go(tmp_path)
    assert fake.calls
    for url, headers, timeout in fake.calls:
        assert url.startswith(API + "/") and 0 < timeout <= 30
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        assert "If-None-Match" not in headers and "ETag" not in headers, "simple GETs, no ETag"


def test_a_transient_failure_is_retried_a_small_number_of_times_then_gives_up_on_that_read(tmp_path):
    routes = fleet()
    flaky = {"n": 0}

    def alerts(_params):
        flaky["n"] += 1
        return OSError("timed out") if flaky["n"] <= 2 else Reply(200, [alert("high")])

    routes[f"/repos/{OWNER}/current/dependabot/alerts"] = alerts
    sleeps: list[float] = []
    _, _, _, doc = go(tmp_path, routes, sleeps=sleeps)
    assert by_name(doc)["current"]["alerts"]["high"] == 1 and flaky["n"] == 3
    assert 0 < len(sleeps) <= 4 and max(sleeps) <= 10, "a short, capped backoff"

    routes[f"/repos/{OWNER}/current/dependabot/alerts"] = OSError("down")
    _, fake, _, doc = go(tmp_path, routes)
    assert by_name(doc)["current"]["alerts"] == "n/a"
    assert fake.paths().count(f"/repos/{OWNER}/current/dependabot/alerts") == fs.RETRIES + 1


def test_a_5xx_is_retried_but_a_403_or_404_is_not(tmp_path):
    routes = fleet()
    seen = {"n": 0}

    def alerts(_params):
        seen["n"] += 1
        return Reply(502, {"message": "Bad Gateway"}) if seen["n"] == 1 else Reply(200, [])

    routes[f"/repos/{OWNER}/current/dependabot/alerts"] = alerts
    go(tmp_path, routes)
    assert seen["n"] == 2
    _, fake, _, _ = go(tmp_path)
    assert fake.paths().count(f"/repos/{OWNER}/denied/dependabot/alerts") == 1


@pytest.mark.parametrize(
    "reply",
    [
        Reply(
            403,
            {"message": "API rate limit exceeded for user ID 1."},
            {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1999999999"},
        ),
        Reply(403, {"message": "You have exceeded a secondary rate limit."}, {"retry-after": "60"}),
        Reply(429, {"message": "Too Many Requests"}),
    ],
    ids=["primary", "secondary", "429"],
)
def test_a_rate_limit_stops_the_run_with_a_clear_message_and_no_guessed_report(tmp_path, capsys, reply):
    routes = fleet()
    routes[f"/repos/{OWNER}/behind/dependabot/alerts"] = reply
    code, fake, md, doc = go(tmp_path, routes)
    err = capsys.readouterr().err
    assert code == 2 and "rate limit" in err.lower() and "no report" in err.lower()
    assert md is None and doc is None, "a partial report would read as a clean fleet"
    assert not [p for p in fake.paths() if "/unprotected/" in p], "the run kept going after the limit"


def test_an_access_denied_403_is_not_mistaken_for_a_rate_limit(tmp_path):
    code, _, _, doc = go(tmp_path)
    assert code == 0 and by_name(doc)["denied"]["alerts"] == "n/a"


def test_an_exhausted_budget_stops_before_the_next_request(tmp_path, capsys):
    routes = fleet()
    routes[f"/repos/{OWNER}/behind/dependabot/alerts"] = Reply(
        200, [], {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1999999999"}
    )
    code, fake, md, _ = go(tmp_path, routes)
    assert code == 2 and md is None
    assert fake.paths()[-1] == f"/repos/{OWNER}/behind/dependabot/alerts", "a request was made on an empty budget"
    assert "rate limit" in capsys.readouterr().err.lower()


def test_the_request_total_is_capped(tmp_path, capsys):
    code, fake, md, _ = go(tmp_path, extra=["--max-requests", "5"])
    assert code == 2 and md is None and len(fake.calls) == 5
    assert "request" in capsys.readouterr().err.lower()


def test_the_listing_cannot_run_away(tmp_path):
    routes = fleet()
    routes[f"/users/{OWNER}/repos"] = lambda params: Reply(
        200, [repo_entry(f"r{params['page']}-{i}") for i in range(100)]
    )
    code, fake, _, _ = go(tmp_path, routes, extra=["--max-requests", "100000"])
    assert fake.paths().count(f"/users/{OWNER}/repos") == fs.MAX_PAGES


def test_hostile_names_from_the_listing_are_refused(tmp_path):
    routes = fleet()
    routes[f"/users/{OWNER}/repos"] = [
        [repo_entry("ok"), repo_entry("../../etc"), repo_entry("a b"), repo_entry("x", default_branch="ma in")]
    ]
    routes |= repo_routes(
        "ok", workflows=None, alerts=Reply(200, []), protection=Reply(200, {}), runs=Reply(200, {"workflow_runs": []})
    )
    _, fake, _, doc = go(tmp_path, routes)
    assert list(by_name(doc)) == ["ok"]
    assert all(" " not in p and ".." not in p for p in fake.paths())


def test_a_bad_owner_or_no_token_is_handled(tmp_path, capsys):
    code, fake, _, _ = go(tmp_path, extra=["--owner", "bad owner/../x"])
    assert code == 1 and not fake.calls
    code, fake, _, doc = go(tmp_path, token="")
    assert code == 0 and all("Authorization" not in h for _, h, _ in fake.calls)
    assert "unauthenticated" in capsys.readouterr().err.lower()


def test_the_transport_never_follows_a_redirect():
    handler = next(h for h in fs.build_opener().handlers if hasattr(h, "redirect_request"))
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.example/") is None


# --- the workflow -----------------------------------------------------------------------------------------------


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def test_the_workflow_is_weekly_and_on_demand_and_reads_only():
    doc = workflow()
    on = doc.get("on") or doc.get(True)
    assert set(on) == {"schedule", "workflow_dispatch"}
    assert len(on["schedule"]) == 1 and re.fullmatch(r"\d+ \d+ \* \* \d", on["schedule"][0]["cron"])
    assert doc["permissions"] == {"contents": "read"}
    assert len(doc["jobs"]) == 1
    job = next(iter(doc["jobs"].values()))
    assert job["permissions"] == {"contents": "read"}
    assert job.get("timeout-minutes", 99) <= 15


def test_the_workflow_holds_no_secret_and_no_credential_beyond_the_job_token():
    text = WORKFLOW.read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "secrets." not in code and "doppler" not in code.lower() and "create-github-app-token" not in code
    assert "id-token" not in code and "persist-credentials: false" in code
    assert "GITHUB_TOKEN: ${{ github.token }}" in code


def test_the_workflow_writes_the_table_to_the_summary_and_uploads_the_json():
    job = next(iter(workflow()["jobs"].values()))
    steps = job["steps"]
    assert steps[0]["uses"].startswith("step-security/harden-runner@")
    assert steps[0]["with"]["egress-policy"] == "block"
    text = WORKFLOW.read_text()
    assert "python3 scripts/fleet_status.py" in text and "GITHUB_STEP_SUMMARY" in text
    upload = next(s for s in steps if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    assert upload["with"]["path"].endswith(".json") and upload["with"]["retention-days"] <= 30
    summary = next(s for s in steps if "GITHUB_STEP_SUMMARY" in str(s.get("run", "")))
    assert summary.get("if") == "always()" or "if" not in summary


def test_the_workflow_reports_what_its_token_can_read_as_na():
    text = WORKFLOW.read_text()
    assert "n/a" in text and "default job token" in text.replace("\n# ", " ")


def test_the_script_is_standard_library_only_and_never_graphql():
    text = SCRIPT.read_text()
    imports = set(re.findall(r"^(?:import|from) ([\w.]+)", text, re.M))
    assert not {m for m in imports if m.split(".")[0] in {"requests", "yaml", "httpx", "github"}}
    assert "graphql" not in text.lower()
    assert "subprocess" not in text
