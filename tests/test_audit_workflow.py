"""audit.yml is this repository's own weekly job, not a reusable workflow.

It holds the one token that can read every repository's settings, so the
properties pinned here are about where that token can and cannot go: only the
audit job, only from main or the schedule, only through its own Doppler
project, and never beside the job that writes issues.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
AUDIT = REPO / ".github" / "workflows" / "audit.yml"
COMPOSITE = REPO / ".github" / "actions" / "doppler-secrets" / "action.yml"

ALLOW_LIST = "api.doppler.com:443 api.github.com:443 files.pythonhosted.org:443 github.com:443 pypi.org:443"


def doc() -> dict:
    return yaml.safe_load(AUDIT.read_text())


def steps(job: str) -> list[dict]:
    return doc()["jobs"][job]["steps"]


def test_it_runs_weekly_on_monday_and_by_hand_and_is_not_callable():
    on = doc().get("on") or doc().get(True)
    assert on["schedule"] == [{"cron": "0 7 * * 1"}]
    assert "workflow_dispatch" in on
    assert "workflow_call" not in on
    assert "pull_request" not in on and "push" not in on


def test_the_jobs_and_their_permissions():
    d = doc()
    assert d["permissions"] == {"contents": "read"}
    assert set(d["jobs"]) == {"audit", "register-issues"}
    assert d["jobs"]["audit"]["permissions"] == {"contents": "read", "id-token": "write"}
    assert d["jobs"]["register-issues"]["permissions"] == {"contents": "read", "issues": "write"}
    assert d["jobs"]["audit"]["runs-on"] == "ubuntu-24.04"
    assert d["jobs"]["audit"]["timeout-minutes"] == 15


def test_every_job_starts_with_a_blocking_harden_runner_and_the_exact_allow_list():
    for name in doc()["jobs"]:
        first = steps(name)[0]
        assert first["uses"].startswith("step-security/harden-runner@")
        assert first["with"]["egress-policy"] == "block"
    audit_hosts = steps("audit")[0]["with"]["allowed-endpoints"]
    assert audit_hosts == ALLOW_LIST
    assert audit_hosts.split() == sorted(audit_hosts.split())
    # the issue job never talks to Doppler
    assert "api.doppler.com:443" not in steps("register-issues")[0]["with"]["allowed-endpoints"]


def test_every_checkout_refuses_to_persist_credentials():
    for name in doc()["jobs"]:
        for step in steps(name):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_the_doppler_decision_is_the_composite_actions_script_and_requires_a_secret():
    composite = [s["run"] for s in yaml.safe_load(COMPOSITE.read_text())["runs"]["steps"] if s.get("id") == "mode"]
    decide = [s for s in steps("audit") if str(s.get("name", "")).startswith("Decide how to authenticate")]
    assert [s["run"] for s in decide] == composite
    env = decide[0]["env"]
    assert env["PROJECT"] == "audit" and env["CONFIG"] == "prd"
    assert env["REQUIRED"] == "true", "an audit that could not fetch its token must fail, not skip"
    assert env["TRUSTED_ONLY"] == "true"
    assert env["IDENTITY_ID"] == "${{ vars.AUDIT_DOPPLER_IDENTITY_ID }}"
    fetch = [s for s in steps("audit") if str(s.get("uses", "")).startswith("dopplerhq/secrets-fetch-action@")]
    assert len(fetch) == 1
    assert fetch[0]["if"] == "steps.doppler.outputs.mode == 'oidc'"
    assert fetch[0]["with"]["doppler-project"] == "audit"
    assert fetch[0]["with"]["doppler-config"] == "prd"
    assert fetch[0]["with"]["doppler-identity-id"] == "${{ vars.AUDIT_DOPPLER_IDENTITY_ID }}"


def test_the_audit_runs_with_the_fetched_token_and_fails_the_job_on_fail_or_unknown():
    run = next(s["run"] for s in steps("audit") if "audit_baseline.py" in s.get("run", ""))
    assert 'GH_TOKEN="$AUDIT_GITHUB_TOKEN" python scripts/audit_baseline.py' in run
    assert "--allow-unknown" not in run
    assert "set -euo pipefail" in run and "| tee audit.txt" in run
    summary = next(s for s in steps("audit") if "GITHUB_STEP_SUMMARY" in s.get("run", ""))
    assert summary["if"] == "always()"


def test_the_audit_token_never_reaches_the_issue_job_and_the_issue_job_never_reaches_doppler():
    text = AUDIT.read_text()
    issues = yaml.dump(doc()["jobs"]["register-issues"])
    assert "AUDIT_GITHUB_TOKEN" not in issues and "doppler" not in issues.lower()
    assert "id-token" not in issues
    env = next(s for s in steps("register-issues") if "gh issue" in s.get("run", ""))["env"]
    assert env["GH_TOKEN"] == "${{ github.token }}"
    assert env["GH_REPO"] == "${{ github.repository }}"
    assert text.count("AUDIT_GITHUB_TOKEN") >= 2  # the guard and the use, both in the audit job


def test_the_issue_job_dedupes_on_the_title_and_asks_the_script_for_the_entries():
    run = next(s["run"] for s in steps("register-issues") if "gh issue" in s.get("run", ""))
    assert "scripts/audit_baseline.py --expiring" in run
    assert 'title="Risk register: $id expires $date"' in run
    assert "gh issue list" in run and "gh issue create" in run
