"""audit.yml is this repository's own weekly job, not a reusable workflow.

It reads every repository's settings with GitHub App installation tokens, one
per owner, minted from a private key held in its own Doppler project. The
properties pinned here are about where that key and those tokens can and cannot
go: only the audit job, only from main or the schedule, only through the
`audit` Doppler project, never beside the job that writes issues, and that no
personal access token is back.
"""

from __future__ import annotations

import re
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


def mint_steps() -> list[dict]:
    return [s for s in steps("audit") if str(s.get("uses", "")).startswith("actions/create-github-app-token@")]


def test_one_installation_token_is_minted_per_owner_from_the_app_key_with_the_client_id():
    mints = {s["with"]["owner"].split()[0]: s for s in mint_steps()}
    assert set(mints) == {"ChiefGyk3D", "Renegade-Penguin"}
    for owner, step in mints.items():
        assert step["with"]["client-id"] == "${{ vars.AUDIT_APP_CLIENT_ID }}"
        assert "app-id" not in step["with"], "app-id is deprecated (#92); client-id is the input"
        assert step["with"]["private-key"] == "${{ env.AUDIT_APP_PRIVATE_KEY }}"
        assert "skip-token-revoke" not in step["with"], f"the {owner} token must be revoked when the job ends"
    # the pin is a commit, never a tag
    for step in mint_steps():
        assert re.fullmatch(r"actions/create-github-app-token@[0-9a-f]{40}", step["uses"])
    # both come after the Doppler fetch that supplies the key, and before the audit
    order = [str(s.get("uses", s.get("name", ""))) for s in steps("audit")]
    fetch = next(i for i, u in enumerate(order) if u.startswith("dopplerhq/secrets-fetch-action@"))
    audit_step = next(i for i, s in enumerate(steps("audit")) if "audit_baseline.py" in s.get("run", ""))
    assert fetch < min(order.index(s["uses"]) for s in mint_steps()) < audit_step


def test_the_audit_reads_each_owner_with_its_own_token_and_fails_the_job_on_fail_or_unknown():
    step = next(s for s in steps("audit") if "audit_baseline.py" in s.get("run", ""))
    run = step["run"]
    assert "--owner-token ChiefGyk3D=AUDIT_TOKEN_USER" in run
    assert "--owner-token Renegade-Penguin=AUDIT_TOKEN_ORG" in run
    assert "--allow-unknown" not in run
    assert "set -euo pipefail" in run and "| tee audit.txt" in run
    users = {s["id"]: s for s in mint_steps()}
    assert step["env"]["AUDIT_TOKEN_USER"] == "${{ steps.app-user.outputs.token }}"
    assert step["env"]["AUDIT_TOKEN_ORG"] == "${{ steps.app-org.outputs.token }}"
    assert users["app-user"]["with"]["owner"].startswith("ChiefGyk3D")
    assert users["app-org"]["with"]["owner"].startswith("Renegade-Penguin")
    summary = next(s for s in steps("audit") if "GITHUB_STEP_SUMMARY" in s.get("run", ""))
    assert summary["if"] == "always()"


def test_every_owner_in_the_repository_list_has_a_token_in_the_workflow():
    """An owner added to baseline/repos.txt with no --owner-token is UNKNOWN every Monday; fail here first."""
    run = next(s["run"] for s in steps("audit") if "audit_baseline.py" in s.get("run", ""))
    covered = set(re.findall(r"--owner-token (\S+?)=", run))
    owners = {
        line.split("/", 1)[0]
        for line in (REPO / "baseline" / "repos.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    assert owners <= covered, f"no installation token for {sorted(owners - covered)}: add a mint step and --owner-token"


def test_no_personal_access_token_is_used_or_named_anywhere_in_the_workflow():
    live = "\n".join(line for line in AUDIT.read_text().splitlines() if not line.lstrip().startswith("#"))
    assert "AUDIT_GITHUB_TOKEN" not in live
    assert "GH_TOKEN=" not in live


def test_the_app_key_never_reaches_the_issue_job_and_the_issue_job_never_reaches_doppler():
    text = AUDIT.read_text()
    issues = yaml.dump(doc()["jobs"]["register-issues"])
    for name in ("AUDIT_APP_PRIVATE_KEY", "AUDIT_APP_CLIENT_ID", "create-github-app-token", "AUDIT_TOKEN"):
        assert name not in issues, name
    assert "doppler" not in issues.lower() and "id-token" not in issues
    env = next(s for s in steps("register-issues") if "gh issue" in s.get("run", ""))["env"]
    assert env["GH_TOKEN"] == "${{ github.token }}"
    assert env["GH_REPO"] == "${{ github.repository }}"
    assert text.count("AUDIT_APP_PRIVATE_KEY") >= 3  # the header, and a mint step per owner


def test_the_issue_job_dedupes_on_the_title_and_asks_the_script_for_the_entries():
    run = next(s["run"] for s in steps("register-issues") if "gh issue" in s.get("run", ""))
    assert "scripts/audit_baseline.py --expiring" in run
    assert 'title="Risk register: $id expires $date"' in run
    assert "gh issue list" in run and "gh issue create" in run
