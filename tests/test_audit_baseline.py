"""The audit script is a check on ten repositories; this is the check on it.

Every API answer is a fixture here, so the suite is offline. Each criterion
gets a passing fixture and a broken one, and the broken one must come back
FAIL with a message naming the fix. A 403 must come back UNKNOWN, not PASS:
the proxy in a cloud session refuses the Actions endpoints, and an audit that
read that refusal as "fine" would be worse than none.
"""

from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "audit_baseline.py"

spec = importlib.util.spec_from_file_location("audit_baseline", SCRIPT)
audit = importlib.util.module_from_spec(spec)
sys.modules["audit_baseline"] = audit
spec.loader.exec_module(audit)

OWNER = "ChiefGyk3D"
REPO_NAME = f"{OWNER}/example"

PIN = "d5d9556afeeb06f78419b91ecb5d146e789c6d51"
SHARED = "ChiefGyk3D/git-your-ship-together/.github/workflows/"
CALLER = (
    "name: CI\non: [push]\npermissions:\n  contents: read\njobs:\n  ci:\n"
    f"    uses: {SHARED}python-ci.yml@{PIN} # v1.0.0\n"
    "    secrets:\n      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}\n"
)


def encoded(text: str) -> dict:
    return {"content": base64.b64encode(text.encode()).decode(), "encoding": "base64"}


def good_answers() -> dict[str, tuple[int, dict | list]]:
    """Every endpoint answering the way BASELINE.md wants."""
    r = f"/repos/{REPO_NAME}"
    return {
        r: (
            200,
            {
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                    "dependabot_security_updates": {"status": "enabled"},
                },
            },
        ),
        f"{r}/collaborators?affiliation=all&per_page=100": (
            200,
            [
                {"login": OWNER, "role_name": "admin", "permissions": {"admin": True, "push": True, "pull": True}},
            ],
        ),
        f"{r}/branches/main/protection": (
            200,
            {
                "required_status_checks": {"strict": False, "checks": [{"context": "ci / CI green"}]},
                "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
            },
        ),
        f"{r}/private-vulnerability-reporting": (200, {"enabled": True}),
        f"{r}/actions/permissions/workflow": (
            200,
            {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
        ),
        f"{r}/actions/permissions/fork-pr-contributor-approval": (
            200,
            {"approval_policy": "all_external_contributors"},
        ),
        f"{r}/contents/.github/workflows": (200, [{"name": "ci.yml"}, {"name": "README.md"}]),
        f"{r}/contents/.github/workflows/ci.yml": (200, encoded(CALLER)),
        f"{r}/contents/.github/dependabot.yml": (
            200,
            encoded("version: 2\nupdates:\n  - package-ecosystem: pip\n    cooldown:\n      default-days: 7\n"),
        ),
        f"{r}/actions/variables/DOPPLER_IDENTITY_ID": (
            200,
            {"name": "DOPPLER_IDENTITY_ID", "value": "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"},
        ),
    }


def fetcher(answers: dict) -> audit.Fetcher:
    def fetch(path: str):
        if path not in answers:
            raise AssertionError(f"unexpected API call {path}")
        return answers[path]

    return fetch


def by_check(results: list) -> dict[str, tuple[str, str]]:
    return {r.check: (r.status, r.detail) for r in results}


def test_a_compliant_repository_passes_every_check():
    results = by_check(audit.audit_repo(REPO_NAME, fetcher(good_answers())))
    failing = {k: v for k, v in results.items() if v[0] != audit.PASS}
    assert not failing, failing
    assert set(results) == {
        "collaborators",
        "required-check",
        "pull-request-required",
        "history-protected",
        "secret-scanning",
        "push-protection",
        "dependabot-security-updates",
        "private-vulnerability-reporting",
        "workflow-token-read-only",
        "fork-pr-approval",
        "workflows-pinned",
        "uses-shared-workflows",
        "dependabot-config",
        "doppler-identity",
    }


def test_a_second_writer_fails_and_is_named():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/collaborators?affiliation=all&per_page=100"] = (
        200,
        [
            {"login": OWNER, "permissions": {"push": True}},
            {"login": "someone-else", "permissions": {"push": True}},
            {"login": "reader", "permissions": {"push": False, "pull": True}},
        ],
    )
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["collaborators"]
    assert status == audit.FAIL and "someone-else" in detail and "reader" not in detail


def test_an_unprotected_default_branch_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/branches/main/protection"] = (404, {"message": "Branch not protected"})
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["branch-protection"]
    assert status == audit.FAIL and "not protected" in detail


def test_the_old_check_names_fail_and_the_expected_name_is_stated():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/branches/main/protection"][1]["required_status_checks"] = {
        "checks": [{"context": "Test Python 3.14"}, {"context": "Snyk Security Scan"}]
    }
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["required-check"]
    assert status == audit.FAIL and "ci / CI green" in detail


def test_stale_approvals_and_force_pushes_fail():
    answers = good_answers()
    prot = answers[f"/repos/{REPO_NAME}/branches/main/protection"][1]
    prot["required_pull_request_reviews"]["dismiss_stale_reviews"] = False
    prot["allow_force_pushes"]["enabled"] = True
    results = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))
    assert results["pull-request-required"][0] == audit.FAIL
    assert results["history-protected"][0] == audit.FAIL and "force pushes allowed" in results["history-protected"][1]


def test_a_disabled_security_feature_fails_by_name():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}"][1]["security_and_analysis"]["secret_scanning_push_protection"] = {
        "status": "disabled"
    }
    results = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))
    assert results["push-protection"][0] == audit.FAIL
    assert results["secret-scanning"][0] == audit.PASS


def test_a_proxy_refusal_is_unknown_not_pass():
    answers = good_answers()
    refused = (403, {"message": "Access to this GitHub Actions path is not permitted through this proxy."})
    answers[f"/repos/{REPO_NAME}/actions/permissions/workflow"] = refused
    answers[f"/repos/{REPO_NAME}/actions/permissions/fork-pr-contributor-approval"] = refused
    answers[f"/repos/{REPO_NAME}/actions/variables/DOPPLER_IDENTITY_ID"] = refused
    results = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))
    for check in ("workflow-token-read-only", "fork-pr-approval", "doppler-identity"):
        assert results[check][0] == audit.UNKNOWN and "403" in results[check][1], check


def test_a_writable_default_token_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/actions/permissions/workflow"] = (
        200,
        {"default_workflow_permissions": "write", "can_approve_pull_request_reviews": True},
    )
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["workflow-token-read-only"]
    assert status == audit.FAIL and "write" in detail


def test_first_time_contributor_policy_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/actions/permissions/fork-pr-contributor-approval"] = (
        200,
        {"approval_policy": "first_time_contributors"},
    )
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["fork-pr-approval"]
    assert status == audit.FAIL and "all_external_contributors" in detail


@pytest.mark.parametrize(
    "bad, expect",
    [
        ("    uses: actions/checkout@v4\n", "not a commit SHA"),
        (
            f"    uses: {SHARED}security.yml@{PIN}\n",
            "no `# vX.Y.Z` comment",
        ),
        ("    secrets: inherit\n", "secrets: inherit"),
    ],
    ids=["tag-pin", "shared-workflow-without-version-comment", "secrets-inherit"],
)
def test_a_forbidden_workflow_line_fails_with_its_location(bad, expect):
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.github/workflows/ci.yml"] = (200, encoded(CALLER + "  extra:\n" + bad))
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["workflows-pinned"]
    assert status == audit.FAIL and expect in detail and "ci.yml:" in detail


def test_a_commented_out_line_is_not_a_finding():
    assert audit.workflow_findings("x.yml", "# uses: actions/checkout@v4\n#   secrets: inherit\n") == []


def test_local_and_self_repository_references_need_no_pin():
    text = "    uses: ./.github/workflows/security.yml\n    uses: $/.github/actions/x\n"
    assert audit.workflow_findings("x.yml", text) == []


def test_a_repository_that_does_not_call_the_shared_workflows_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.github/workflows/ci.yml"] = (200, encoded("name: x\non: [push]\njobs: {}\n"))
    status, _ = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["uses-shared-workflows"]
    assert status == audit.FAIL


def test_dependabot_without_cooldown_fails_and_missing_file_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"] = (200, encoded("version: 2\nupdates: []\n"))
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.FAIL
    answers[f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"] = (404, {"message": "Not Found"})
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.FAIL


def test_a_missing_identity_variable_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/actions/variables/DOPPLER_IDENTITY_ID"] = (404, {"message": "Not Found"})
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["doppler-identity"]
    assert status == audit.FAIL and "DOPPLER_IDENTITY_ID" in detail


def test_exit_codes_distinguish_fail_from_unknown():
    R = audit.Result
    ok = [R("r", "a", audit.PASS, "")]
    unknown = ok + [R("r", "b", audit.UNKNOWN, "")]
    fail = unknown + [R("r", "c", audit.FAIL, "")]
    assert audit.exit_code(ok, allow_unknown=False) == 0
    assert audit.exit_code(unknown, allow_unknown=False) == 2
    assert audit.exit_code(unknown, allow_unknown=True) == 0
    assert audit.exit_code(fail, allow_unknown=True) == 1


def test_the_repo_list_lists_this_repository_and_ignores_comments():
    repos = audit.read_repo_list(REPO / "baseline" / "repos.txt")
    assert "ChiefGyk3D/git-your-ship-together" in repos
    assert all("/" in r and not r.startswith("#") for r in repos)
    assert len(repos) == len(set(repos))


def test_the_shared_repository_requires_its_own_gate_name():
    """git-your-ship-together runs python-ci's gate directly, so its check is `CI green`, not `ci / CI green`."""
    shared = "ChiefGyk3D/git-your-ship-together"
    answers = {k.replace(REPO_NAME, shared): v for k, v in good_answers().items()}
    answers[f"/repos/{shared}/branches/main/protection"][1]["required_status_checks"] = {
        "checks": [{"context": "CI green"}]
    }
    answers[f"/repos/{shared}/contents/.github/workflows/ci.yml"] = (200, encoded("name: x\non: [push]\njobs: {}\n"))
    results = by_check(audit.audit_repo(shared, fetcher(answers)))
    assert results["required-check"][0] == audit.PASS
    assert results["uses-shared-workflows"][0] == audit.PASS
    # and a caller is not allowed to borrow that name
    caller = good_answers()
    caller[f"/repos/{REPO_NAME}/branches/main/protection"][1]["required_status_checks"] = {
        "checks": [{"context": "CI green"}]
    }
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(caller)))["required-check"][0] == audit.FAIL
