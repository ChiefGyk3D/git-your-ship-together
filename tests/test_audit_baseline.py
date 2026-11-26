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
import json
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
    "    with:\n      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}\n"
)

# A caller that never reads Doppler: no identity input, no token secret.
CALLER_WITHOUT_DOPPLER = (
    "name: CI\non: [push]\npermissions:\n  contents: read\njobs:\n  ci:\n"
    f"    uses: {SHARED}python-ci.yml@{PIN} # v1.0.0\n"
)


def encoded(text: str) -> dict:
    return {"content": base64.b64encode(text.encode()).decode(), "encoding": "base64"}


def dep_file(text: str | bytes, **overrides) -> dict:
    """The Contents API answer for .github/dependabot.yml: a regular base64 file, whole."""
    raw = text.encode() if isinstance(text, str) else text
    body = {
        "type": "file",
        "path": ".github/dependabot.yml",
        "encoding": "base64",
        "size": len(raw),
        "content": base64.b64encode(raw).decode(),
    }
    return {**body, **overrides}


def wrapped(text: str) -> dict:
    """The contents API as GitHub sends it: base64 wrapped at 60 columns with newlines in it."""
    content = base64.encodebytes(text.encode()).decode()
    assert "\n" in content.rstrip("\n"), "the fixture must be long enough to wrap, or it proves nothing"
    return {"content": content, "encoding": "base64"}


def good_answers() -> dict[str, tuple[int, dict | list]]:
    """Every endpoint answering the way BASELINE.md wants."""
    r = f"/repos/{REPO_NAME}"
    return {
        r: (
            200,
            {
                "default_branch": "main",
                "allow_auto_merge": True,
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
        f"{r}/actions/permissions": (200, {"enabled": True, "allowed_actions": "selected"}),
        f"{r}/actions/permissions/selected-actions": (
            200,
            {
                "github_owned_allowed": True,
                "verified_allowed": False,
                "patterns_allowed": ["step-security/harden-runner@*", "dopplerhq/secrets-fetch-action@*"],
            },
        ),
        f"{r}/contents/.github/workflows": (200, [{"name": "ci.yml"}, {"name": "README.md"}]),
        f"{r}/contents/.github/workflows/ci.yml": (200, encoded(CALLER)),
        f"{r}/contents/.github/dependabot.yml": (
            200,
            dep_file(
                "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /\n"
                "    cooldown:\n      default-days: 7\n"
            ),
        ),
        f"{r}/contents/.githooks/pre-commit": (
            200,
            wrapped((REPO / ".githooks" / "pre-commit").read_text()),
        ),
        f"{r}/contents/requirements.txt": (404, {"message": "Not Found"}),
        f"{r}/contents/requirements-dev.txt": (404, {"message": "Not Found"}),
        f"{r}/rulesets": (200, [{"id": 7, "target": "tag", "enforcement": "active"}]),
        f"{r}/rulesets/7": (
            200,
            {
                "target": "tag",
                "enforcement": "active",
                "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
                "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}],
            },
        ),
        f"{r}/actions/variables/DOPPLER_IDENTITY_ID": (
            200,
            {"name": "DOPPLER_IDENTITY_ID", "value": "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"},
        ),
    }


def completed(path: str, body):
    """A file answer the way the Contents API sends it: fixtures that give only `content` get type, path and size.

    An answer that names any of those keys itself is left exactly as written, so a hostile fixture stays hostile.
    """
    if (
        isinstance(body, dict)
        and type(body.get("content")) is str
        and not {"type", "path", "size"} & set(body)
        and "/contents/" in path
    ):
        try:
            size = len(base64.b64decode(body["content"].replace("\n", ""), validate=True))
        except ValueError:
            return body
        return {**body, "type": "file", "path": path.split("/contents/", 1)[1], "size": size}
    return body


def fetcher(answers: dict) -> audit.Fetcher:
    def fetch(path: str):
        if path not in answers:
            raise AssertionError(f"unexpected API call {path}")
        code, body = answers[path]
        return code, completed(path, body)

    return fetch


def raw_fetcher(answers: dict) -> audit.Fetcher:
    """Answers exactly as given, for a fixture that must stay hostile (a missing key stays missing)."""
    return lambda path: answers[path]


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
        "actions-allowlist",
        "workflows-pinned",
        "uses-shared-workflows",
        "risk-exceptions",
        "dependabot-config",
        "dependabot-ecosystem",
        "doppler-identity",
        "pre-commit-hook",
        "auto-merge-enabled",
        "tag-ruleset",
    }


def test_a_missing_or_different_pre_commit_hook_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.githooks/pre-commit"] = (404, {"message": "Not Found"})
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["pre-commit-hook"]
    assert status == audit.FAIL and ".githooks/pre-commit" in detail

    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.githooks/pre-commit"] = (200, encoded("#!/bin/sh\n"))
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["pre-commit-hook"]
    assert status == audit.FAIL and "does not match" in detail


def test_an_unreadable_pre_commit_hook_is_unknown_not_pass():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.githooks/pre-commit"] = (
        403,
        {"message": "Resource not accessible by integration"},
    )
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["pre-commit-hook"]
    assert status == audit.UNKNOWN and "403" in detail


def test_auto_merge_disabled_fails():
    answers = good_answers()
    body = dict(answers[f"/repos/{REPO_NAME}"][1])
    body["allow_auto_merge"] = False
    answers[f"/repos/{REPO_NAME}"] = (200, body)
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["auto-merge-enabled"]
    assert status == audit.FAIL and "disabled" in detail


def test_no_tag_ruleset_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/rulesets"] = (200, [])
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["tag-ruleset"]
    assert status == audit.FAIL and "refs/tags/v*" in detail


def test_a_tag_ruleset_that_still_allows_moving_a_tag_fails():
    """Deletion alone is not the hazard; a tag moved onto another commit is."""
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/rulesets/7"] = (
        200,
        {
            "target": "tag",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [{"type": "deletion"}],
        },
    )
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["tag-ruleset"]
    assert status == audit.FAIL and "update" in detail and "non_fast_forward" in detail


def test_a_disabled_tag_ruleset_does_not_count():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/rulesets"] = (200, [{"id": 7, "target": "tag", "enforcement": "disabled"}])
    status, _ = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["tag-ruleset"]
    assert status == audit.FAIL


def test_a_refused_ruleset_listing_is_unknown_not_pass():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/rulesets"] = (403, {"message": "Resource not accessible by integration"})
    status, _ = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["tag-ruleset"]
    assert status == audit.UNKNOWN


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
    answers[f"/repos/{REPO_NAME}/actions/permissions"] = refused
    answers[f"/repos/{REPO_NAME}/actions/variables/DOPPLER_IDENTITY_ID"] = refused
    results = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))
    for check in ("workflow-token-read-only", "fork-pr-approval", "actions-allowlist", "doppler-identity"):
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


def test_allowing_all_actions_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/actions/permissions"] = (200, {"enabled": True, "allowed_actions": "all"})
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["actions-allowlist"]
    assert status == audit.FAIL and "all" in detail


def test_allowing_marketplace_verified_creators_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/actions/permissions/selected-actions"] = (
        200,
        {"github_owned_allowed": True, "verified_allowed": True, "patterns_allowed": ["step-security/harden-runner@*"]},
    )
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["actions-allowlist"]
    assert status == audit.FAIL and "verified" in detail


def test_an_empty_pattern_list_fails():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/actions/permissions/selected-actions"] = (
        200,
        {"github_owned_allowed": True, "verified_allowed": False, "patterns_allowed": []},
    )
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["actions-allowlist"]
    assert status == audit.FAIL and "pattern" in detail


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
    answers[f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"] = (200, dep_file("version: 2\nupdates: []\n"))
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.FAIL
    answers[f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"] = (404, {"message": "Not Found"})
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.FAIL


UV_LOCK = (
    "# This file was autogenerated by uv via the following command:\n"
    "#    uv pip compile requirements.in --universal --generate-hashes --python-version 3.10 -o requirements.txt\n"
    "requests==2.0 \\\n    --hash=sha256:abc\n"
)
PLAIN_LOCK = "# This file was autogenerated by uv via the following command:\n#    uv pip compile requirements.in\n"


def ecosystem_answers(ecosystem: str | None, lock: str | None) -> dict:
    answers = good_answers()
    path = f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"
    if ecosystem is None:
        answers[path] = (404, {"message": "Not Found"})
    else:
        text = (
            f"version: 2\nupdates:\n  - package-ecosystem: {ecosystem}\n    directory: /\n"
            "    cooldown:\n      default-days: 7\n"
        )
        answers[path] = (200, encoded(text))
    if lock is not None:
        answers[f"/repos/{REPO_NAME}/contents/requirements.txt"] = (200, encoded(lock))
    return answers


def ecosystem_check(answers: dict) -> tuple[str, str]:
    return by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-ecosystem"]


def test_a_uv_universal_lock_updated_by_the_uv_ecosystem_passes():
    assert ecosystem_check(ecosystem_answers("uv", UV_LOCK))[0] == audit.PASS


def test_a_uv_universal_lock_updated_by_the_pip_ecosystem_fails_naming_the_lock():
    status, detail = ecosystem_check(ecosystem_answers("pip", UV_LOCK))
    assert status == audit.FAIL and "requirements.txt" in detail and "uv ecosystem is required" in detail


def test_the_pip_ecosystem_is_fine_for_a_lock_that_is_not_uv_universal():
    assert ecosystem_check(ecosystem_answers("pip", PLAIN_LOCK))[0] == audit.PASS
    assert ecosystem_check(ecosystem_answers("pip", "requests==2.0\n"))[0] == audit.PASS


def test_a_quoted_pip_ecosystem_and_root_directory_are_still_caught():
    answers = ecosystem_answers("pip", UV_LOCK)
    text = "version: 2\nupdates:\n  - directory: '/'\n    package-ecosystem: \"pip\"\n"
    answers[f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"] = (200, encoded(text))
    assert ecosystem_check(answers)[0] == audit.FAIL


def test_a_pip_entry_for_another_directory_does_not_count():
    answers = ecosystem_answers("pip", UV_LOCK)
    text = "version: 2\nupdates:\n  - package-ecosystem: pip\n    directory: /docs\n"
    answers[f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"] = (200, encoded(text))
    assert ecosystem_check(answers)[0] == audit.PASS


def test_a_uv_universal_lock_with_no_dependabot_yml_fails_and_without_a_lock_passes():
    status, detail = ecosystem_check(ecosystem_answers(None, UV_LOCK))
    assert status == audit.FAIL and "requirements.txt" in detail
    assert ecosystem_check(ecosystem_answers(None, None))[0] == audit.PASS


def test_a_refused_read_of_the_lock_or_dependabot_yml_is_unknown_not_pass():
    refused = (403, {"message": "Resource not accessible by integration"})
    answers = ecosystem_answers("pip", UV_LOCK)
    answers[f"/repos/{REPO_NAME}/contents/requirements-dev.txt"] = refused
    status, detail = ecosystem_check(answers)
    assert status == audit.UNKNOWN and "403" in detail
    answers = ecosystem_answers("pip", UV_LOCK)
    answers[f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"] = refused
    status, detail = ecosystem_check(answers)
    assert status == audit.UNKNOWN and "403" in detail


def test_a_repository_that_reads_no_doppler_needs_no_identity():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.github/workflows/ci.yml"] = (200, encoded(CALLER_WITHOUT_DOPPLER))
    # The variable endpoint is not consulted at all: the fetcher raises on it.
    del answers[f"/repos/{REPO_NAME}/actions/variables/DOPPLER_IDENTITY_ID"]
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["doppler-identity"]
    assert status == audit.PASS and "no workflow reads" in detail


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


CALLER_TWO_LANGUAGES = CALLER + f"  shell:\n    uses: {SHARED}bash-ci.yml@{PIN} # v1.0.0\n"
RELEASE_ONLY = (
    "name: Release\non: [push]\npermissions:\n  contents: read\njobs:\n  container:\n"
    f"    uses: {SHARED}python-docker-release.yml@{PIN} # v1.0.0\n"
)


def test_expected_gates_are_one_per_shared_ci_call():
    """Every caller job that uses a `*-ci.yml` here reports `<job> / CI green`; nothing else does."""
    assert audit.expected_gates(CALLER) == {"ci / CI green"}
    assert audit.expected_gates(CALLER_TWO_LANGUAGES) == {"ci / CI green", "shell / CI green"}
    assert audit.expected_gates(RELEASE_ONLY) == set()
    assert audit.expected_gates("# uses: " + SHARED + "python-ci.yml@" + PIN + "\n") == set()


def test_every_language_gate_must_be_required():
    """A second language's gate left out of branch protection merges red; the audit names it."""
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.github/workflows/ci.yml"] = (200, encoded(CALLER_TWO_LANGUAGES))
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["required-check"]
    assert status == audit.FAIL and "shell / CI green" in detail and "ci / CI green" not in detail.split("missing")[1]
    answers[f"/repos/{REPO_NAME}/branches/main/protection"][1]["required_status_checks"] = {
        "checks": [{"context": "ci / CI green"}, {"context": "shell / CI green"}]
    }
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["required-check"]
    assert status == audit.PASS and "shell / CI green" in detail


def test_a_caller_with_no_shared_ci_call_is_held_to_the_default_gate():
    """The expected name must still be stated when there is nothing to derive it from."""
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.github/workflows/ci.yml"] = (200, encoded(RELEASE_ONLY))
    results = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))
    assert results["required-check"][0] == audit.PASS  # good_answers requires `ci / CI green`
    answers[f"/repos/{REPO_NAME}/branches/main/protection"][1]["required_status_checks"] = {"checks": []}
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["required-check"]
    assert status == audit.FAIL and "ci / CI green" in detail


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


# --- risk exceptions --------------------------------------------------------

SECURITY_CALLER = (
    "name: Security\non: [pull_request]\npermissions:\n  contents: read\njobs:\n  security:\n"
    f"    uses: {SHARED}security.yml@{PIN} # v1.0.0\n"
    "    with:\n"
    "      # nltk has no fixed release yet (see the register)\n"
    "      pip-audit-extra-args: --ignore-vuln PYSEC-2026-3740\n"
    "      dependency-review-allow-ghsas: GHSA-8mgp-746c-j5xp, GHSA-aaaa-bbbb-cccc\n"
)

TODAY = audit.dt.date(2026, 9, 21)
REGISTER = [
    {
        "id": "GHSA-8mgp-746c-j5xp",
        "aliases": ["PYSEC-2026-3740"],
        "repos": [REPO_NAME],
        "review_by": audit.dt.date(2026, 12, 20),
    },
    {"id": "GHSA-aaaa-bbbb-cccc", "repos": [REPO_NAME], "review_by": audit.dt.date(2026, 12, 20)},
]


def test_exceptions_are_read_from_both_inputs_and_not_from_comments():
    text = SECURITY_CALLER + "      # --ignore-vuln PYSEC-0000-1 is only mentioned here\n"
    assert audit.exceptions_in(text) == {"PYSEC-2026-3740", "GHSA-8mgp-746c-j5xp", "GHSA-aaaa-bbbb-cccc"}


def test_an_input_description_is_not_an_exception():
    """The shared security.yml documents the inputs with example IDs; those are prose, not exceptions."""
    text = (
        "on:\n  workflow_call:\n    inputs:\n      pip-audit-extra-args:\n"
        "        description: Extra pip-audit arguments, e.g. `--ignore-vuln PYSEC-2026-3740`"
        " for an advisory with no fix yet.\n"
        '        default: ""\n      dependency-review-allow-ghsas:\n'
        "        description: Comma-separated GitHub Advisory IDs the review may not fail on.\n"
        '        type: string\n        default: ""\n'
    )
    assert audit.exceptions_in(text) == set()


def test_the_rescan_input_is_read_as_an_exception_and_its_own_declaration_is_not():
    caller = (
        "      with:\n        image: ghcr.io/o/i:1\n"
        "        rescan-ignore-advisories: CVE-2026-12345, GHSA-aaaa-bbbb-cccc\n"
    )
    assert audit.exceptions_in(caller) == {"CVE-2026-12345", "GHSA-aaaa-bbbb-cccc"}
    shared = (REPO / ".github" / "workflows" / "verify-published.yml").read_text()
    assert audit.exceptions_in(shared) == set()
    result = audit.check_risk_exceptions(REPO_NAME, {"CVE-2026-12345"}, REGISTER, today=TODAY)
    assert result.status == audit.FAIL and "not in baseline/risk-register.yaml" in result.detail


def test_registered_unexpired_exceptions_pass():
    ids = audit.exceptions_in(SECURITY_CALLER)
    result = audit.check_risk_exceptions(REPO_NAME, ids, REGISTER, today=TODAY)
    assert result.status == audit.PASS, result


def test_an_unregistered_exception_fails_by_id():
    ids = {"GHSA-zzzz-yyyy-xxxx"}
    result = audit.check_risk_exceptions(REPO_NAME, ids, REGISTER, today=TODAY)
    assert result.status == audit.FAIL
    assert "GHSA-zzzz-yyyy-xxxx" in result.detail and "risk-register" in result.detail


def test_an_exception_registered_for_another_repository_fails():
    result = audit.check_risk_exceptions("ChiefGyk3D/other", {"PYSEC-2026-3740"}, REGISTER, today=TODAY)
    assert result.status == audit.FAIL
    assert "not for ChiefGyk3D/other" in result.detail


def test_an_expired_exception_fails_and_says_so():
    late = audit.dt.date(2027, 1, 1)
    result = audit.check_risk_exceptions(REPO_NAME, {"PYSEC-2026-3740"}, REGISTER, today=late)
    assert result.status == audit.FAIL
    assert "has passed" in result.detail


def test_no_exceptions_is_a_pass():
    assert audit.check_risk_exceptions(REPO_NAME, set(), [], today=TODAY).status == audit.PASS


def test_the_audit_reads_exceptions_out_of_the_security_workflow():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.github/workflows"] = (
        200,
        [{"name": "ci.yml"}, {"name": "security.yml"}],
    )
    answers[f"/repos/{REPO_NAME}/contents/.github/workflows/security.yml"] = (200, encoded(SECURITY_CALLER))
    results = by_check(audit.audit_repo(REPO_NAME, fetcher(answers), register=[]))
    status, detail = results["risk-exceptions"]
    assert status == audit.FAIL and "GHSA-8mgp-746c-j5xp" in detail


def test_the_shipped_register_parses_as_the_audit_reads_it():
    """The real file parses, and every entry carries the fields the audit looks at.

    This deliberately names no advisory: an entry is closed the day its fix
    ships, and a test pinned to one would fail for the good outcome.
    """
    register = audit.load_register()
    assert isinstance(register, list)
    for entry in register:
        assert entry.get("id"), f"an entry has no id: {entry}"
        assert entry.get("repos"), f"{entry.get('id')}: no repos"
        assert entry.get("review_by"), f"{entry.get('id')}: no review_by"


# --- expiring register entries ----------------------------------------------

D = audit.dt.date
EXPIRY_REGISTER = [
    {"id": "GHSA-late", "repos": [REPO_NAME], "review_by": D(2026, 12, 1)},
    {"id": "GHSA-soon", "repos": [REPO_NAME, "ChiefGyk3D/other"], "review_by": D(2026, 9, 30)},
    {"id": "GHSA-past", "repos": [REPO_NAME], "review_by": D(2026, 9, 1)},
    {"id": "GHSA-edge", "repos": [REPO_NAME], "review_by": D(2026, 10, 5)},
    {"id": "GHSA-nodate", "repos": [REPO_NAME]},
]


def test_expiring_entries_are_those_within_the_window_or_past():
    due = audit.expiring_entries(EXPIRY_REGISTER, 14, TODAY)
    assert [e["id"] for e in due] == ["GHSA-past", "GHSA-soon", "GHSA-edge", "GHSA-nodate"]
    assert [e["days_left"] for e in due] == [-20, 9, 14, None]


def test_the_window_edge_is_inclusive_and_an_empty_register_has_nothing_due():
    assert [e["id"] for e in audit.expiring_entries(EXPIRY_REGISTER, 13, TODAY)] == [
        "GHSA-past",
        "GHSA-soon",
        "GHSA-nodate",
    ]
    assert audit.expiring_entries([], 90, TODAY) == []


def test_expiring_lines_are_one_tab_separated_record_per_entry():
    lines = audit.format_expiring(audit.expiring_entries(EXPIRY_REGISTER, 14, TODAY))
    assert lines[1] == "EXPIRING\tGHSA-soon\t2026-09-30\t9\tChiefGyk3D/example,ChiefGyk3D/other"
    assert lines[3] == f"EXPIRING\tGHSA-nodate\tunknown\tunknown\t{REPO_NAME}"
    assert all(line.count("\t") == 4 for line in lines)


def test_the_expiring_flag_needs_no_token_and_prints_nothing_for_an_empty_register(monkeypatch, capsys):
    monkeypatch.setattr(audit, "load_register", lambda: [])
    monkeypatch.setattr(audit, "find_token", lambda: pytest.fail("--expiring must not read a token"))
    assert audit.main(["--expiring", "30"]) == 0
    assert capsys.readouterr().out == ""


def test_the_expiring_flag_counts_from_the_date_it_is_given(monkeypatch, capsys):
    monkeypatch.setattr(audit, "load_register", lambda: EXPIRY_REGISTER)
    assert audit.main(["--expiring", "0", "--today", "2026-09-30"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert [line.split("\t")[1] for line in out] == ["GHSA-past", "GHSA-soon", "GHSA-nodate"]


def test_a_prefixed_identity_variable_does_not_count_as_the_shared_one():
    """audit.yml reads AUDIT_DOPPLER_IDENTITY_ID; only vars.DOPPLER_IDENTITY_ID means the shared identity."""
    import re

    pattern = re.compile(r"(?<![A-Z_])DOPPLER_IDENTITY_ID")
    assert pattern.search("doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}")
    assert not pattern.search("identity: ${{ vars.AUDIT_DOPPLER_IDENTITY_ID }}")


# --- organizations (#95, #98) -------------------------------------------------

ORG = "Example-Org"
ORG_REPO = f"{ORG}/example"
ORG_OWNER = "the-owner"


def org_answers() -> dict[str, tuple[int, dict | list]]:
    """A compliant repository under an organization: the owner reaches it through membership only."""
    r = f"/repos/{ORG_REPO}"
    answers = {path.replace(REPO_NAME, ORG_REPO): value for path, value in good_answers().items()}
    answers[r] = (200, {**answers[r][1], "owner": {"login": ORG, "type": "Organization"}})
    del answers[f"{r}/collaborators?affiliation=all&per_page=100"]
    answers[f"{r}/collaborators?affiliation=direct&per_page=100"] = (200, [])
    answers[f"{r}/collaborators?affiliation=outside&per_page=100"] = (200, [])
    answers[f"/orgs/{ORG}/members?role=admin&per_page=100"] = (200, [{"login": ORG_OWNER}])
    return answers


def org_posture() -> dict[str, tuple[int, dict | list]]:
    """The organization endpoints, answering the way BASELINE.md "Organizations" wants."""
    return {
        f"/orgs/{ORG}": (
            200,
            {
                "login": ORG,
                "two_factor_requirement_enabled": True,
                **{k: True for k in audit.NEW_REPO_DEFAULTS},
            },
        ),
        f"/orgs/{ORG}/actions/permissions": (200, {"enabled_repositories": "all", "allowed_actions": "selected"}),
        f"/orgs/{ORG}/actions/permissions/workflow": (
            200,
            {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False},
        ),
        f"/orgs/{ORG}/members?role=admin&per_page=100": (200, [{"login": ORG_OWNER}]),
    }


def run_org(answers, repos=(ORG_REPO,)):
    """audit_repo for each repository, then audit_org once, the way main() does."""
    orgs: dict[str, dict] = {}
    repo_results = []
    for repo in repos:
        repo_results += audit.audit_repo(repo, fetcher(answers), orgs=orgs)
    return repo_results, audit.audit_org(ORG, fetcher(answers), orgs[ORG], repo_results)


def test_an_organization_owner_with_no_direct_grant_is_not_an_outsider():
    """#95: under an organization the owner login is the organization, and its owners are members."""
    repo_results, _ = run_org({**org_answers(), **org_posture()})
    status, detail = by_check(repo_results)["collaborators"]
    assert status == audit.PASS and ORG_OWNER in detail


def test_an_organization_owner_who_is_also_a_direct_collaborator_is_still_the_owner():
    answers = {**org_answers(), **org_posture()}
    answers[f"/repos/{ORG_REPO}/collaborators?affiliation=direct&per_page=100"] = (
        200,
        [{"login": ORG_OWNER, "permissions": {"push": True, "admin": True}}],
    )
    assert by_check(run_org(answers)[0])["collaborators"][0] == audit.PASS


def test_a_real_outside_collaborator_with_write_still_fails_under_an_organization():
    answers = {**org_answers(), **org_posture()}
    answers[f"/repos/{ORG_REPO}/collaborators?affiliation=outside&per_page=100"] = (
        200,
        [{"login": "contractor", "permissions": {"push": True}}, {"login": "viewer", "permissions": {"push": False}}],
    )
    status, detail = by_check(run_org(answers)[0])["collaborators"]
    assert status == audit.FAIL and "contractor" in detail and "viewer" not in detail
    assert ORG_OWNER not in detail


def test_a_direct_collaborator_who_is_not_an_owner_fails_under_an_organization():
    answers = {**org_answers(), **org_posture()}
    answers[f"/repos/{ORG_REPO}/collaborators?affiliation=direct&per_page=100"] = (
        200,
        [{"login": "member", "permissions": {"push": True}}],
    )
    status, detail = by_check(run_org(answers)[0])["collaborators"]
    assert status == audit.FAIL and "member" in detail


def test_unreadable_owners_make_the_collaborators_check_unknown_naming_the_permission():
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}/members?role=admin&per_page=100"] = (403, {"message": "Resource not accessible"})
    status, detail = by_check(run_org(answers)[0])["collaborators"]
    assert status == audit.UNKNOWN and "Organization Members: read" in detail


def test_the_owner_list_is_read_once_per_organization():
    answers = {**org_answers(), **org_posture()}
    second = "Example-Org/second"
    for path, value in list(org_answers().items()):
        answers[path.replace(ORG_REPO, second)] = value
    calls = []
    inner = fetcher(answers)

    def counting(path):
        calls.append(path)
        return inner(path)

    orgs: dict[str, dict] = {}
    for repo in (ORG_REPO, second):
        audit.audit_repo(repo, counting, orgs=orgs)
    audit.audit_org(ORG, counting, orgs[ORG], [])
    assert calls.count(f"/orgs/{ORG}/members?role=admin&per_page=100") == 1


def test_a_user_owned_repository_has_no_organization_and_unchanged_collaborator_calls():
    orgs: dict[str, dict] = {}
    audit.audit_repo(REPO_NAME, fetcher(good_answers()), orgs=orgs)
    assert orgs == {}


def test_a_compliant_organization_passes_its_four_checks():
    _, org = run_org({**org_answers(), **org_posture()})
    assert set(by_check(org)) == {
        "org-2fa-required",
        "org-new-repo-defaults",
        "org-actions-policy",
        "org-owner-collaborators",
    }
    assert {s for s, _ in by_check(org).values()} == {audit.PASS}
    assert all(r.repo == f"{ORG} (organization)" for r in org)


def test_two_factor_off_fails():
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}"] = (200, {**answers[f"/orgs/{ORG}"][1], "two_factor_requirement_enabled": False})
    assert by_check(run_org(answers)[1])["org-2fa-required"][0] == audit.FAIL


def test_each_new_repository_default_that_is_off_fails_and_is_named():
    for key in audit.NEW_REPO_DEFAULTS:
        answers = {**org_answers(), **org_posture()}
        answers[f"/orgs/{ORG}"] = (200, {**answers[f"/orgs/{ORG}"][1], key: False})
        status, detail = by_check(run_org(answers)[1])["org-new-repo-defaults"]
        assert status == audit.FAIL and key in detail, key


def test_org_fields_the_token_is_not_sent_are_unknown_naming_the_permission_not_a_pass():
    """A token that is not the owner's gets the public organization body: no two_factor_*, no *_for_new_repositories."""
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}"] = (200, {"login": ORG, "public_repos": 3})
    org = by_check(run_org(answers)[1])
    for check in ("org-2fa-required", "org-new-repo-defaults"):
        assert org[check][0] == audit.UNKNOWN and "Organization administration: read" in org[check][1], check


def test_an_unreadable_organization_is_unknown_on_every_field_check():
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}"] = (404, {"message": "Not Found"})
    org = by_check(run_org(answers)[1])
    assert org["org-2fa-required"][0] == org["org-new-repo-defaults"][0] == audit.UNKNOWN


def test_the_org_actions_policy_is_unknown_on_a_403_naming_the_permission():
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}/actions/permissions"] = (403, {"message": "You must be an org admin"})
    status, detail = by_check(run_org(answers)[1])["org-actions-policy"]
    assert status == audit.UNKNOWN and "Organization administration: read" in detail and "HTTP 403" in detail
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}/actions/permissions/workflow"] = (403, {"message": "no"})
    assert by_check(run_org(answers)[1])["org-actions-policy"][0] == audit.UNKNOWN


def test_an_org_that_allows_local_only_or_a_write_default_token_fails():
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}/actions/permissions"] = (200, {"allowed_actions": "local_only"})
    status, detail = by_check(run_org(answers)[1])["org-actions-policy"]
    assert status == audit.FAIL and "local_only" in detail
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}/actions/permissions/workflow"] = (200, {"default_workflow_permissions": "write"})
    status, detail = by_check(run_org(answers)[1])["org-actions-policy"]
    assert status == audit.FAIL and "write" in detail


def test_an_org_that_allows_all_actions_passes_only_when_every_repository_narrows_it():
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}/actions/permissions"] = (200, {"allowed_actions": "all"})
    status, detail = by_check(run_org(answers)[1])["org-actions-policy"]
    assert status == audit.PASS and "narrows" in detail
    # one repository that does not narrow it breaks the exception
    r = f"/repos/{ORG_REPO}"
    answers[f"{r}/actions/permissions"] = (200, {"enabled": True, "allowed_actions": "all"})
    status, detail = by_check(run_org(answers)[1])["org-actions-policy"]
    assert status == audit.FAIL and "not every audited repository" in detail


def test_an_org_with_no_readable_owner_is_unknown_and_one_with_none_fails():
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}/members?role=admin&per_page=100"] = (403, {"message": "no"})
    status, detail = by_check(run_org(answers)[1])["org-owner-collaborators"]
    assert status == audit.UNKNOWN and "Organization Members: read" in detail
    answers[f"/orgs/{ORG}/members?role=admin&per_page=100"] = (200, [])
    assert by_check(run_org(answers)[1])["org-owner-collaborators"][0] == audit.FAIL


# --- one token per owner (#89) ---------------------------------------------------


def test_owner_token_pairs_are_parsed_and_malformed_ones_refused():
    assert audit.parse_owner_tokens([]) is None
    assert audit.parse_owner_tokens(["Org=A", "Me=B"]) == {"org": "A", "me": "B"}
    for bad in ("Org", "=A", "Org="):
        with pytest.raises(SystemExit):
            audit.parse_owner_tokens([bad])


def test_an_owner_with_no_or_an_empty_token_is_unknown_never_read_with_another_owners_token(monkeypatch):
    monkeypatch.setenv("TOK_ME", "token-me")
    monkeypatch.setenv("TOK_ORG", "")
    tokens = {"me": "TOK_ME", "org": "TOK_ORG"}
    assert audit.fetcher_for("Me", tokens) is not None
    assert audit.fetcher_for("Org", tokens) is None, "an empty token must not fall back to anything"
    assert audit.fetcher_for("Stranger", tokens) is None
    assert "TOK_ORG" in audit.no_token_reason("Org", tokens)
    assert "--owner-token Stranger=" in audit.no_token_reason("Stranger", tokens)


def test_main_reads_each_owner_with_its_own_token_and_audits_the_org_once(monkeypatch, capsys, tmp_path):
    """The whole run, offline: two owners, two tokens, one organization block."""
    seen: dict[str, list[str]] = {"me": [], "org": []}
    answers = {**good_answers(), **org_answers(), **org_posture()}

    def github_fetcher(token):
        inner = fetcher(answers)

        def fetch(path):
            seen[token].append(path)
            return inner(path)

        return fetch

    monkeypatch.setattr(audit, "github_fetcher", github_fetcher)
    monkeypatch.setattr(audit, "load_register", lambda: [])
    monkeypatch.setattr(audit, "find_token", lambda: pytest.fail("a per-owner run must not read a default token"))
    monkeypatch.setenv("TOK_ME", "me")
    monkeypatch.setenv("TOK_ORG", "org")
    code = audit.main([REPO_NAME, ORG_REPO, "--owner-token", f"{OWNER}=TOK_ME", "--owner-token", f"{ORG}=TOK_ORG"])
    out = capsys.readouterr().out
    assert code == 0, out
    assert all(f"/repos/{REPO_NAME}" in p or "/orgs/" not in p for p in seen["me"])
    assert not any(ORG in p for p in seen["me"]), "the user token never touches the organization"
    assert not any(REPO_NAME in p for p in seen["org"]), "the organization token never touches the user's repository"
    assert out.count(f"{ORG} (organization)") == 1 and out.count("  PASS    org-") == 4 and "0 FAIL, 0 UNKNOWN" in out
    assert "1 organization(s)" in out


def test_main_reports_a_missing_owner_token_as_unknown_and_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(audit, "github_fetcher", lambda token: fetcher({**good_answers()}))
    monkeypatch.setattr(audit, "load_register", lambda: [])
    monkeypatch.setenv("TOK_ME", "me")
    monkeypatch.delenv("TOK_ORG", raising=False)
    code = audit.main([REPO_NAME, ORG_REPO, "--owner-token", f"{OWNER}=TOK_ME", "--owner-token", f"{ORG}=TOK_ORG"])
    out = capsys.readouterr().out
    assert code == 2 and "$TOK_ORG is empty" in out


def test_an_org_that_allows_all_actions_with_no_repository_audited_does_not_pass_on_an_empty_proof():
    answers = {**org_answers(), **org_posture()}
    answers[f"/orgs/{ORG}/actions/permissions"] = (200, {"allowed_actions": "all"})
    status, _ = by_check(audit.audit_org(ORG, fetcher(answers), {}, []))["org-actions-policy"]
    assert status == audit.FAIL


# --- the Dependabot cooldown value --------------------------------------------

DEPENDABOT_PATH = f"/repos/{REPO_NAME}/contents/.github/dependabot.yml"


def cooldown_entry(ecosystem: str, cooldown: str | None) -> str:
    text = f"  - package-ecosystem: {ecosystem}\n    directory: /\n"
    return text if cooldown is None else text + f"    cooldown:\n{cooldown}"


def dependabot_check(*entries: str) -> tuple[str, str]:
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (200, dep_file("version: 2\nupdates:\n" + "".join(entries)))
    return by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"]


def test_a_cooldown_of_seven_days_or_more_on_every_ecosystem_passes():
    status, detail = dependabot_check(
        cooldown_entry("github-actions", "      default-days: 7\n"),
        cooldown_entry("npm", "      default-days: 30\n      semver-major-days: 14\n"),
        cooldown_entry("gomod", "      default-days: 7\n"),
    )
    assert status == audit.PASS, detail
    assert "7 days" in detail


def test_a_cooldown_under_seven_days_fails_and_names_the_ecosystem_and_value():
    status, detail = dependabot_check(
        cooldown_entry("github-actions", "      default-days: 7\n"),
        cooldown_entry("docker", "      default-days: 2\n"),
    )
    assert status == audit.FAIL
    assert "docker" in detail and "default-days is 2" in detail and "github-actions" not in detail


def test_one_ecosystem_without_a_cooldown_fails_even_when_another_has_one():
    status, detail = dependabot_check(cooldown_entry("pip", "      default-days: 7\n"), cooldown_entry("npm", None))
    assert status == audit.FAIL
    assert "npm" in detail and "no cooldown" in detail


def test_a_short_semver_override_or_a_missing_default_fails():
    status, detail = dependabot_check(cooldown_entry("pip", "      default-days: 7\n      semver-patch-days: 1\n"))
    assert status == audit.FAIL and "semver-patch-days is 1" in detail
    status, detail = dependabot_check(cooldown_entry("pip", "      semver-major-days: 10\n"))
    assert status == audit.FAIL and "no default-days" in detail


def test_a_cooldown_that_is_not_a_whole_number_of_days_fails():
    for value in ('"7"', "7.5", "true"):
        status, detail = dependabot_check(cooldown_entry("pip", f"      default-days: {value}\n"))
        assert status == audit.FAIL, value
        assert "whole number" in detail


def test_a_dependabot_yml_with_no_update_entries_or_unparseable_is_not_a_pass():
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (200, dep_file("version: 2\nupdates: []\n"))
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.FAIL
    answers[DEPENDABOT_PATH] = (200, dep_file("updates: [unclosed\n"))
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.UNKNOWN


def test_a_failing_cooldown_gives_exit_code_one_through_the_report_convention():
    results = audit.audit_repo(REPO_NAME, fetcher(_answers_with_cooldown(3)))
    assert audit.exit_code(results, allow_unknown=False) == 1


def _answers_with_cooldown(days: int) -> dict:
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (
        200,
        dep_file("version: 2\nupdates:\n" + cooldown_entry("pip", f"      default-days: {days}\n")),
    )
    return answers


def test_the_templates_hold_a_seven_day_cooldown_on_every_ecosystem_the_audit_reads():
    import yaml

    for name in ("dependabot-template.yml", "dependabot-gyst.yml"):
        text = (REPO / "examples" / name).read_text()
        assert audit.cooldown_problems(yaml.safe_load(text)) == [], name
    template = yaml.safe_load((REPO / "examples" / "dependabot-template.yml").read_text())
    assert {u["package-ecosystem"] for u in template["updates"]} >= {"github-actions", "pip", "docker", "npm", "gomod"}
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (200, dep_file((REPO / "examples" / "dependabot-template.yml").read_text()))
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.PASS


# --- hostile dependabot.yml files ---------------------------------------------------


def dependabot_check_text(text: str | bytes) -> tuple[str, str]:
    answers = good_answers()
    raw = text.encode() if isinstance(text, str) else text
    answers[DEPENDABOT_PATH] = (200, dep_file(raw))
    return by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"]


GOOD_ENTRY = "  - package-ecosystem: pip\n    directory: /\n    cooldown:\n      default-days: 7\n"


def test_an_alias_a_billion_laughs_document_or_an_anchor_is_unknown_not_expanded():
    laughs = "version: 2\nl0: &l0 [x, x, x, x, x, x, x, x, x, x]\n" + "".join(
        f"l{i}: &l{i} [{', '.join([f'*l{i - 1}'] * 10)}]\n" for i in range(1, 10)
    )
    assert dependabot_check_text(laughs + "updates:\n" + GOOD_ENTRY)[0] == audit.UNKNOWN
    anchored = "updates:\n  - &a\n    package-ecosystem: pip\n    cooldown:\n      default-days: 7\n"
    assert dependabot_check_text(anchored)[0] == audit.UNKNOWN
    merged = "updates:\n  - package-ecosystem: pip\n    cooldown:\n      <<: {default-days: 7}\n"
    assert dependabot_check_text(merged)[0] == audit.UNKNOWN


def test_a_duplicate_key_that_would_hide_a_short_cooldown_is_unknown():
    text = "updates:\n  - package-ecosystem: pip\n    cooldown:\n      default-days: 1\n      default-days: 7\n"
    assert dependabot_check_text(text)[0] == audit.UNKNOWN
    assert (
        dependabot_check_text("updates:\n  - package-ecosystem: pip\n    package-ecosystem: npm\n")[0] == audit.UNKNOWN
    )


def test_deep_nesting_and_an_oversized_file_are_unknown_not_a_crash():
    deep = "updates:\n  - package-ecosystem: pip\n    x: " + "[" * 5000 + "]" * 5000 + "\n"
    assert dependabot_check_text(deep)[0] == audit.UNKNOWN
    nested_map = "updates:\n  - package-ecosystem: pip\n    x:\n" + "".join(
        "  " * (3 + i) + f"k{i}:\n" for i in range(40)
    )
    assert dependabot_check_text(nested_map)[0] == audit.UNKNOWN
    big = "version: 2\n# " + "a" * audit.MAX_DEPENDABOT_BYTES + "\nupdates:\n" + GOOD_ENTRY
    assert dependabot_check_text(big)[0] == audit.UNKNOWN
    just_under = "version: 2\nupdates:\n" + GOOD_ENTRY
    assert len(just_under) < audit.MAX_DEPENDABOT_BYTES
    assert dependabot_check_text(just_under)[0] == audit.PASS


def test_bad_bytes_and_a_non_string_content_field_are_unknown():
    assert dependabot_check_text(b"\xff\xfe\x00bad")[0] == audit.UNKNOWN
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (200, {"content": 12345})
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.UNKNOWN


def test_foreign_values_in_the_label_are_one_clean_line_and_never_forge_a_line():
    hostile = (
        "updates:\n"
        '  - package-ecosystem: pip\n    directory: "/a\\n::error::forged\\n\\u001b[31mred\\r  FAIL x"\n'
        "    cooldown:\n      default-days: 1\n"
        "  - package-ecosystem: [a, b]\n    directory: {k: v}\n    cooldown:\n      default-days: 1\n"
        f'  - package-ecosystem: npm\n    directory: "{"d" * 500}"\n    cooldown:\n      default-days: 1\n'
    )
    status, detail = dependabot_check_text(hostile)
    assert status == audit.FAIL
    assert "\n" not in detail and "\r" not in detail and chr(27) not in detail and "::" not in detail
    assert detail.count(audit.COMPLEX) >= 1
    assert "d" * 150 not in detail and "[a, b]" not in detail and "k: v" not in detail
    report = audit.render([audit.Result(REPO_NAME, "dependabot-config", status, detail)])
    assert not any(line.lstrip().startswith("::") for line in report.splitlines())
    assert len(report.splitlines()) == 3  # blank line, repo name, the one result line


def test_render_neutralizes_newlines_controls_and_workflow_commands_in_any_field():
    nasty = audit.Result(
        "o/r\n::set-output name=x::1", "chk" + chr(27) + "[2J", audit.FAIL, "a\n::error::b\r\nFAIL forged" + chr(7)
    )
    report = audit.render([nasty])
    assert len(report.splitlines()) == 3
    assert "::" not in report and chr(27) not in report and chr(7) not in report and "\r" not in report


def test_a_cooldown_check_that_raises_is_unknown_and_the_audit_goes_on(monkeypatch):
    def boom(_config):
        raise RecursionError

    monkeypatch.setattr(audit, "cooldown_problems", boom)
    results = audit.audit_repo(REPO_NAME, fetcher(good_answers()))
    assert by_check(results)["dependabot-config"][0] == audit.UNKNOWN
    assert "dependabot-ecosystem" in by_check(results)
    assert audit.exit_code(results, allow_unknown=False) == 2


# --- round 2: ecosystem, version, the file object, redirects -----------------------


def config_check(text: str) -> tuple[str, str]:
    return dependabot_check_text(text)


@pytest.mark.parametrize(
    "entry",
    [
        "  - directory: /\n    cooldown:\n      default-days: 7\n",
        '  - package-ecosystem: ""\n    directory: /\n    cooldown:\n      default-days: 7\n',
        "  - package-ecosystem: true\n    directory: /\n    cooldown:\n      default-days: 7\n",
        "  - package-ecosystem: {a: b}\n    directory: /\n    cooldown:\n      default-days: 7\n",
        "  - package-ecosystem: [pip]\n    directory: /\n    cooldown:\n      default-days: 7\n",
        '  - package-ecosystem: "pip\\n::error::x"\n    directory: /\n    cooldown:\n      default-days: 7\n',
    ],
)
def test_an_entry_without_a_valid_package_ecosystem_fails_even_with_a_good_cooldown(entry):
    status, detail = config_check("version: 2\nupdates:\n" + entry)
    assert status == audit.FAIL, detail
    assert "package-ecosystem" in detail and "\n" not in detail and "::" not in detail


@pytest.mark.parametrize(
    "version", ["", "version: 1\n", 'version: "2"\n', "version: true\n", "version: 3\n", "version: 2.0\n"]
)
def test_a_document_that_is_not_version_two_fails(version):
    status, detail = config_check(version + "updates:\n" + GOOD_ENTRY)
    assert status == audit.FAIL, detail
    assert "version: 2" in detail


@pytest.mark.parametrize(
    "changes",
    [
        {"type": "symlink", "target": "../elsewhere/dependabot.yml"},
        {"type": "submodule"},
        {"type": "dir"},
        {"encoding": "none"},
        {"path": ".github/other.yml"},
        {"size": 10_000},
        {"content": "!!!not base64!!!"},
        {"content": 7},
    ],
)
def test_a_contents_answer_that_is_not_the_whole_regular_file_is_unknown(changes):
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (200, dep_file("version: 2\nupdates:\n" + GOOD_ENTRY, **changes))
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.UNKNOWN
    answers[DEPENDABOT_PATH] = (200, [dep_file("x")])
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.UNKNOWN


def test_a_whole_regular_file_still_passes():
    assert dependabot_check_text("version: 2\nupdates:\n" + GOOD_ENTRY)[0] == audit.PASS


def serve(handler_cls):
    import http.server
    import threading

    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_a_redirect_is_refused_and_the_second_host_never_sees_the_token(monkeypatch):
    import http.server

    seen = []

    class Target(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"content": "x"}')

        def log_message(self, *args):
            pass

    target, target_thread = serve(Target)

    class Redirector(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target.server_address[1]}/collect")
            self.end_headers()
            self.wfile.write(b"secret-looking redirect body")

        def log_message(self, *args):
            pass

    front, front_thread = serve(Redirector)
    try:
        monkeypatch.setattr(audit, "API", f"http://127.0.0.1:{front.server_address[1]}")
        code, body = audit.github_fetcher("tok-123")("/repos/o/r/contents/.github/dependabot.yml")
    finally:
        for server, thread in ((front, front_thread), (target, target_thread)):
            server.shutdown()
            server.server_close()
            thread.join()
    assert seen == [], "the redirect target must not be contacted at all"
    assert code == 302
    assert "tok-123" not in str(body) and "secret-looking" not in str(body)


def test_a_refused_redirect_reads_as_unknown_in_the_check():
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (302, {"message": "redirect refused"})
    status, detail = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"]
    assert status == audit.UNKNOWN and "302" in detail


# --- round 3: scope exemptions, transport errors, strict file, duplicates ------------


def scoped(extra: str) -> str:
    return "version: 2\nupdates:\n" + cooldown_entry("pip", "      default-days: 7\n" + extra)


@pytest.mark.parametrize(
    "extra",
    [
        '      exclude: ["*"]\n',
        "      exclude: [left-pad]\n",
        "      include: [one-dependency]\n",
        "      include: []\n",
        "      include: [1, 2]\n",
        "      include: everything\n",
        "      exclude: {a: b}\n",
        "      exclude: nope\n",
        '      include: ["*", extra]\n',
    ],
)
def test_a_cooldown_that_exempts_or_narrows_its_scope_fails(extra):
    status, detail = dependabot_check_text(scoped(extra))
    assert status == audit.FAIL, detail
    assert "exclude" in detail or "include" in detail


@pytest.mark.parametrize("extra", ["", '      include: ["*"]\n', "      exclude: []\n"])
def test_a_cooldown_with_the_full_scope_still_passes(extra):
    assert dependabot_check_text(scoped(extra))[0] == audit.PASS


def test_duplicate_ecosystem_and_directory_entries_fail_and_distinct_ones_pass():
    one = "  - package-ecosystem: pip\n    directory: /{d}\n    cooldown:\n      default-days: 7\n"
    status, detail = dependabot_check_text("version: 2\nupdates:\n" + one.format(d="") * 2)
    assert status == audit.FAIL and "twice" in detail
    assert dependabot_check_text("version: 2\nupdates:\n" + one.format(d="") + one.format(d="docs"))[0] == audit.PASS
    both = "  - package-ecosystem: npm\n    directories: [/a, /a]\n    cooldown:\n      default-days: 7\n"
    assert dependabot_check_text("version: 2\nupdates:\n" + both)[0] == audit.FAIL


def test_an_ecosystem_outside_the_known_list_is_a_note_beside_a_pass_not_a_failure():
    text = "version: 2\nupdates:\n" + GOOD_ENTRY.replace("pip", "brand-new")
    status, detail = dependabot_check_text(text)
    assert status == audit.PASS
    assert "brand-new" in detail and "KNOWN_ECOSYSTEMS" in detail
    assert "note" not in dependabot_check_text("version: 2\nupdates:\n" + GOOD_ENTRY)[1]
    assert {"pip", "npm", "gomod", "docker", "github-actions", "uv"} <= audit.KNOWN_ECOSYSTEMS


@pytest.mark.parametrize("size", ["missing", "7", True, 7.0, None])
def test_a_contents_answer_without_an_integer_size_is_unknown(size):
    file = dep_file("version: 2\nupdates:\n" + GOOD_ENTRY)
    if size == "missing":
        del file["size"]
    elif isinstance(size, float):
        file["size"] = float(file["size"])  # equal to the length, but not an int
    elif size == "7":
        file["size"] = str(file["size"])
    else:
        file["size"] = size
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (200, file)
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.UNKNOWN


def test_base64_with_ignored_garbage_is_unknown_but_the_apis_own_line_wrapping_passes():
    text = "version: 2\nupdates:\n" + GOOD_ENTRY
    file = dep_file(text)
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (200, {**file, "content": "!!!" + file["content"]})
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.UNKNOWN
    answers[DEPENDABOT_PATH] = (200, {**file, "content": base64.encodebytes(text.encode()).decode()})
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-config"][0] == audit.PASS


# transport errors: a stubbed opener, no network


class _Opener:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def open(self, req, timeout=None):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _Resp:
    status = 200
    headers = {}

    def __init__(self, body=b"{}"):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        body, self.body = self.body[:size] if size >= 0 else self.body, self.body[size:] if size >= 0 else b""
        return body


def _fetch_with(monkeypatch, *outcomes):
    opener = _Opener(*outcomes)
    waits = []
    monkeypatch.setattr(audit, "_OPENER", opener)
    monkeypatch.setattr(audit, "_sleep", waits.append)
    return audit.github_fetcher("tok-secret")("/repos/o/r/contents/x"), opener, waits


@pytest.mark.parametrize(
    "error",
    [
        OSError("tok-secret leaked in text"),
        ConnectionResetError("reset"),
        ConnectionRefusedError("refused"),
        TimeoutError("slow"),
        __import__("urllib.error").error.URLError("dns failure for https://api.github.com"),
        __import__("ssl").SSLError("tls"),
        __import__("http.client").client.RemoteDisconnected("closed"),
        ValueError("bad"),
    ],
)
def test_a_transport_failure_is_a_sanitized_599_never_an_exception(monkeypatch, error):
    (code, body), _, _ = _fetch_with(monkeypatch, *[error] * 3)
    assert code == 599
    assert body == {"message": f"transport error: {type(error).__name__}"}
    assert "tok-secret" not in str(body) and "api.github.com" not in str(body)


def test_a_transport_failure_reads_as_unknown_in_the_check_and_the_run_goes_on():
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (599, {"message": "transport error: URLError"})
    results = audit.audit_repo(REPO_NAME, fetcher(answers))
    assert by_check(results)["dependabot-config"][0] == audit.UNKNOWN
    assert "pre-commit-hook" in by_check(results)


def test_a_timeout_is_retried_up_to_three_attempts_then_reported(monkeypatch):
    (code, _), opener, waits = _fetch_with(monkeypatch, TimeoutError(), TimeoutError(), TimeoutError())
    assert code == 599 and opener.calls == 3 and waits == [1.0, 2.0]


def test_a_timeout_then_success_returns_the_answer(monkeypatch):
    (code, body), opener, _ = _fetch_with(monkeypatch, TimeoutError(), _Resp(b'{"ok": true}'))
    assert (code, body, opener.calls) == (200, {"ok": True}, 2)


def _http_error(code, headers=None):
    import io
    import urllib.error

    return urllib.error.HTTPError("u", code, "m", headers or {}, io.BytesIO(b'{"message": "busy tok-secret"}'))


def test_429_and_5xx_are_retried_with_a_capped_retry_after_and_403_is_not(monkeypatch):
    (code, _), opener, waits = _fetch_with(
        monkeypatch, _http_error(429, {"Retry-After": "9999"}), _http_error(503), _Resp(b"{}")
    )
    assert code == 200 and opener.calls == 3
    assert waits == [audit.RETRY_AFTER_CAP, 2.0]
    (code, body), opener, waits = _fetch_with(monkeypatch, _http_error(403))
    assert code == 403 and opener.calls == 1 and waits == []
    assert "tok-secret" not in str(body), "a server that echoes the token is redacted"


def test_a_non_retryable_transport_error_is_not_retried(monkeypatch):
    (code, _), opener, waits = _fetch_with(monkeypatch, ConnectionResetError("reset"))
    assert code == 599 and opener.calls == 1 and waits == []


# --- round 4: error bodies, locations, Retry-After, the ecosystem list ---------------


class _BadBody:
    """A file-like error body whose read() raises, or returns what it is told."""

    def __init__(self, result):
        self.result = result

    def read(self, size=-1):
        if isinstance(self.result, BaseException):
            raise self.result
        out, self.result = self.result[:size], self.result[size:]
        return out

    def close(self):
        pass


def _error_with(code, result, headers=None):
    import urllib.error

    return urllib.error.HTTPError("https://api.github.com/x", code, "m", headers or {}, _BadBody(result))


@pytest.mark.parametrize(
    "result, name",
    [
        (OSError("tok-secret from the error body"), "OSError"),
        (__import__("http.client").client.IncompleteRead(b"tok-secret"), "IncompleteRead"),
        (b"\xff\xfe tok-secret", "UnicodeDecodeError"),
        (b"{not json \xff", "UnicodeDecodeError"),
        (b"x" * (64 * 1024 + 1), "_BodyTooLarge"),
    ],
)
def test_an_unreadable_error_body_is_a_fixed_message_and_never_an_exception(monkeypatch, result, name):
    (code, body), opener, _ = _fetch_with(monkeypatch, _error_with(403, result))
    assert code == 403 and opener.calls == 1
    assert body == {"message": f"HTTP error body unreadable: {name}"}
    assert "tok-secret" not in str(body)


def test_an_unreadable_body_after_retries_is_reported_and_the_audit_goes_on(monkeypatch):
    errors = [_error_with(500, OSError("tok-secret"))] * 3
    (code, body), opener, _ = _fetch_with(monkeypatch, *errors)
    assert code == 500 and opener.calls == 3
    assert body == {"message": "HTTP error body unreadable: OSError"} and "tok-secret" not in str(body)
    answers = good_answers()
    answers[DEPENDABOT_PATH] = (code, body)
    results = audit.audit_repo(REPO_NAME, fetcher(answers))
    assert by_check(results)["dependabot-config"][0] == audit.UNKNOWN
    assert "tok-secret" not in audit.render(results)


def test_a_success_body_over_the_cap_is_a_transport_error_not_a_parse(monkeypatch):
    big = _Resp(b'{"a": "' + b"x" * audit.MAX_BODY + b'"}')
    (code, body), _, _ = _fetch_with(monkeypatch, big)
    assert code == 599 and body == {"message": "transport error: _BodyTooLarge"}


def test_a_small_error_body_still_gives_its_message_with_the_token_redacted(monkeypatch):
    (code, body), _, _ = _fetch_with(monkeypatch, _error_with(404, b'{"message": "Not Found tok-secret"}'))
    assert code == 404 and body == {"message": "Not Found ***"}
    (code, body), _, _ = _fetch_with(monkeypatch, _error_with(404, b"plain text tok-secret"))
    assert body == {"message": "plain text ***"}


LOCATION_ENTRY = "  - package-ecosystem: pip\n{loc}    cooldown:\n      default-days: 7\n"


@pytest.mark.parametrize(
    "loc",
    [
        "",
        "    directory: null\n",
        '    directory: ""\n',
        '    directory: "   "\n',
        "    directory: [/]\n",
        "    directory: 5\n",
        "    directories: []\n",
        "    directories: null\n",
        "    directories: /\n",
        "    directories: [/, 5]\n",
        '    directories: [/, ""]\n',
        "    directories: [/a, /a]\n",
        "    directories: {a: b}\n",
        "    directory: /\n    directories: [/a]\n",
    ],
)
def test_an_entry_without_exactly_one_valid_location_fails(loc):
    status, detail = dependabot_check_text("version: 2\nupdates:\n" + LOCATION_ENTRY.format(loc=loc))
    assert status == audit.FAIL, detail
    assert "directory" in detail and "\n" not in detail


@pytest.mark.parametrize("loc", ["    directory: /\n", "    directories: [/a, /b]\n", "    directories: ['/**/*']\n"])
def test_a_valid_directory_or_directories_passes(loc):
    assert dependabot_check_text("version: 2\nupdates:\n" + LOCATION_ENTRY.format(loc=loc))[0] == audit.PASS


def test_the_same_location_across_entries_of_one_ecosystem_still_fails():
    one = LOCATION_ENTRY.format(loc="    directories: [/a, /b]\n")
    two = LOCATION_ENTRY.format(loc="    directory: /b\n")
    assert dependabot_check_text("version: 2\nupdates:\n" + one + two)[0] == audit.FAIL


class _Headers(dict):
    pass


@pytest.mark.parametrize(
    "value, expected",
    [
        ("²", 1.0),
        ("-5", 1.0),
        ("99999999999", 1.0),
        ("soon", 1.0),
        ("", 1.0),
        ("3", 3.0),
        (" 4 ", 4.0),
        ("9999", audit.RETRY_AFTER_CAP),
        ("Thu, 26 Nov 2026 12:00:07 GMT", 7.0),
        ("Thu, 26 Nov 2026 11:00:00 GMT", 1.0),
        ("Thu, 26 Nov 2026 18:00:00 GMT", audit.RETRY_AFTER_CAP),
        ("Thu, 99 Zzz 2026 99:99:99 GMT", 1.0),
        ("26 Nov 2026 12:00:07", 7.0),
    ],
)
def test_retry_after_is_parsed_strictly_and_capped(monkeypatch, value, expected):
    import datetime

    monkeypatch.setattr(audit, "_now", lambda: datetime.datetime(2026, 11, 26, 12, 0, 0, tzinfo=datetime.UTC))
    assert audit._retry_wait(0, _Headers({"Retry-After": value})) == expected


def test_a_hostile_retry_after_header_does_not_abort_the_fetch(monkeypatch):
    (code, _), opener, waits = _fetch_with(monkeypatch, _error_with(429, b"{}", {"Retry-After": "²"}), _Resp(b"{}"))
    assert code == 200 and opener.calls == 2 and waits == [1.0]


def test_the_known_ecosystem_list_is_the_documented_set():
    documented = {
        "bazel", "bun", "bundler", "cargo", "composer", "conda", "deno", "devcontainers", "docker",
        "docker-compose", "dotnet-sdk", "elm", "github-actions", "gitsubmodule", "gomod", "gradle", "helm",
        "julia", "maven", "mix", "nix", "npm", "nuget", "opentofu", "pip", "pre-commit", "pub", "rust-toolchain",
        "sbt", "swift", "terraform", "uv", "vcpkg",
    }  # fmt: skip
    assert audit.KNOWN_ECOSYSTEMS == documented
    status, detail = dependabot_check_text("version: 2\nupdates:\n" + GOOD_ENTRY.replace("pip", "deno"))
    assert status == audit.PASS and "note" not in detail


# --- round 5: every file read is strict, requests are bounded in time, messages are typed ----


def _completed_answers(answers: dict) -> dict:
    return {path: (code, completed(path, body)) for path, (code, body) in answers.items()}


def _relative(api_path: str) -> str:
    return api_path.split("/contents/", 1)[1]


def _site(name: str):
    """(answers, api path of the file under test, the checks that read it)."""
    base = f"/repos/{REPO_NAME}/contents/"
    if name == "workflow":
        return good_answers(), base + ".github/workflows/ci.yml", ["workflows-pinned"]
    if name == "hook":
        return good_answers(), base + ".githooks/pre-commit", ["pre-commit-hook"]
    if name == "lock":
        return ecosystem_answers("uv", UV_LOCK), base + "requirements.txt", ["dependabot-ecosystem"]
    return (
        ecosystem_answers("uv", UV_LOCK),
        base + ".github/dependabot.yml",
        ["dependabot-ecosystem", "dependabot-config"],
    )


def _hostile(kind: str, rel: str) -> dict:
    good = base64.b64encode(b"name: x\n").decode()
    whole = {"type": "file", "path": rel, "encoding": "base64", "size": 8, "content": good}
    return {
        "non-utf8": {**whole, "content": "//4=", "size": 2},
        "non-str content": {**whole, "content": 7},
        "missing type": {k: v for k, v in whole.items() if k != "type"},
        "missing path": {k: v for k, v in whole.items() if k != "path"},
        "missing size": {k: v for k, v in whole.items() if k != "size"},
        "missing content": {k: v for k, v in whole.items() if k != "content"},
        "symlink": {**whole, "type": "symlink"},
        "wrong path": {**whole, "path": "elsewhere/" + rel},
        "bad base64": {**whole, "content": "***"},
    }[kind]


HOSTILE_KINDS = [
    "non-utf8",
    "non-str content",
    "missing type",
    "missing path",
    "missing size",
    "missing content",
    "symlink",
    "wrong path",
    "bad base64",
]


@pytest.mark.parametrize("site", ["workflow", "hook", "lock", "dependabot"])
@pytest.mark.parametrize("kind", HOSTILE_KINDS)
def test_every_file_read_site_survives_a_hostile_contents_answer(site, kind):
    answers, api_path, checks = _site(site)
    answers = _completed_answers(answers)
    answers[api_path] = (200, _hostile(kind, _relative(api_path)))
    results = by_check(audit.audit_repo(REPO_NAME, raw_fetcher(answers)))  # must not raise
    for check in checks:
        status, detail = results[check]
        if site == "hook" and kind == "non-utf8":
            assert status == audit.FAIL, "the hook is compared as bytes; wrong bytes are drift, not a crash"
        else:
            assert status == audit.UNKNOWN, (check, detail)


def test_the_strict_decoder_gives_text_only_for_a_whole_plain_utf8_file():
    ok = dep_file("a: 1\n")
    assert audit.contents_text(ok, ".github/dependabot.yml") == "a: 1\n"
    assert audit.contents_text(ok, "other.yml") is None
    for bad in (None, [], "text", 7, {**ok, "content": None}, dep_file(b"\xff\xfe")):
        assert audit.contents_text(bad, ".github/dependabot.yml") is None


def test_a_workflow_listing_with_hostile_entries_does_not_raise():
    answers = good_answers()
    answers[f"/repos/{REPO_NAME}/contents/.github/workflows"] = (200, [None, 7, {"name": 5}, {"name": "ci.yml"}])
    assert by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["workflows-pinned"][0] == audit.PASS


# the clock


class _FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class _Drip:
    """A body that yields one byte per read and lets 20 fake seconds pass each time."""

    def __init__(self, clock):
        self.clock = clock
        self.reads = 0

    def read(self, size=-1):
        self.reads += 1
        self.clock.now += 20
        return b"x"


def test_a_slow_drip_body_trips_the_request_deadline(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(audit, "_clock", clock)
    drip = _Drip(clock)
    with pytest.raises(audit._DeadlineExceeded):
        audit._read_capped(drip, audit.MAX_BODY, clock() + audit.REQUEST_DEADLINE)
    assert drip.reads <= 4, "bounded by the deadline, not by the 4 MiB cap"
    assert audit._read_capped(_BadBody(b"ok"), 10, clock() + 60) == b"ok", "a prompt body is untouched"


def test_a_slow_drip_through_the_fetcher_is_a_transport_error_after_bounded_work(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(audit, "_clock", clock)
    drips = []

    class Resp(_Resp):
        def __init__(self):
            self.drip = _Drip(clock)
            drips.append(self.drip)

        def read(self, size=-1):
            return self.drip.read(size)

    monkeypatch.setattr(audit, "_OPENER", _Opener(Resp(), Resp(), Resp()))
    monkeypatch.setattr(audit, "_sleep", clock.sleep)
    code, body = audit.github_fetcher("tok")("/repos/o/r")
    assert code == 599 and body["message"].startswith("transport error")
    assert sum(d.reads for d in drips) <= 3 * 4


def test_retry_waits_count_against_the_repository_deadline(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(audit, "_clock", clock)
    opener = _Opener(TimeoutError(), TimeoutError(), TimeoutError())
    monkeypatch.setattr(audit, "_OPENER", opener)
    monkeypatch.setattr(audit, "_sleep", clock.sleep)
    monkeypatch.setitem(audit._limits, "repo", clock() + 2.5)
    try:
        code, body = audit.github_fetcher("tok")("/repos/o/r")
    finally:
        audit._limits["repo"] = None
    assert code == 599 and body == {"message": "transport error: deadline exceeded"}
    assert opener.calls == 2, "the 2 second wait would pass the deadline, so the third try never starts"


def test_a_repository_past_its_deadline_stops_calling_the_api(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(audit, "_clock", clock)
    calls = []

    class Slow:
        def open(self, req, timeout=None):
            calls.append(req.full_url)
            clock.now += 30
            return _Resp(b"{}")

    monkeypatch.setattr(audit, "_OPENER", Slow())
    monkeypatch.setattr(audit, "load_register", lambda: [])
    results = audit.audit_repo(REPO_NAME, audit.github_fetcher("tok"), register=[])
    assert 4 <= len(calls) <= 7, calls  # 180 s of 30 s calls, then every later check is UNKNOWN unasked
    assert any(r.status == audit.UNKNOWN and "deadline" in r.detail for r in results)
    assert audit._limits["repo"] is None, "the repository deadline is cleared afterwards"


def test_the_audit_deadline_makes_the_remaining_repositories_unknown(monkeypatch, capsys):
    clock = _FakeClock()
    monkeypatch.setattr(audit, "_clock", clock)
    inner = fetcher(good_answers())

    def slow_fetcher(token):
        def fetch(path):
            if "second" in path:
                raise AssertionError("the second repository must not be asked about")
            clock.now += 7200  # two hours pass during the first repository
            return inner(path)

        return fetch

    monkeypatch.setattr(audit, "github_fetcher", slow_fetcher)
    monkeypatch.setattr(audit, "load_register", lambda: [])
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    code = audit.main([REPO_NAME, f"{OWNER}/second", "--deadline-minutes", "1"])
    out = capsys.readouterr().out
    assert code == 2 and "audit deadline passed" in out and f"{OWNER}/second" in out
    assert audit._limits["audit"] is None


def test_the_default_deadlines_are_the_documented_ones():
    assert (audit.REQUEST_DEADLINE, audit.REPO_DEADLINE, audit.AUDIT_DEADLINE) == (60.0, 180.0, 2700.0)


# error message typing


@pytest.mark.parametrize("message", [7, [1, 2], {"a": 1}, None, True, 0, False, 1.5])
def test_a_non_string_error_message_is_a_fixed_text_and_never_a_crash(monkeypatch, message):
    body = json.dumps({"message": message}).encode()
    (code, answer), _, _ = _fetch_with(monkeypatch, _error_with(403, body))
    assert answer == {"message": audit.MALFORMED_ERROR}
    assert audit.unreadable(code, answer) == f"HTTP 403: {audit.MALFORMED_ERROR}"
    assert audit.unreadable(403, {"message": message}) == f"HTTP 403: {audit.MALFORMED_ERROR}"


def test_a_string_error_message_still_reads_and_a_missing_one_is_empty():
    assert audit.unreadable(404, {"message": "Not Found"}) == "HTTP 404: Not Found"
    assert audit.unreadable(404, {}) == "HTTP 404"
    assert audit.unreadable(404, [1]) == "HTTP 404"


def test_a_retry_wait_that_would_pass_the_repository_deadline_is_refused_even_with_the_clock_still(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(audit, "_clock", clock)
    opener = _Opener(TimeoutError(), TimeoutError(), TimeoutError())
    monkeypatch.setattr(audit, "_OPENER", opener)
    monkeypatch.setattr(audit, "_sleep", lambda seconds: None)  # time does not pass: only the wait check can stop it
    monkeypatch.setitem(audit._limits, "repo", clock() + 1.5)
    try:
        code, body = audit.github_fetcher("tok")("/repos/o/r")
    finally:
        audit._limits["repo"] = None
    assert code == 599 and body == {"message": "transport error: deadline exceeded"} and opener.calls == 2


def test_a_request_made_after_the_deadline_has_passed_is_not_sent(monkeypatch):
    clock = _FakeClock()
    monkeypatch.setattr(audit, "_clock", clock)
    opener = _Opener(_Resp())
    monkeypatch.setattr(audit, "_OPENER", opener)
    monkeypatch.setitem(audit._limits, "audit", clock() - 1)
    try:
        code, body = audit.github_fetcher("tok")("/repos/o/r")
    finally:
        audit._limits["audit"] = None
    assert code == 599 and opener.calls == 0


# --- round 6: a real interrupting deadline, per-repository isolation, structural roots -----


def _drip_server(stop, status=200):
    import http.server
    import socketserver
    import threading
    import time

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Length", "8192")
            self.end_headers()
            try:
                for _ in range(60):  # a byte every 0.2 s: far under any socket timeout, never the whole body
                    if stop.is_set():
                        return
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                pass

        def log_message(self, *args):
            pass

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_a_real_slow_drip_server_is_cut_off_at_the_request_deadline(monkeypatch):
    import threading
    import time

    stop = threading.Event()
    server, thread = _drip_server(stop)
    monkeypatch.setattr(audit, "API", f"http://127.0.0.1:{server.server_address[1]}")
    monkeypatch.setattr(audit, "REQUEST_DEADLINE", 1.0)
    monkeypatch.setattr(audit, "FETCH_ATTEMPTS", 1)
    try:
        started = time.monotonic()
        code, body = audit.github_fetcher("tok")("/repos/o/r")
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join()
    assert code == 599 and body["message"].startswith("transport error"), (code, body)
    assert elapsed < 4, f"a read that drips for 12 s was cut off after {elapsed:.1f} s"


def test_a_real_slow_drip_error_body_is_cut_off_at_the_request_deadline_too(monkeypatch):
    import threading
    import time

    stop = threading.Event()
    server, thread = _drip_server(stop, status=403)
    monkeypatch.setattr(audit, "API", f"http://127.0.0.1:{server.server_address[1]}")
    monkeypatch.setattr(audit, "REQUEST_DEADLINE", 1.0)
    monkeypatch.setattr(audit, "FETCH_ATTEMPTS", 1)
    try:
        started = time.monotonic()
        code, body = audit.github_fetcher("tok")("/repos/o/r")
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        thread.join()
    assert code == 403 and body == {"message": "HTTP error body unreadable: _DeadlineExceeded"}, (code, body)
    assert elapsed < 4, f"an error body that drips for 12 s was cut off after {elapsed:.1f} s"


def test_the_per_repository_loop_survives_audit_repo_itself_raising(monkeypatch, capsys):
    real = audit.audit_repo

    def flaky(repo, *args, **kwargs):
        if repo.endswith("/broken"):
            raise RuntimeError("secret-text")
        return real(repo, *args, **kwargs)

    monkeypatch.setattr(audit, "audit_repo", flaky)
    monkeypatch.setattr(audit, "github_fetcher", lambda token: fetcher(good_answers()))
    monkeypatch.setattr(audit, "load_register", lambda: [])
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    assert audit.main([f"{OWNER}/broken", REPO_NAME]) == 2
    out = capsys.readouterr().out
    assert "RuntimeError" in out and "secret-text" not in out and "  PASS    dependabot-config" in out


def test_the_alarm_interrupts_a_blocked_call_and_restores_the_handler_and_timer():
    import signal
    import time

    before = signal.getsignal(signal.SIGALRM)
    started = time.monotonic()
    with pytest.raises(audit._DeadlineExceeded):
        with audit._alarm(0.2):
            time.sleep(5)
    assert time.monotonic() - started < 2
    assert signal.getsignal(signal.SIGALRM) is before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    with audit._alarm(5):  # a block that finishes in time is untouched, and the timer is cleared
        pass
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_without_sigalrm_the_alarm_is_a_no_op_and_the_chunk_checks_remain(monkeypatch):
    import types

    monkeypatch.setattr(audit, "signal", types.SimpleNamespace())
    ran = []
    with audit._alarm(0.001):
        ran.append(True)
    assert ran == [True]


# isolation: one repository, or one check, never takes the fleet down

EXCEPTIONS = [RecursionError, MemoryError, OverflowError, RuntimeError, AttributeError, TypeError]


@pytest.mark.parametrize("exc", EXCEPTIONS)
def test_a_check_that_raises_is_unknown_by_class_name_and_the_others_still_report(monkeypatch, exc):
    def boom(*args, **kwargs):
        raise exc("secret-text-from-the-exception")

    monkeypatch.setattr(audit, "check_tag_ruleset", boom)
    results = audit.audit_repo(REPO_NAME, fetcher(good_answers()))
    by = by_check(results)
    assert by["tag-ruleset"][0] == audit.UNKNOWN and exc.__name__ in by["tag-ruleset"][1]
    assert "secret-text" not in audit.render(results)
    assert by["dependabot-config"][0] == audit.PASS and by["pre-commit-hook"][0] == audit.PASS


@pytest.mark.parametrize("exc", EXCEPTIONS)
def test_a_repository_that_raises_is_unknown_and_the_next_one_is_still_audited(monkeypatch, capsys, exc):
    other = f"{OWNER}/broken"
    inner = fetcher(good_answers())

    def make(token):
        def fetch(path):
            if path.startswith(f"/repos/{other}"):
                raise exc("secret-text-from-the-exception")
            return inner(path)

        return fetch

    monkeypatch.setattr(audit, "github_fetcher", make)
    monkeypatch.setattr(audit, "load_register", lambda: [])
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    code = audit.main([other, REPO_NAME])
    out = capsys.readouterr().out
    assert code == 2
    assert exc.__name__ in out and "secret-text" not in out
    assert f"\n{REPO_NAME}\n" in out and "  PASS    dependabot-config" in out
    assert audit._limits["repo"] is None


def test_audit_repo_lets_keyboard_interrupt_and_system_exit_through(monkeypatch):
    for exc in (KeyboardInterrupt, SystemExit):

        def boom(*args, _exc=exc, **kwargs):
            raise _exc

        monkeypatch.setattr(audit, "check_tag_ruleset", boom)
        with pytest.raises(exc):
            audit.audit_repo(REPO_NAME, fetcher(good_answers()))
        assert audit._limits["repo"] is None


HOSTILE_VALUES = [None, 7, "text", [], [None], [7, "x", None], {}, {"x": 7}, {"owner": 7}, [{"name": 7}], True]


def test_no_malformed_answer_to_any_call_raises_out_of_the_audit():
    base = good_answers()
    for path in base:
        for value in HOSTILE_VALUES:
            answers = dict(base)
            answers[path] = (200, value)
            results = audit.audit_repo(REPO_NAME, fetcher(answers))  # must not raise
            assert results and all(isinstance(r, audit.Result) for r in results), (path, value)


@pytest.mark.parametrize("owner", [7, None, ["x"], "Organization", {"type": 7}, {"type": ["Organization"]}])
def test_a_malformed_owner_object_does_not_abort_the_repository(owner):
    answers = good_answers()
    code, body = answers[f"/repos/{REPO_NAME}"]
    answers[f"/repos/{REPO_NAME}"] = (code, {**body, "owner": owner})
    results = by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))
    assert results["dependabot-config"][0] == audit.PASS and "repository" not in results, "the checks still ran"


# the ecosystem check reads the structure


def _eco(text: str) -> tuple[str, str]:
    answers = ecosystem_answers("uv", UV_LOCK)
    answers[DEPENDABOT_PATH] = (200, dep_file(text))
    return by_check(audit.audit_repo(REPO_NAME, fetcher(answers)))["dependabot-ecosystem"]


@pytest.mark.parametrize(
    "entry",
    [
        "  - package-ecosystem: pip\n    directories: [/]\n",
        "  - package-ecosystem: pip\n    directories:\n      - /docs\n      - /\n",
        "  - {package-ecosystem: pip, directory: /}\n",
        "  - {package-ecosystem: pip, directories: ['/', /x]}\n",
        "  - package-ecosystem: pip\n    directory: >-\n      /\n",
        '  - package-ecosystem: "pip"\n    directory: "/"\n',
        "  - package-ecosystem: pip\n",
    ],
)
def test_a_pip_entry_covering_the_root_fails_however_it_is_written(entry):
    status, detail = _eco("version: 2\nupdates:\n" + entry)
    assert status == audit.FAIL, detail
    assert "uv" in detail


@pytest.mark.parametrize(
    "entry",
    [
        "  - package-ecosystem: pip\n    directory: /docs\n",
        "  - package-ecosystem: pip\n    directories: [/docs, /x]\n",
        "  - package-ecosystem: uv\n    directories: [/]\n",
        "  - {package-ecosystem: npm, directory: /}\n",
    ],
)
def test_a_pip_entry_elsewhere_or_another_ecosystem_for_the_root_passes(entry):
    assert _eco("version: 2\nupdates:\n" + entry)[0] == audit.PASS


def test_an_unparseable_dependabot_yml_makes_the_ecosystem_check_unknown_never_pass():
    for text in ("updates: &a\n  - *a\n", "updates: [unclosed\n", "a: 1\na: 2\n"):
        status, detail = _eco(text)
        assert status == audit.UNKNOWN and "was not read" in detail, (text, detail)


# the deadline option


@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0", "-5", "0.5", "721", "1e999", "1e308", "abc", ""])
def test_a_bad_deadline_option_is_refused(value, capsys):
    with pytest.raises(SystemExit) as stop:
        audit.main([REPO_NAME, "--deadline-minutes", value])
    assert stop.value.code == 2
    assert "deadline-minutes" in capsys.readouterr().err


@pytest.mark.parametrize("value, minutes", [("1", 1.0), ("45", 45.0), ("720", 720.0), ("2.5", 2.5)])
def test_a_good_deadline_option_is_accepted(value, minutes):
    assert audit._deadline_minutes(value) == minutes
