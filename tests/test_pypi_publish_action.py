"""PyPI Trusted Publishing cannot use a reusable workflow as the publisher.

PyPI matches the token's `job_workflow_ref`, which for a job inside a reusable
workflow is the reusable file, not the caller's. A publisher registered for the
caller's workflow is answered `invalid-publisher` (warehouse#11096; hypeman
v0.3.1 and v0.3.2). A composite action used from a job in the caller's own
workflow keeps the caller's `job_workflow_ref`, so the publish step lives in
`.github/actions/publish-pypi` and the caller owns the job around it.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
ACTION_PATH = REPO / ".github" / "actions" / "publish-pypi" / "action.yml"
WORKFLOW_PATH = REPO / ".github" / "workflows" / "python-package-release.yml"
README = (REPO / "README.md").read_text()
WIKI = (REPO / "docs" / "wiki" / "Workflow-python-package-release.md").read_text()
ACTION = yaml.safe_load(ACTION_PATH.read_text())
WORKFLOW = yaml.safe_load(WORKFLOW_PATH.read_text())
JOBS = WORKFLOW["jobs"]
CALL = (WORKFLOW.get("on") or WORKFLOW.get(True))["workflow_call"]
SHA_USES = re.compile(r"uses:\s*(\S+)@([0-9a-f]{40})\s+# (v\d+\.\d+\.\d+)")


def problems(action: dict, text: str) -> list[str]:
    """Everything wrong with a publish composite; empty means sound."""
    found = []
    if action.get("runs", {}).get("using") != "composite":
        found.append("not a composite action")
    steps = action.get("runs", {}).get("steps", [])
    uses = [s.get("uses", "") for s in steps]
    if not (uses and uses[0].startswith("actions/download-artifact@")):
        found.append("first step must download the dist artifact")
    elif steps[0].get("with") != {"name": "dist", "path": "dist/"}:
        found.append("must download exactly the dist artifact into dist/")
    if sum(u.startswith("pypa/gh-action-pypi-publish@") for u in uses) != 1:
        found.append("must run pypa/gh-action-pypi-publish exactly once")
    if any(u.startswith("actions/checkout@") for u in uses):
        found.append("must not check anything out beside the OIDC token")
    if any("run" in s for s in steps):
        found.append("no shell steps: nothing here needs a script")
    if "${{ github." in text or "${{ secrets" in text:
        found.append("no context interpolation")
    for name, spec in (action.get("inputs") or {}).items():
        if not spec.get("description") or "default" not in spec:
            found.append(f"input {name} lacks a description or default")
        if f"inputs.{name}" not in text.split("inputs:", 1)[-1].split("runs:", 1)[-1]:
            found.append(f"input {name} is never used")
    return found


def test_the_action_is_sound():
    assert problems(ACTION, ACTION_PATH.read_text()) == []


def test_the_guard_bites():
    bad = {
        "runs": {
            "using": "composite",
            "steps": [{"uses": "actions/checkout@abc"}, {"run": "echo ${{ github.ref }}"}],
        },
        "inputs": {"orphan": {"description": "x", "default": ""}},
    }
    found = problems(bad, "run: echo ${{ github.ref }}")
    assert len(found) >= 5


def test_the_download_pin_matches_the_reusable_workflow():
    def pins(path: Path):
        return {m[0:2] for m in SHA_USES.findall(path.read_text()) if m[0] == "actions/download-artifact"}

    assert pins(ACTION_PATH) and pins(ACTION_PATH) == pins(WORKFLOW_PATH)


def test_publishing_uses_the_attested_pypa_action_at_a_pinned_sha():
    publish = next(s for s in ACTION["runs"]["steps"] if "gh-action-pypi-publish" in s["uses"])
    assert re.fullmatch(r"pypa/gh-action-pypi-publish@[0-9a-f]{40}", publish["uses"])
    assert publish["with"]["attestations"] is True or publish["with"]["attestations"] == "true"
    assert publish["with"]["repository-url"] == "${{ inputs.repository-url }}"
    assert ACTION["inputs"]["repository-url"]["default"] == "https://upload.pypi.org/legacy/"


def test_the_reusable_workflow_no_longer_publishes_to_pypi_itself():
    assert "publish-pypi" not in JOBS
    assert "gh-action-pypi-publish" not in WORKFLOW_PATH.read_text().replace("# ", "").split("\njobs:")[1]
    granted = {n for n, j in JOBS.items() if (j.get("permissions") or {}).get("id-token") == "write"}
    assert granted == {"github-release"}, "only build provenance needs an OIDC token here"


def test_pypi_defaults_off_and_asking_for_it_fails_fast():
    assert CALL["inputs"]["pypi"]["default"] is False
    job = JOBS["pypi-unsupported"]
    assert "inputs.pypi" in str(job["if"]) and job.get("permissions") == {"contents": "read"}
    runs = [s["run"] for s in job["steps"] if "run" in s]
    assert runs and "exit 1" in runs[-1] and "publish-pypi" in runs[-1]


def test_the_github_release_does_not_depend_on_pypi():
    needs = JOBS["github-release"]["needs"]
    assert needs == "build" or needs == ["build"]
    assert "pypi" not in str(JOBS["github-release"]["if"])


def test_the_readme_and_the_wiki_show_the_caller_job():
    for text in (README, WIKI):
        assert "/.github/actions/publish-pypi@" in text
        assert "environment:" in text and "url: https://pypi.org/p/" in text
        assert "reusable workflow" in text and "invalid-publisher" in text
        assert "(not this one's)" not in text
