"""PyPI is published by direct steps in the caller's own job, never through a wrapper.

PyPI Trusted Publishing matches the token's `job_workflow_ref`, which for a job
inside a reusable workflow is the reusable file (warehouse#11096; hypeman
v0.3.1 and v0.3.2), so the publish job lives in the caller's workflow. And
pypa/gh-action-pypi-publish is a Docker action that derives its image from the
repository of the action that contains it: wrapped in a composite action
(GYST v1.19.0) it ran `docker run ghcr.io/ChiefGyk3D/git-your-ship-together:<sha>`
and failed (hypeman v0.3.3, run 37976560401). It must be a direct step.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW_PATH = REPO / ".github" / "workflows" / "python-package-release.yml"
README = (REPO / "README.md").read_text()
WIKI = (REPO / "docs" / "wiki" / "Workflow-python-package-release.md").read_text()
WORKFLOW = yaml.safe_load(WORKFLOW_PATH.read_text())
JOBS = WORKFLOW["jobs"]
CALL = (WORKFLOW.get("on") or WORKFLOW.get(True))["workflow_call"]
DOWNLOAD = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
PYPA = "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"


def caller_job(text: str) -> dict:
    block = re.search(r"  publish-pypi:\n(?:    .*\n|\n)+", text)
    assert block, "no publish-pypi caller job"
    return yaml.safe_load(block.group(0))["publish-pypi"]


def wrappers_of_pypa(root: Path) -> list[str]:
    """Composite actions under root that run the pypa publish action."""
    return sorted(
        str(p.relative_to(root)) for p in root.glob("*/action.y*ml") if "pypa/gh-action-pypi-publish" in p.read_text()
    )


def test_no_composite_action_wraps_the_pypa_publish_action():
    assert wrappers_of_pypa(REPO / ".github" / "actions") == []
    assert not (REPO / ".github" / "actions" / "publish-pypi").exists()


def test_the_wrapper_guard_bites(tmp_path):
    (tmp_path / "wrap").mkdir()
    (tmp_path / "wrap" / "action.yml").write_text(f"runs:\n  steps:\n    - uses: {PYPA} # v1.14.2\n")
    assert wrappers_of_pypa(tmp_path) == ["wrap/action.yml"]


def test_the_readme_pins_match_the_ones_this_repository_uses():
    job = caller_job(README)
    assert job["steps"][1]["uses"].startswith(DOWNLOAD) and job["steps"][2]["uses"].startswith(PYPA)
    assert DOWNLOAD in WORKFLOW_PATH.read_text()


def test_the_documented_job_is_two_direct_steps_after_harden_runner():
    for text in (README, WIKI):
        job = caller_job(text)
        assert job["needs"] == "package" and job["if"] == "github.event_name == 'release'"
        assert job["environment"]["name"] == "pypi" and job["environment"]["url"].startswith("https://pypi.org/p/")
        assert job["permissions"] == {"contents": "read", "id-token": "write"}
        steps = job["steps"]
        assert steps[0]["uses"].startswith("step-security/harden-runner@")
        assert len(steps) == 3
        download, publish = steps[1], steps[2]
        assert download["uses"].split(" ")[0].split("@")[0] == "actions/download-artifact"
        assert download["with"] == {"name": "dist", "path": "dist/"}
        assert publish["uses"].split(" ")[0].split("@")[0] == "pypa/gh-action-pypi-publish"
        assert publish["with"] == {"attestations": True}


def test_the_docs_carry_the_direct_step_warning():
    for text in (README, WIKI):
        assert "must be a direct step" in text
        assert "37976560401" in text and "docker run --help" in text
        assert "invalid-publisher" in text and "reusable workflow" in text
        assert ".github/actions/publish-pypi" not in text


def test_the_reusable_workflow_no_longer_publishes_to_pypi_itself():
    assert "publish-pypi" not in JOBS
    uses = [s.get("uses", "") for j in JOBS.values() for s in j.get("steps", [])]
    assert not [u for u in uses if u.startswith("pypa/")]
    granted = {n for n, j in JOBS.items() if (j.get("permissions") or {}).get("id-token") == "write"}
    assert granted == {"github-release"}, "only build provenance needs an OIDC token here"


def test_pypi_defaults_off_and_asking_for_it_fails_fast_pointing_at_the_direct_job():
    assert CALL["inputs"]["pypi"]["default"] is False
    job = JOBS["pypi-unsupported"]
    assert "inputs.pypi" in str(job["if"]) and job.get("permissions") == {"contents": "read"}
    runs = [s["run"] for s in job["steps"] if "run" in s]
    assert runs and "exit 1" in runs[-1] and "publish-pypi" in runs[-1]
    assert "gh-action-pypi-publish as direct steps" in runs[-1]
    assert ".github/actions/publish-pypi" not in runs[-1]


def test_the_github_release_does_not_depend_on_pypi():
    needs = JOBS["github-release"]["needs"]
    assert needs == "build" or needs == ["build"]
    assert "pypi" not in str(JOBS["github-release"]["if"])
