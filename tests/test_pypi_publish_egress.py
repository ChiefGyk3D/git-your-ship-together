"""The PyPI publish job pulls a container image; only that job may reach the registry.

pypa/gh-action-pypi-publish is a Docker action: the runner pulls
ghcr.io/pypa/gh-action-pypi-publish before it runs, and the layers are
redirected to pkg-containers.githubusercontent.com. Under harden-runner `block`
the pull is refused (hypeman v0.3.1, "connection refused"). The hosts belong in
the publish job's own list, not in the one the build job shares.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
DOC = yaml.safe_load((REPO / ".github" / "workflows" / "python-package-release.yml").read_text())
CALL = (DOC.get("on") or DOC.get(True))["workflow_call"]
JOBS = DOC["jobs"]
REGISTRY = {"ghcr.io:443", "pkg-containers.githubusercontent.com:443"}


def harden(job: str) -> dict:
    return next(s for s in JOBS[job]["steps"] if "harden-runner" in s.get("uses", ""))["with"]


def test_the_publish_job_allows_the_action_image_pull():
    default = CALL["inputs"]["publish-allowed-endpoints"]["default"].split(" ")
    assert REGISTRY <= set(default)
    assert "inputs.publish-allowed-endpoints" in harden("publish-pypi")["allowed-endpoints"]


def test_the_action_is_still_the_docker_one():
    # If pypa moves off a Docker action the registry hosts are dead weight; say so loudly.
    uses = [s["uses"] for s in JOBS["publish-pypi"]["steps"] if "gh-action-pypi-publish" in s.get("uses", "")]
    assert len(uses) == 1


def test_other_jobs_do_not_get_the_registry_hosts():
    # Negative case: the guard bites if the hosts leak into the shared default or another job.
    shared = set(CALL["inputs"]["allowed-endpoints"]["default"].split(" "))
    assert not REGISTRY & shared
    for job in ("build", "github-release"):
        assert "publish-allowed-endpoints" not in harden(job)["allowed-endpoints"]
