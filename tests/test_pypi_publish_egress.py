"""The publish step pulls a container image; the caller's publish job must allow the registry.

pypa/gh-action-pypi-publish is a Docker action: the runner pulls
ghcr.io/pypa/gh-action-pypi-publish before it runs, and the layers are
redirected to pkg-containers.githubusercontent.com. Under harden-runner `block`
the pull is refused (hypeman v0.3.1, "connection refused"). Publishing now runs
in the caller's own job (see test_pypi_publish_action.py), so the allow-list is
the caller's: the README example is the one place this repository writes it, and
it must hold every host the publish needs.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
README = (REPO / "README.md").read_text()
DOC = yaml.safe_load((REPO / ".github" / "workflows" / "python-package-release.yml").read_text())
CALL = (DOC.get("on") or DOC.get(True))["workflow_call"]
REGISTRY = {"ghcr.io:443", "pkg-containers.githubusercontent.com:443"}
NEEDED = REGISTRY | {
    "upload.pypi.org:443",
    "files.pythonhosted.org:443",
    "pypi.org:443",
    "fulcio.sigstore.dev:443",
    "rekor.sigstore.dev:443",
    "tuf-repo-cdn.sigstore.dev:443",
    "timestamp.sigstore.dev:443",
    "api.github.com:443",
    "github.com:443",
}


def example_allow_list(text: str) -> set[str]:
    """The allow-list of the harden-runner step in the README's publish-pypi caller job."""
    block = re.search(r"  publish-pypi:\n(?:    .*\n|\n)+", text)
    assert block, "README has no publish-pypi caller job"
    job = yaml.safe_load(block.group(0))["publish-pypi"]
    first = job["steps"][0]
    assert first["uses"].startswith("step-security/harden-runner@")
    assert first["with"]["egress-policy"] == "block"
    return set(first["with"]["allowed-endpoints"].split(" "))


def test_the_readme_publish_job_allows_every_host_the_publish_needs():
    assert NEEDED <= example_allow_list(README)


def test_the_example_allow_list_is_one_line_of_sorted_host_ports():
    block = re.search(r"  publish-pypi:\n(?:    .*\n|\n)+", README).group(0)
    line = next(ln for ln in block.splitlines() if "allowed-endpoints:" in ln)
    hosts = line.split("allowed-endpoints:", 1)[1].strip().split(" ")
    assert hosts == sorted(hosts) and "*" not in line


def test_the_guard_bites_when_the_registry_is_missing():
    # Negative case: strip the registry hosts from the example and the check must fail.
    without = README
    for host in REGISTRY:
        without = without.replace(f" {host}", "")
    assert not NEEDED <= example_allow_list(without)


def test_the_reusable_workflow_no_longer_carries_the_registry_hosts():
    # The build and release jobs never pull an image; the input that appended them is gone.
    assert "publish-allowed-endpoints" not in CALL["inputs"]
    shared = set(CALL["inputs"]["allowed-endpoints"]["default"].split(" "))
    assert not REGISTRY & shared
