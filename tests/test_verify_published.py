"""verify-published.yml proves a published image verifies from outside.

It is consumer-side: a reader, never a publisher. These checks hold it to
that, and keep its cosign and gh commands from drifting away from what
container-release.yml produces.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github" / "workflows" / "verify-published.yml"
CI = REPO / ".github" / "workflows" / "ci.yml"
TEXT = WORKFLOW.read_text()
DOC = yaml.safe_load(TEXT)
CALL = (DOC.get("on") or DOC.get(True))["workflow_call"]
JOBS = DOC["jobs"]


def steps(job: str) -> list[dict]:
    return JOBS[job]["steps"]


def step_named(fragment: str) -> dict:
    for step in steps("verify"):
        if fragment in step.get("name", ""):
            return step
    raise AssertionError(f"no step mentions {fragment!r}")


def test_inputs_and_defaults():
    inputs = CALL["inputs"]
    assert inputs["image"]["required"] is True
    assert inputs["identity-regexp"]["default"] == "^https://github.com/ChiefGyk3D/"
    assert inputs["oidc-issuer"]["default"] == "https://token.actions.githubusercontent.com"
    assert inputs["verify-sbom"]["default"] is True
    assert inputs["verify-provenance"]["default"] is True
    assert inputs["test-command"]["default"] == ""
    assert inputs["platforms"]["default"] == "linux/amd64,linux/arm64"
    assert inputs["egress-policy"]["default"] == "block"
    assert "secrets" not in CALL


def test_shape_and_permissions():
    assert set(JOBS) == {"verify", "verified"}
    assert JOBS["verify"]["name"] == "Verify ${{ inputs.image }}"
    assert JOBS["verify"]["runs-on"] == "ubuntu-24.04"
    assert JOBS["verify"]["permissions"] == {"contents": "read", "packages": "read"}
    assert JOBS["verified"]["name"] == "Verified"
    assert JOBS["verified"]["needs"] == ["verify"]
    assert JOBS["verified"]["if"] == "always()"
    assert JOBS["verified"]["permissions"] == {}


def test_it_holds_no_token_and_no_secret():
    assert "id-token" not in TEXT.replace("no `id-token`", "")
    assert "secrets." not in TEXT
    assert "doppler" not in TEXT.lower()
    assert "write" not in yaml.safe_dump([j.get("permissions") for j in JOBS.values()])


def test_cosign_verifies_signature_and_sbom_against_identity_and_issuer():
    sign = step_named("signature")["run"]
    assert 'cosign verify "$IMAGE"' in sign
    sbom = step_named("SBOM")
    assert sbom["if"] == "inputs.verify-sbom"
    assert 'cosign verify-attestation --type spdxjson "$IMAGE"' in sbom["run"]
    for run in (sign, sbom["run"]):
        assert '--certificate-identity-regexp "$IDENTITY_REGEXP"' in run
        assert '--certificate-oidc-issuer "$OIDC_ISSUER"' in run
        assert "--certificate-identity " not in run


def test_provenance_uses_the_read_only_github_token_and_the_image_owner():
    step = step_named("provenance")
    assert step["if"] == "inputs.verify-provenance"
    assert step["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert 'gh attestation verify "oci://$IMAGE" --owner "$owner"' in step["run"]


def test_every_platform_is_pulled_and_qemu_only_when_one_differs():
    run = step_named("each platform")["run"]
    assert 'docker pull --platform "$platform"' in run
    assert 'DOCKER_DEFAULT_PLATFORM="$platform"' in run
    qemu = [s for s in steps("verify") if "docker/setup-qemu-action@" in s.get("uses", "")]
    assert len(qemu) == 1
    assert qemu[0]["if"] == "steps.emulation.outputs.qemu == 'true'"


def test_cosign_installer_matches_the_producer():
    producer = (REPO / ".github" / "workflows" / "container-release.yml").read_text()
    line = next(x.strip() for x in TEXT.splitlines() if "sigstore/cosign-installer@" in x)
    assert line in {x.strip().removeprefix("- ") for x in producer.splitlines()} | {
        x.strip() for x in producer.splitlines()
    }, "cosign-installer is pinned differently from container-release.yml"


def test_fixture_verifies_a_real_image_and_gates_ci_green():
    ci = yaml.safe_load(CI.read_text())["jobs"]
    job = ci["fixture-verify"]
    assert job["uses"] == "./.github/workflows/verify-published.yml"
    assert job["with"]["image"].startswith("ghcr.io/chiefgyk3d/")
    assert job["with"]["test-command"].strip()
    assert "|| true" not in job["with"]["test-command"]
    assert "fixture-verify" in ci["ci-green"]["needs"]
