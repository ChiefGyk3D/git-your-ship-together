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
    assert inputs["image"]["default"] == ""
    assert inputs["release-tag"]["default"] == ""
    assert inputs["release-repository"]["default"] == ""
    assert inputs["verify-release-sbom"]["default"] is True
    assert inputs["identity-regexp"]["default"] == "^https://github.com/ChiefGyk3D/"
    assert inputs["oidc-issuer"]["default"] == "https://token.actions.githubusercontent.com"
    assert inputs["verify-sbom"]["default"] is True
    assert inputs["verify-provenance"]["default"] is True
    assert inputs["test-command"]["default"] == ""
    assert inputs["platforms"]["default"] == "linux/amd64,linux/arm64"
    assert inputs["egress-policy"]["default"] == "block"
    assert "secrets" not in CALL


def test_shape_and_permissions():
    assert set(JOBS) == {"verify", "verify-release", "verified"}
    assert JOBS["verify"]["name"] == "Verify ${{ inputs.image }}"
    assert JOBS["verify"]["if"] == "inputs.image != ''"
    assert JOBS["verify-release"]["if"] == "inputs.release-tag != ''"
    assert JOBS["verify-release"]["permissions"] == {"contents": "read"}
    assert JOBS["verify"]["runs-on"] == "ubuntu-24.04"
    assert JOBS["verify"]["permissions"] == {"contents": "read", "packages": "read"}
    assert JOBS["verified"]["name"] == "Verified"
    assert JOBS["verified"]["needs"] == ["verify", "verify-release"]
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


# --- the release half ------------------------------------------------------


def release_step(fragment: str) -> dict:
    for step in steps("verify-release"):
        if fragment in step.get("name", ""):
            return step
    raise AssertionError(f"no verify-release step mentions {fragment!r}")


def run_block(step: dict, directory, *, gh: str = "exit 0"):
    """Run a step's script in `directory` with `gh` stubbed to the given shell body."""
    import os
    import subprocess

    stub = directory / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "gh").write_text(f"#!/bin/bash\n{gh}\n")
    (stub / "gh").chmod(0o755)
    env = {**os.environ, "PATH": f"{stub}:{os.environ['PATH']}", "REPO": "o/r", "TAG": "v1"}
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", step["run"]], cwd=directory, env=env, capture_output=True, text=True
    )


def make_release(directory, *, sbom: bool = True, extra: str | None = None, tamper: bool = False):
    import hashlib
    import json

    release = directory / "release"
    release.mkdir()
    files = {"p-1.0.tar.gz": b"sdist", "p-1.0-py3-none-any.whl": b"wheel"}
    if sbom:
        files["sbom.cdx.json"] = json.dumps(
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "p"}]}
        ).encode()
        files["sbom.spdx.json"] = json.dumps({"spdxVersion": "SPDX-2.3", "packages": [{"name": "p"}]}).encode()
    (release / "SHA256SUMS").write_text("".join(f"{hashlib.sha256(b).hexdigest()}  ./{n}\n" for n, b in files.items()))
    for name, body in files.items():
        (release / name).write_bytes(body + (b"x" if tamper and name == "p-1.0.tar.gz" else b""))
    if extra:
        (release / extra).write_bytes(b"unlisted")
    return release


def test_release_assets_are_downloaded_checked_and_attested_for_the_owner():
    assert release_step("Download")["env"]["REPO"] == "${{ inputs.release-repository || github.repository }}"
    assert 'gh release download "$TAG" --repo "$REPO" --dir release' in release_step("Download")["run"]
    prov = release_step("provenance")
    assert prov["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert 'gh attestation verify "$f" --owner "$owner"' in prov["run"]
    assert release_step("SBOMs")["if"] == "inputs.verify-release-sbom"


def test_a_release_with_matching_checksums_and_both_sboms_passes(tmp_path):
    make_release(tmp_path)
    assert run_block(release_step("checksums"), tmp_path).returncode == 0
    assert run_block(release_step("SBOMs"), tmp_path).returncode == 0
    assert run_block(release_step("provenance"), tmp_path).returncode == 0


def test_a_changed_file_fails_the_checksums(tmp_path):
    make_release(tmp_path, tamper=True)
    assert run_block(release_step("checksums"), tmp_path).returncode != 0


def test_a_file_missing_from_sha256sums_fails(tmp_path):
    make_release(tmp_path, extra="added-later.bin")
    result = run_block(release_step("checksums"), tmp_path)
    assert result.returncode != 0 and "disagree" in result.stdout


def test_a_release_without_sboms_fails_the_sbom_check(tmp_path):
    make_release(tmp_path, sbom=False)
    result = run_block(release_step("SBOMs"), tmp_path)
    assert result.returncode != 0 and "sbom.cdx.json" in result.stdout


def test_an_sbom_that_is_not_cyclonedx_fails_the_sbom_check(tmp_path):
    release = make_release(tmp_path)
    (release / "sbom.cdx.json").write_text('{"bomFormat": "other"}')
    assert run_block(release_step("SBOMs"), tmp_path).returncode != 0


def test_a_failing_attestation_fails_the_provenance_step(tmp_path):
    make_release(tmp_path)
    assert run_block(release_step("provenance"), tmp_path, gh="exit 1").returncode != 0


def test_verified_fails_when_nothing_was_asked_for_and_accepts_a_skipped_half():
    run = steps("verified")[-1]["run"]
    assert 'if [ "$IMAGE_RESULT" = "skipped" ] && [ "$RELEASE_RESULT" = "skipped" ]' in run
    assert 'if [ "$result" != "success" ] && [ "$result" != "skipped" ]' in run
