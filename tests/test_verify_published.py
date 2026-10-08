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
    assert set(JOBS) == {"verify", "verify-release", "rescan", "verified"}
    assert JOBS["verify"]["name"] == "Verify ${{ inputs.image }}"
    assert JOBS["verify"]["if"] == "inputs.image != ''"
    assert JOBS["verify-release"]["if"] == "inputs.release-tag != ''"
    assert JOBS["verify-release"]["permissions"] == {"contents": "read"}
    assert JOBS["verify"]["runs-on"] == "ubuntu-24.04"
    assert JOBS["verify"]["permissions"] == {"contents": "read", "packages": "read"}
    assert JOBS["verified"]["name"] == "Verified"
    assert JOBS["verified"]["needs"] == ["verify", "verify-release", "rescan"]
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


def test_every_image_reference_pulled_verified_run_or_rescanned_is_the_one_resolved_digest():
    """A tag can move after it is resolved; nothing but the digest may be verified, pulled, run or scanned.

    `inputs.image` may appear only where the digest is resolved, in the job's name and condition, and as the
    rescan's record of what was asked for. Every other IMAGE in the workflow is an output of the resolution.
    """
    allowed = {
        ("verify", "Resolve the image digest", "IMAGE"),
        ("rescan", "Rescan with Trivy", "IMAGE_REQUESTED"),
    }
    used = set()
    for job_name, job in JOBS.items():
        for step in job.get("steps", []):
            for key, value in (step.get("env") or {}).items():
                if "inputs.image" in str(value):
                    assert (job_name, step.get("name"), key) in allowed, (
                        f"{job_name}/{step.get('name')}: {key} takes inputs.image; use the resolved digest"
                    )
                    used.add((job_name, step.get("name"), key))
            for field in ("run", "with", "if"):
                assert "inputs.image" not in str(step.get(field, "")), f"{job_name}/{step.get('name')}: {field}"
    assert used == allowed
    refs = {
        (job_name, step.get("name")): step["env"]["IMAGE"]
        for job_name, job in JOBS.items()
        for step in job.get("steps", [])
        if "IMAGE" in (step.get("env") or {}) and (job_name, step.get("name"), "IMAGE") not in allowed
    }
    assert refs, "no step takes an image reference"
    assert {r for (j, _), r in refs.items() if j == "verify"} == {"${{ steps.digest.outputs.ref }}"}
    assert {r for (j, _), r in refs.items() if j == "rescan"} == {"${{ needs.verify.outputs.ref }}"}
    for fragment in ("signature", "SBOM attestation", "provenance", "each platform"):
        assert step_named(fragment)["env"]["IMAGE"] == "${{ steps.digest.outputs.ref }}"
    run = step_named("each platform")["run"]
    assert 'docker pull --platform "$platform" "$IMAGE"' in run
    # a digest holds one platform at a time locally, so the previous one is removed before the next pull
    assert run.index('docker image rm --force "$IMAGE"') < run.index("docker pull") < run.index("bash -eo pipefail -c")


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


# --- the rescan ------------------------------------------------------------
#
# Opt-in, a pinned Trivy binary, no action, no write, and a failure that is
# Trivy's own exit code. The scan step's script is run here with a stub `trivy`
# that records its arguments, so the flags are proved; the live half (the real
# binary against an SBOM with a known-vulnerable package) is `rescan_live`
# below, run by ci.yml's `rescan-live` job.

import os  # noqa: E402
import re  # noqa: E402
import subprocess  # noqa: E402

import pytest  # noqa: E402

RESCAN_INPUTS = (
    "rescan",
    "rescan-severity",
    "rescan-exit-code",
    "rescan-ignore-unfixed",
    "rescan-ignore-advisories",
    "rescan-artifact-name",
    "trivy-version",
    "trivy-sha256",
)


def rescan_step(fragment: str) -> dict:
    for step in steps("rescan"):
        if fragment in step.get("name", "") or fragment in step.get("uses", ""):
            return step
    raise AssertionError(f"no rescan step mentions {fragment!r}")


def test_the_rescan_is_off_by_default_and_its_defaults_are_the_containers():
    inputs = CALL["inputs"]
    assert inputs["rescan"]["default"] is False
    assert inputs["rescan-severity"]["default"] == "CRITICAL,HIGH"
    assert inputs["rescan-exit-code"]["default"] == "1"
    assert inputs["rescan-ignore-unfixed"]["default"] is True
    assert inputs["rescan-ignore-advisories"]["default"] == ""
    container = yaml.safe_load((REPO / ".github" / "workflows" / "container-release.yml").read_text())
    container_inputs = (container.get("on") or container.get(True))["workflow_call"]["inputs"]
    assert inputs["rescan-severity"]["default"] == container_inputs["trivy-severity"]["default"]
    assert inputs["rescan-exit-code"]["default"] == container_inputs["trivy-exit-code"]["default"]
    assert inputs["rescan-ignore-unfixed"]["default"] == container_inputs["trivy-ignore-unfixed"]["default"]
    for name in RESCAN_INPUTS:
        assert name in inputs and inputs[name]["description"].strip()


def test_the_rescan_job_runs_only_when_asked_and_only_after_a_good_verification():
    job = JOBS["rescan"]
    assert job["needs"] == ["verify", "verify-release"]
    assert "inputs.rescan" in job["if"]
    assert "contains(needs.*.result, 'failure')" in job["if"]
    assert "contains(needs.*.result, 'cancelled')" in job["if"]
    assert job["permissions"] == {"contents": "read"}
    assert steps("rescan")[0]["with"]["disable-sudo"] is True
    assert JOBS["verified"]["permissions"] == {}


def test_trivy_is_a_binary_pinned_by_hash_and_no_new_action_or_host_is_involved():
    install = rescan_step("Install Trivy")
    assert 'echo "${TRIVY_SHA256}  ${archive}" | sha256sum -c -' in install["run"]
    assert install["env"]["TRIVY_VERSION"] == "${{ inputs.trivy-version }}"
    assert re.fullmatch(r"[0-9a-f]{64}", CALL["inputs"]["trivy-sha256"]["default"])
    assert "aquasecurity/trivy-action" not in TEXT
    # the download and the database come from hosts the list already carries
    default = CALL["inputs"]["allowed-endpoints"]["default"].split()
    for host in ("github.com:443", "release-assets.githubusercontent.com:443", "mirror.gcr.io:443", "ghcr.io:443"):
        assert host in default
    assert "check.trivy.dev" not in default and "get.trivy.dev" not in default
    assert "--skip-version-check" in rescan_step("Rescan")["run"]


def test_caller_values_reach_the_rescan_only_through_env():
    for name in ("Install Trivy", "Write the ignore file", "Rescan"):
        assert "${{" not in rescan_step(name)["run"], name
    scan = rescan_step("Rescan")["env"]
    assert scan["SEVERITY"] == "${{ inputs.rescan-severity }}"
    assert scan["EXIT_CODE"] == "${{ inputs.rescan-exit-code }}"
    assert scan["IMAGE_REQUESTED"] == "${{ inputs.image }}"


def test_the_sarif_leaves_as_an_artifact_because_an_upload_would_break_every_existing_caller():
    upload = rescan_step("upload-artifact")
    assert upload["if"] == "always()"
    assert upload["with"]["name"] == "${{ inputs.rescan-artifact-name }}"
    assert "security-events" not in TEXT.replace("`security-events: write`", "")


DIGEST = "sha256:" + "ab" * 32
DIGEST_REF = f"ghcr.io/o/i@{DIGEST}"


def put_sbom(directory, env, body: bytes = b"{}", *, recorded: bytes | None = None):
    """Place the verified SBOM where the download step puts it, and record its hash as the verify job did."""
    import hashlib

    sbom_dir = directory / "verified-sbom"
    sbom_dir.mkdir(exist_ok=True)
    (sbom_dir / "sbom.cdx.json").write_bytes(body)
    env["SBOM_SHA256"] = hashlib.sha256(body if recorded is None else recorded).hexdigest()


def stub_env(directory, *, trivy_body: str):
    bin_dir = directory / "bin"
    bin_dir.mkdir(exist_ok=True)
    (directory / "trivy-bin").mkdir(exist_ok=True)
    (directory / "trivy-bin" / "trivy").write_text(f"#!/bin/bash\n{trivy_body}\n")
    (directory / "trivy-bin" / "trivy").chmod(0o755)
    return {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(directory),
        "SEVERITY": "CRITICAL,HIGH",
        "EXIT_CODE": "1",
        "IGNORE_UNFIXED": "true",
        "IMAGE": "",
        "IMAGE_REQUESTED": "",
        "PLATFORMS": "linux/amd64, linux/arm64",
        "RELEASE_TAG": "",
        "SBOM_DIR": str(directory / "verified-sbom"),
        "SBOM_SHA256": "",
    }


def run_rescan(directory, env, step="Rescan"):
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", rescan_step(step)["run"]],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
    )


# A trivy that logs its arguments, writes a JSON report for scans and a file for conversions.
RECORDING = (
    'echo "$@" >> "$RUNNER_TEMP/calls"\n'
    'out=""; prev=""; for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; done\n'
    '[ -n "$out" ] && echo \'{}\' > "$out"\n'
    'exit "${STUB_RC:-0}"'
)


def test_each_platform_of_the_image_is_scanned_with_the_configured_severity_and_exit_code(tmp_path):
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env.update(IMAGE=DIGEST_REF, IMAGE_REQUESTED="ghcr.io/o/i:1")
    result = run_rescan(tmp_path, env)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = (tmp_path / "calls").read_text()
    for platform in ("linux/amd64", "linux/arm64"):
        assert f"--platform {platform} -- {DIGEST_REF}" in calls
    assert "--severity CRITICAL,HIGH" in calls and "--exit-code 1" in calls
    assert "--image-src remote" in calls and "--ignore-unfixed" in calls
    assert (tmp_path / "rescan" / "image-linux-arm64.sarif").exists()


def test_a_finding_fails_the_step_and_exit_code_zero_only_reports(tmp_path):
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env.update(IMAGE=DIGEST_REF, IMAGE_REQUESTED="ghcr.io/o/i:1", STUB_RC="1")
    failed = run_rescan(tmp_path, env)
    assert failed.returncode == 1 and "::error title=rescan::image-linux-amd64" in failed.stdout
    # the report is still written, so the artifact carries what was found
    assert (tmp_path / "rescan" / "image-linux-amd64.sarif").exists()

    (tmp_path / "calls").unlink()
    env.update(EXIT_CODE="0", STUB_RC="0")
    assert run_rescan(tmp_path, env).returncode == 0
    assert "--exit-code 0" in (tmp_path / "calls").read_text()


def test_a_scan_that_errors_before_writing_a_report_still_fails(tmp_path):
    env = stub_env(tmp_path, trivy_body="exit 2")
    env.update(IMAGE=DIGEST_REF, IMAGE_REQUESTED="ghcr.io/o/i:1")
    result = run_rescan(tmp_path, env)
    assert result.returncode == 1
    assert not list((tmp_path / "rescan").glob("*.sarif"))


def test_the_release_sbom_is_scanned_and_a_release_without_one_fails(tmp_path):
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env["RELEASE_TAG"] = "v1"
    put_sbom(tmp_path, env)
    assert run_rescan(tmp_path, env).returncode == 0
    assert "sbom --quiet" in (tmp_path / "calls").read_text()
    assert (tmp_path / "rescan" / "release.sarif").exists()

    (tmp_path / "m").mkdir()
    missing = stub_env(tmp_path / "m", trivy_body=RECORDING)
    missing["RELEASE_TAG"] = "v1"
    result = run_rescan(tmp_path / "m", missing)
    assert result.returncode == 1 and "no sbom.cdx.json" in result.stdout


def test_a_replaced_sbom_with_a_different_hash_is_never_scanned(tmp_path):
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env["RELEASE_TAG"] = "v1"
    put_sbom(tmp_path, env, b'{"clean": true}', recorded=b'{"verified": true}')
    result = run_rescan(tmp_path, env)
    assert result.returncode == 1 and "sha256 mismatch" in result.stdout
    assert not (tmp_path / "calls").exists()


def test_a_missing_recorded_hash_fails_rather_than_trusting_the_file(tmp_path):
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env["RELEASE_TAG"] = "v1"
    put_sbom(tmp_path, env)
    env["SBOM_SHA256"] = ""
    assert run_rescan(tmp_path, env).returncode == 1


def test_both_halves_are_scanned_even_when_the_first_one_fails(tmp_path):
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env.update(IMAGE=DIGEST_REF, IMAGE_REQUESTED="ghcr.io/o/i:1", RELEASE_TAG="v1", STUB_RC="1")
    put_sbom(tmp_path, env)
    assert run_rescan(tmp_path, env).returncode == 1
    calls = (tmp_path / "calls").read_text()
    assert "image " in calls and "sbom " in calls


def test_the_scan_is_bound_to_the_verified_digest_not_the_tag_the_caller_typed(tmp_path):
    """The tag may resolve to different bytes by now; the scan names only what verify resolved."""
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env.update(IMAGE=DIGEST_REF, IMAGE_REQUESTED="ghcr.io/o/i:latest", PLATFORMS="linux/amd64")
    assert run_rescan(tmp_path, env).returncode == 0
    calls = (tmp_path / "calls").read_text()
    assert f"-- {DIGEST_REF}" in calls and ":latest" not in calls


@pytest.mark.parametrize("ref", ["", "ghcr.io/o/i:latest", "ghcr.io/o/i@sha256:abc"])
def test_a_reference_that_is_not_a_full_digest_is_refused_not_scanned(tmp_path, ref):
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env.update(IMAGE=ref, IMAGE_REQUESTED="ghcr.io/o/i:latest")
    result = run_rescan(tmp_path, env)
    assert result.returncode == 1 and "no image digest" in result.stdout
    assert not (tmp_path / "calls").exists()


@pytest.mark.parametrize("platforms", ["", "   ", ",", " , ,, "])
def test_an_empty_platform_list_fails_before_scanning_anything(tmp_path, platforms):
    env = stub_env(tmp_path, trivy_body=RECORDING)
    env.update(IMAGE=DIGEST_REF, IMAGE_REQUESTED="ghcr.io/o/i:1", PLATFORMS=platforms)
    result = run_rescan(tmp_path, env)
    assert result.returncode == 1 and "no image scan ran" in result.stdout
    assert not (tmp_path / "calls").exists()


def test_the_rescan_binds_to_what_the_verify_jobs_output():
    env = rescan_step("Rescan")["env"]
    assert env["IMAGE"] == "${{ needs.verify.outputs.ref }}"
    assert env["SBOM_SHA256"] == "${{ needs.verify-release.outputs.sbom-sha256 }}"
    assert JOBS["verify"]["outputs"]["ref"] == "${{ steps.digest.outputs.ref }}"
    for name in ("signature", "SBOM attestation", "provenance"):
        assert step_named(name)["env"]["IMAGE"] == "${{ steps.digest.outputs.ref }}"
    assert "gh release download" not in rescan_step("Rescan")["run"]
    handoff = [s for s in steps("verify-release") if "upload-artifact" in s.get("uses", "")]
    assert len(handoff) == 1 and handoff[0]["with"]["path"] == "release/sbom.cdx.json"
    assert JOBS["verify-release"]["permissions"] == {"contents": "read"}


def test_the_digest_step_resolves_the_manifest_digest_and_drops_the_tag(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text(f"#!/bin/bash\necho {DIGEST}\n")
    (bin_dir / "docker").chmod(0o755)
    for image in ("ghcr.io/o/i:latest", "ghcr.io/o/i", f"ghcr.io/o/i@sha256:{'cd' * 32}", "localhost:5000/o/i:1"):
        out = tmp_path / "out"
        out.write_text("")
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "IMAGE": image, "GITHUB_OUTPUT": str(out)}
        step = next(s for s in steps("verify") if s.get("id") == "digest")
        result = subprocess.run(["bash", "-eo", "pipefail", "-c", step["run"]], env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        base = image.split("@")[0]
        if base.rsplit("/", 1)[-1].count(":"):
            base = base.rsplit(":", 1)[0]
        assert out.read_text().strip() == f"ref={base}@{DIGEST}"


def ignore_file(tmp_path, advisories):
    env = {**os.environ, "RUNNER_TEMP": str(tmp_path), "ADVISORIES": advisories}
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", rescan_step("Write the ignore file")["run"]],
        env=env,
        capture_output=True,
        text=True,
    )
    return result, tmp_path / "rescan.trivyignore"


def test_accepted_advisories_become_the_ignore_file(tmp_path):
    result, path = ignore_file(tmp_path, "CVE-2026-12345, GHSA-abcd-1234-wxyz")
    assert result.returncode == 0
    assert path.read_text().split() == ["CVE-2026-12345", "GHSA-abcd-1234-wxyz"]


def test_no_accepted_advisories_is_an_empty_ignore_file(tmp_path):
    result, path = ignore_file(tmp_path, "")
    assert result.returncode == 0 and path.read_text() == ""


@pytest.mark.parametrize("bad", ["*", "CVE-2026-1", "CVE-2026-12345 exp:2099-01-01", "$(id)", "GHSA-ABCD-1234-wxyz"])
def test_a_value_that_is_not_an_advisory_id_is_refused_not_written(tmp_path, bad):
    result, path = ignore_file(tmp_path, f"CVE-2026-12345,{bad}")
    assert result.returncode != 0 and "is not a CVE or GHSA ID" in result.stdout
    assert "uid=" not in path.read_text()


def test_verified_reads_the_rescan_and_fails_on_it():
    run = steps("verified")[-1]["run"]
    assert 'for result in "$IMAGE_RESULT" "$RELEASE_RESULT" "$RESCAN_RESULT"' in run
    assert steps("verified")[-1]["env"]["RESCAN_RESULT"] == "${{ needs.rescan.result }}"


def test_the_fixture_rescans_a_real_image_and_gates_ci_green():
    ci = yaml.safe_load(CI.read_text())["jobs"]
    job = ci["fixture-rescan"]
    assert job["uses"] == "./.github/workflows/verify-published.yml"
    assert job["with"]["rescan"] is True
    assert job["with"]["image"].startswith("ghcr.io/chiefgyk3d/")
    assert job["permissions"] == {"contents": "read", "packages": "read"}
    assert "fixture-rescan" in ci["ci-green"]["needs"]
    live = ci["rescan-live"]
    assert live["steps"][-1]["env"]["RESCAN_LIVE"] == "1"
    assert "rescan-live" in ci["ci-green"]["needs"]


# --- the live half: the real Trivy against an SBOM with a known-vulnerable package --------

LIVE = bool(os.environ.get("RESCAN_LIVE"))
live = pytest.mark.skipif(not LIVE, reason="set RESCAN_LIVE=1 to run the real Trivy (ci.yml's rescan-live does)")

VULNERABLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [
        {
            "type": "library",
            "name": "django",
            "version": "1.11.0",
            "purl": "pkg:pypi/django@1.11.0",
            "bom-ref": "pkg:pypi/django@1.11.0",
        }
    ],
}
CLEAN_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": []}


def live_rescan(tmp_path, sbom, *, advisories="", exit_code="1"):
    """Install the pinned Trivy with the workflow's own step, then run its scan step on a release carrying `sbom`."""
    import json

    env = {
        **os.environ,
        "RUNNER_TEMP": str(tmp_path),
        "TRIVY_VERSION": CALL["inputs"]["trivy-version"]["default"],
        "TRIVY_SHA256": CALL["inputs"]["trivy-sha256"]["default"],
    }
    if not (tmp_path / "trivy-bin" / "trivy").exists():
        install = subprocess.run(
            ["bash", "-eo", "pipefail", "-c", rescan_step("Install Trivy")["run"]],
            env=env,
            capture_output=True,
            text=True,
        )
        assert install.returncode == 0, install.stdout + install.stderr
    ignored, _ = ignore_file(tmp_path, advisories)
    assert ignored.returncode == 0, ignored.stdout
    put_sbom(tmp_path, env, json.dumps(sbom).encode())
    env.update(
        TRIVY_CACHE_DIR=os.environ.get("TRIVY_CACHE_DIR", str(tmp_path / "cache")),
        SEVERITY="CRITICAL",
        EXIT_CODE=exit_code,
        IGNORE_UNFIXED="false",
        IMAGE="",
        IMAGE_REQUESTED="",
        PLATFORMS="",
        RELEASE_TAG="v1",
        SBOM_DIR=str(tmp_path / "verified-sbom"),
    )
    return subprocess.run(
        ["bash", "-eo", "pipefail", "-c", rescan_step("Rescan")["run"]],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


@live
def test_live_an_sbom_with_a_known_critical_advisory_fails_the_rescan_and_writes_sarif(tmp_path):
    import json

    result = live_rescan(tmp_path, VULNERABLE_SBOM)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "CVE-2019-14234" in result.stdout
    sarif = json.loads((tmp_path / "rescan" / "release.sarif").read_text())
    assert sarif["runs"][0]["results"], "the SARIF carries no results"


@live
def test_live_exit_code_zero_reports_the_same_finding_without_failing(tmp_path):
    result = live_rescan(tmp_path, VULNERABLE_SBOM, exit_code="0")
    assert result.returncode == 0 and "CVE-2019-14234" in result.stdout


@live
def test_live_an_accepted_advisory_is_honoured_and_the_others_still_fail(tmp_path):
    import json

    assert live_rescan(tmp_path, VULNERABLE_SBOM).returncode == 1
    found = {r["ruleId"] for r in json.loads((tmp_path / "rescan" / "release.sarif").read_text())["runs"][0]["results"]}
    assert len(found) >= 2, "the sample must carry more than one critical advisory for this proof"
    first, *rest = sorted(found)
    assert live_rescan(tmp_path, VULNERABLE_SBOM, advisories=first).returncode == 1  # the rest still fail
    assert live_rescan(tmp_path, VULNERABLE_SBOM, advisories=",".join(sorted(found))).returncode == 0


@live
def test_live_an_sbom_with_nothing_in_it_passes(tmp_path):
    assert live_rescan(tmp_path, CLEAN_SBOM).returncode == 0
