"""Publish order and Rekor handling in container-release.yml (issue #286).

Background: two caller releases failed in `Publish, sign` on a Rekor 409
(`an equivalent entry already exists`) from the Docker Hub `cosign sign`. The
sign loop was `set -e`, so the SBOM attestation and provenance never ran, but
the real tags (`latest` included) had already been pushed: a published,
unattested image. These tests pin three rules:

1. Nothing mutable moves until the image is signed, attested and verified.
2. A 409 equivalent-entry conflict counts as success only when `cosign verify`
   (or `verify-attestation`) of that exact digest passes with the identity,
   issuer and repository constraints; any other error is fatal.
3. Transient errors are retried a bounded number of times, never forever.

The step scripts run for real, with a stub `cosign` and `docker` on PATH.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest
from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

RELEASE = WORKFLOWS / "container-release.yml"
DIGEST = "sha256:" + "ab" * 32
IDENTITY = r"^https://github.com/ChiefGyk3D/git-your-ship-together/\.github/workflows/container-release\.yml@"
ISSUER = "https://token.actions.githubusercontent.com"
REPO = "ChiefGyk3D/Star-Daemon"
CONFLICT = (
    "Error: signing [x]: signing bundle: [POST /api/v1/log/entries][409] createLogEntryConflict "
    '{"message":"an equivalent entry already exists in the transparency log"}'
)
TRANSIENT = "Error: signing: [POST /api/v1/log/entries][503] createLogEntryServiceUnavailable"


def merge_steps() -> list[dict]:
    return list(steps_of(jobs(load(RELEASE))["merge"]))


def step(name: str) -> dict:
    found = [s for s in merge_steps() if s.get("name") == name]
    assert len(found) == 1, (name, len(found))
    return found[0]


def names() -> list[str]:
    return [s.get("name", "") for s in merge_steps()]


# --- order -----------------------------------------------------------------


def test_the_mutable_tags_move_only_after_sign_attest_provenance_and_verify():
    order = [
        "Create the multi-arch index",
        "Sign the image (keyless)",
        "Generate the SBOM with syft",
        "Attach the SBOM as a cosign attestation",
        "Record build provenance",
        "Verify the image before publishing the tags",
        "Publish the release tags",
    ]
    found = names()
    for name in order:
        assert name in found, f"merge step {name!r} is missing"
    assert [n for n in found if n in order] == order


def test_the_first_push_carries_no_release_tag():
    """The index is created under an immutable staging tag only; `latest` and the other tags come last."""
    index = step("Create the multi-arch index")
    assert "TAGS" not in index.get("env", {}), "the real tags must not be pushed with the staging index"
    assert "steps.meta.outputs.tags" not in str(index)
    script = index["run"]
    assert "${GHCR}:${SHA}" in script and "${DOCKERHUB}:${SHA}" in script, "staging tag on both registries"
    publish = step("Publish the release tags")
    assert publish["env"]["TAGS"] == "${{ steps.meta.outputs.tags }}"
    assert "${GHCR}@${DIGEST}" in publish["run"], "tags are applied to the signed digest, not to a rebuilt image"


def test_only_the_publish_step_pushes_real_tags():
    quiet = ("Image metadata", "Summary")
    mentions = [s["name"] for s in merge_steps() if "steps.meta.outputs.tags" in str(s) and s["name"] not in quiet]
    assert mentions == ["Publish the release tags"]


# --- the helper and the signing steps, run for real --------------------------


def make_stubs(tmp_path: Path) -> Path:
    stub = tmp_path / "stub"
    stub.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    tool = (
        "#!/bin/bash\n"
        'name=$(basename "$0")\n'
        'echo "$name $*" >> "$STUB/calls"\n'
        'sub="$1"\n'
        'prefix="$name $sub "\n'
        'if [ "$name" = docker ]; then sub="$3"; prefix="docker buildx imagetools $sub "; fi\n'
        'n=$(grep -c "^$prefix" "$STUB/calls")\n'
        'f="$STUB/$sub.$n"; [ -f "$f.rc" ] || f="$STUB/$sub.default"\n'
        '[ -f "$f.out" ] && cat "$f.out"\n'
        '[ -f "$f.rc" ] && exit "$(cat "$f.rc")"\n'
        "exit 0\n"
    )
    for tool_name in ("cosign", "docker"):
        path = bindir / tool_name
        path.write_text(tool)
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return stub


def script(stub: Path, sub: str, n: str, rc: int, out: str = "") -> None:
    (stub / f"{sub}.{n}.rc").write_text(str(rc))
    (stub / f"{sub}.{n}.out").write_text(out + ("\n" if out else ""))


def calls(stub: Path, prefix: str) -> list[str]:
    file = stub / "calls"
    if not file.exists():
        return []
    return [line for line in file.read_text().splitlines() if line.startswith(prefix)]


def run_step(tmp_path: Path, name: str, stub: Path, **env: str) -> subprocess.CompletedProcess:
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir(exist_ok=True)
    base = {
        "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}",
        "STUB": str(stub),
        "RUNNER_TEMP": str(runner_temp),
        "GITHUB_OUTPUT": str(tmp_path / "out"),
        "REKOR_BACKOFF_SECONDS": "0",
        "GHCR": "ghcr.io/o/r",
        "DOCKERHUB": "docker.io/u/r",
        "DIGEST": DIGEST,
        "IDENTITY_REGEXP": IDENTITY,
        "OIDC_ISSUER": ISSUER,
        "SOURCE_REPOSITORY": REPO,
    }
    if not (runner_temp / "rekor-run.sh").exists():
        prep = step("Prepare the Rekor retry helper")
        done = subprocess.run(["bash", "-c", prep["run"]], env={**base, **env}, capture_output=True, text=True)
        assert done.returncode == 0, done.stdout + done.stderr
    return subprocess.run(["bash", "-c", step(name)["run"]], env={**base, **env}, capture_output=True, text=True)


SIGN = "Sign the image (keyless)"
ATTEST = "Attach the SBOM as a cosign attestation"


@pytest.fixture
def stub(tmp_path: Path) -> Path:
    return make_stubs(tmp_path)


def test_a_clean_sign_runs_once_per_registry_and_verifies_nothing(tmp_path, stub):
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert calls(stub, "cosign sign") == [
        f"cosign sign --yes ghcr.io/o/r@{DIGEST}",
        f"cosign sign --yes docker.io/u/r@{DIGEST}",
    ]
    assert calls(stub, "cosign verify") == []


def test_a_409_is_success_only_after_a_constrained_verify_of_that_digest(tmp_path, stub):
    script(stub, "sign", "2", 1, CONFLICT)  # the Docker Hub sign
    script(stub, "verify", "1", 0)
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    verify = calls(stub, "cosign verify ")
    assert len(verify) == 1
    line = verify[0]
    assert f"docker.io/u/r@{DIGEST}" in line
    assert f"--certificate-identity-regexp {IDENTITY}" in line
    assert f"--certificate-oidc-issuer {ISSUER}" in line
    assert f"--certificate-github-workflow-repository {REPO}" in line
    assert len(calls(stub, "cosign sign")) == 2, "a conflict is not retried"


def test_a_409_whose_verify_fails_stays_fatal(tmp_path, stub):
    script(stub, "sign", "1", 1, CONFLICT)
    script(stub, "verify", "1", 1, "Error: no matching signatures")
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode != 0
    assert "::error" in done.stdout
    assert len(calls(stub, "cosign sign")) == 1, "nothing after the failed image is signed or trusted"
    assert len(calls(stub, "cosign verify ")) == 1


@pytest.mark.parametrize("missing", ["IDENTITY_REGEXP", "OIDC_ISSUER", "SOURCE_REPOSITORY"])
def test_a_409_is_never_verified_without_every_constraint(tmp_path, stub, missing):
    """An empty identity regexp matches everything: the guard must refuse to run an unconstrained verify."""
    script(stub, "sign", "1", 1, CONFLICT)
    script(stub, "verify", "default", 0)
    done = run_step(tmp_path, SIGN, stub, **{missing: ""})
    assert done.returncode != 0, "an unconstrained verify must not turn a conflict into success"
    assert calls(stub, "cosign verify ") == []


def test_a_409_without_the_equivalent_entry_message_is_fatal(tmp_path, stub):
    script(stub, "sign", "1", 1, "Error: [POST /api/v1/log/entries][409] createLogEntryConflict {}")
    script(stub, "verify", "default", 0)
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode != 0
    assert calls(stub, "cosign verify ") == []


@pytest.mark.parametrize("err", ["Error: UNAUTHORIZED: authentication required", "Error: [POST][400] bad request"])
def test_any_other_error_is_fatal_on_the_first_attempt(tmp_path, stub, err):
    script(stub, "sign", "default", 1, err)
    script(stub, "verify", "default", 0)
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode != 0
    assert len(calls(stub, "cosign sign")) == 1
    assert calls(stub, "cosign verify ") == []


def test_a_transient_error_is_retried_then_succeeds(tmp_path, stub):
    script(stub, "sign", "1", 1, TRANSIENT)
    script(stub, "sign", "2", 1, "Error: signing: context deadline exceeded")
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(calls(stub, "cosign sign")) == 4, "2 failed + 1 ok for ghcr, then 1 ok for Docker Hub"


def test_retries_are_capped(tmp_path, stub):
    script(stub, "sign", "default", 1, TRANSIENT)
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode != 0
    assert len(calls(stub, "cosign sign")) == 4, "exactly 4 attempts, never forever"
    assert calls(stub, "cosign verify ") == []


def test_a_retry_that_hits_a_conflict_is_verified(tmp_path, stub):
    """The first attempt reached Rekor but the reply was lost: the retry then sees the entry."""
    script(stub, "sign", "1", 1, TRANSIENT)
    script(stub, "sign", "2", 1, CONFLICT)
    script(stub, "verify", "1", 0)
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(calls(stub, "cosign verify ")) == 1


def test_the_sbom_attestation_gets_the_same_treatment(tmp_path, stub):
    script(stub, "attest", "1", 1, CONFLICT)
    script(stub, "verify-attestation", "1", 0)
    done = run_step(tmp_path, ATTEST, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    verify = calls(stub, "cosign verify-attestation")
    assert len(verify) == 1
    assert "--type spdxjson" in verify[0] and f"ghcr.io/o/r@{DIGEST}" in verify[0]
    assert f"--certificate-identity-regexp {IDENTITY}" in verify[0]
    assert f"--certificate-oidc-issuer {ISSUER}" in verify[0]
    assert f"--certificate-github-workflow-repository {REPO}" in verify[0]
    assert calls(stub, "cosign verify ") == [], "the signature verify is not a stand-in for the attestation"


def test_a_conflict_on_attest_with_a_failing_verify_stays_fatal(tmp_path, stub):
    script(stub, "attest", "1", 1, CONFLICT)
    script(stub, "verify-attestation", "default", 1)
    done = run_step(tmp_path, ATTEST, stub)
    assert done.returncode != 0
    assert len(calls(stub, "cosign attest")) == 1


def test_the_steps_receive_the_constraints_from_the_workflow():
    for name in (SIGN, ATTEST, "Verify the image before publishing the tags"):
        env = step(name)["env"]
        assert env["IDENTITY_REGEXP"] == "${{ inputs.signer-identity-regexp }}"
        assert env["OIDC_ISSUER"] == "https://token.actions.githubusercontent.com"
        assert env["SOURCE_REPOSITORY"] == "${{ github.repository }}"


# --- the final verify and the tag move ---------------------------------------


VERIFY = "Verify the image before publishing the tags"
PUBLISH = "Publish the release tags"


def test_the_final_verify_checks_signature_and_sbom_on_every_registry(tmp_path, stub):
    done = run_step(tmp_path, VERIFY, stub, SIGN="true", SBOM="true")
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(calls(stub, "cosign verify ")) == 2
    assert len(calls(stub, "cosign verify-attestation")) == 2
    for line in calls(stub, "cosign verify"):
        assert f"--certificate-identity-regexp {IDENTITY}" in line
        assert f"--certificate-github-workflow-repository {REPO}" in line


def test_a_failed_final_verify_fails_the_step_so_the_tags_never_move(tmp_path, stub):
    script(stub, "verify", "default", 1, "Error: no matching signatures")
    done = run_step(tmp_path, VERIFY, stub, SIGN="true", SBOM="false")
    assert done.returncode != 0
    assert "::error" in done.stdout
    jobs_steps = names()
    assert jobs_steps.index(VERIFY) < jobs_steps.index(PUBLISH)
    assert "if" not in step(PUBLISH) or "always()" not in str(step(PUBLISH)["if"]), (
        "publish must not run after a failure"
    )


def test_the_tags_are_applied_to_the_signed_digest_and_checked(tmp_path, stub):
    (stub / "inspect.default.out").write_text(DIGEST + "\n")
    done = run_step(tmp_path, PUBLISH, stub, TAGS="ghcr.io/o/r:latest\ndocker.io/u/r:latest")
    assert done.returncode == 0, done.stdout + done.stderr
    create = calls(stub, "docker buildx imagetools create")
    assert len(create) == 1
    assert f"--tag ghcr.io/o/r:latest --tag docker.io/u/r:latest ghcr.io/o/r@{DIGEST}" in create[0]


def test_a_tag_that_lands_on_another_digest_fails_the_job(tmp_path, stub):
    (stub / "inspect.default.out").write_text("sha256:" + "cd" * 32 + "\n")
    done = run_step(tmp_path, PUBLISH, stub, TAGS="ghcr.io/o/r:latest")
    assert done.returncode != 0
    assert "::error" in done.stdout


def test_no_tags_is_an_error(tmp_path, stub):
    done = run_step(tmp_path, PUBLISH, stub, TAGS="")
    assert done.returncode != 0
    assert calls(stub, "docker buildx imagetools create") == []


# --- the input -----------------------------------------------------------------


def test_the_signer_identity_input_defaults_to_the_reusable_workflow_and_is_forwarded():
    inputs = triggers(load(RELEASE))["workflow_call"]["inputs"]
    default = inputs["signer-identity-regexp"]["default"]
    assert default == IDENTITY, "must name this workflow file, not just the owner"
    assert inputs["signer-identity-regexp"]["type"] == "string"
    thin = jobs(load(WORKFLOWS / "python-docker-release.yml"))["release"]["with"]
    assert thin["signer-identity-regexp"] == "${{ inputs.signer-identity-regexp }}"
