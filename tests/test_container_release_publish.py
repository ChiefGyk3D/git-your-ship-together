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

import json
import os
import stat
import subprocess
from pathlib import Path

import pytest
from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

RELEASE = WORKFLOWS / "container-release.yml"
DIGEST = "sha256:" + "ab" * 32
IDENTITY = r"^https://github\.com/ChiefGyk3D/git-your-ship-together/\.github/workflows/container-release\.yml@"
ISSUER = "https://token.actions.githubusercontent.com"
REPO = "ChiefGyk3D/Star-Daemon"
SHA = "1234567890abcdef1234567890abcdef12345678"
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


COSIGN_STUB = (
    "#!/bin/bash\n"
    'echo "cosign $*" >> "$STUB/calls"\n'
    'sub="$1"\n'
    'n=$(grep -c "^cosign $sub " "$STUB/calls")\n'
    'f="$STUB/$sub.$n"; [ -f "$f.rc" ] || f="$STUB/$sub.default"\n'
    '[ -f "$f.out" ] && cat "$f.out"\n'
    '[ -f "$f.rc" ] && exit "$(cat "$f.rc")"\n'
    "exit 0\n"
)

DOCKER_STUB = (
    "#!/bin/bash\n"
    'echo "docker $*" >> "$STUB/calls"\n'
    'case " $* " in *" --raw "*) [ -f "$STUB/raw.json" ] && cat "$STUB/raw.json"; exit 0;; esac\n'
    'if [ "$3" = create ]; then\n'
    '  prev=""\n'
    '  for a in "$@"; do\n'
    '    if [ "$prev" = --metadata-file ] && [ -f "$STUB/meta.json" ]; then cp "$STUB/meta.json" "$a"; fi\n'
    "    prev=$a\n"
    "  done\n"
    '  [ -f "$STUB/create.rc" ] && exit "$(cat "$STUB/create.rc")"\n'
    "  exit 0\n"
    "fi\n"
    '[ -f "$STUB/inspect.default.out" ] && cat "$STUB/inspect.default.out"\n'
    "exit 0\n"
)


def make_stubs(tmp_path: Path) -> Path:
    stub = tmp_path / "stub"
    stub.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool_name, text in (("cosign", COSIGN_STUB), ("docker", DOCKER_STUB)):
        path = bindir / tool_name
        path.write_text(text)
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


TIMEOUT = 30  # seconds; a loop that lost its cap raises TimeoutExpired, which fails the test


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
        "WORKFLOW_SHA": SHA,
    }
    if name in (SIGN, ATTEST) and not (runner_temp / "rekor-run.sh").exists():
        prep = step("Prepare the Rekor retry helper")
        done = subprocess.run(
            ["bash", "-c", prep["run"]], env={**base, **env}, capture_output=True, text=True, timeout=TIMEOUT
        )
        assert done.returncode == 0, done.stdout + done.stderr
    return subprocess.run(
        ["bash", "-c", step(name)["run"]], env={**base, **env}, capture_output=True, text=True, timeout=TIMEOUT
    )


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
    assert f"--certificate-github-workflow-sha {SHA}" in line
    assert len(calls(stub, "cosign sign")) == 2, "a conflict is not retried"


def test_a_409_whose_verify_fails_stays_fatal(tmp_path, stub):
    script(stub, "sign", "1", 1, CONFLICT)
    script(stub, "verify", "1", 1, "Error: no matching signatures")
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode != 0
    assert "::error" in done.stdout
    assert len(calls(stub, "cosign sign")) == 1, "nothing after the failed image is signed or trusted"
    assert len(calls(stub, "cosign verify ")) == 1


@pytest.mark.parametrize("missing", ["IDENTITY_REGEXP", "OIDC_ISSUER", "SOURCE_REPOSITORY", "WORKFLOW_SHA"])
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
    assert f"--certificate-github-workflow-sha {SHA}" in verify[0]
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
        assert env["WORKFLOW_SHA"] == "${{ github.sha }}"


# --- the final verify and the tag move ---------------------------------------


VERIFY = "Verify the image before publishing the tags"
PUBLISH = "Publish the release tags"
SIGNED = {"SIGN": "true", "SBOM": "true", "PROVENANCE": "true", "ALLOW_UNSIGNED": "false"}


def test_the_final_verify_checks_signature_and_sbom_on_every_registry(tmp_path, stub):
    done = run_step(tmp_path, VERIFY, stub, SIGN="true", SBOM="true")
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(calls(stub, "cosign verify ")) == 2
    assert len(calls(stub, "cosign verify-attestation")) == 2
    for line in calls(stub, "cosign verify"):
        assert f"--certificate-identity-regexp {IDENTITY}" in line
        assert f"--certificate-github-workflow-repository {REPO}" in line
        assert f"--certificate-github-workflow-sha {SHA}" in line
    assert f"--certificate-github-workflow-sha {SHA}" in line


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
    done = run_step(tmp_path, PUBLISH, stub, **SIGNED, TAGS="ghcr.io/o/r:latest\ndocker.io/u/r:latest")
    assert done.returncode == 0, done.stdout + done.stderr
    create = calls(stub, "docker buildx imagetools create")
    assert len(create) == 1
    assert f"--tag ghcr.io/o/r:latest --tag docker.io/u/r:latest ghcr.io/o/r@{DIGEST}" in create[0]


def test_a_tag_that_lands_on_another_digest_fails_the_job(tmp_path, stub):
    (stub / "inspect.default.out").write_text("sha256:" + "cd" * 32 + "\n")
    done = run_step(tmp_path, PUBLISH, stub, **SIGNED, TAGS="ghcr.io/o/r:latest")
    assert done.returncode != 0
    assert "::error" in done.stdout


def test_no_tags_is_an_error(tmp_path, stub):
    done = run_step(tmp_path, PUBLISH, stub, **SIGNED, TAGS="")
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


# --- the index: built from digests, pushed under the staging tag only ----------

INDEX = "Create the multi-arch index"
AMD = "sha256:" + "11" * 32
ARM = "sha256:" + "22" * 32
INDEX_DIGEST = "sha256:" + "33" * 32


def seed_digests(tmp_path: Path, stub: Path, amd: str = AMD, arm: str = ARM, listed: tuple[str, ...] | None = None):
    base = tmp_path / "runner" / "image-digests"
    for arch, digest in (("linux-amd64", amd), ("linux-arm64", arm)):
        d = base / f"image-digest-{arch}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "digest.txt").write_text(digest + "\n")
    (stub / "meta.json").write_text(json.dumps({"containerimage.digest": INDEX_DIGEST}))
    manifests = [{"digest": x} for x in (listed if listed is not None else (amd, arm))]
    (stub / "raw.json").write_text(json.dumps({"manifests": manifests}))


def run_index(tmp_path: Path, stub: Path, **env: str) -> subprocess.CompletedProcess:
    runner = tmp_path / "runner"
    runner.mkdir(exist_ok=True)
    defaults = {
        "PLATFORMS": "linux/amd64,linux/arm64",
        "SHA": SHA,
        "DIGESTS": str(runner / "image-digests"),
        "META": str(runner / "index-metadata.json"),
    }
    return run_step(tmp_path, INDEX, stub, **{**defaults, **env})


def test_the_index_is_built_from_digests_and_pushed_only_under_the_staging_tag(tmp_path, stub):
    seed_digests(tmp_path, stub)
    done = run_index(tmp_path, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    create = calls(stub, "docker buildx imagetools create")
    assert len(create) == 1
    words = create[0].split()
    tag_values = [words[i + 1] for i, w in enumerate(words) if w == "--tag"]
    assert sorted(tag_values) == sorted([f"ghcr.io/o/r:{SHA}", f"docker.io/u/r:{SHA}"])
    sources = [w for w in words if w.startswith("ghcr.io/o/r@")]
    assert sorted(sources) == sorted([f"ghcr.io/o/r@{AMD}", f"ghcr.io/o/r@{ARM}"])
    assert "latest" not in create[0]
    assert f"digest={INDEX_DIGEST}" in (tmp_path / "out").read_text()


def test_the_index_digest_comes_from_the_create_result_not_from_a_tag_lookup(tmp_path, stub):
    seed_digests(tmp_path, stub)
    (stub / "inspect.default.out").write_text("sha256:" + "ee" * 32 + "\n")  # what a tag lookup would answer
    done = run_index(tmp_path, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"digest={INDEX_DIGEST}" in (tmp_path / "out").read_text()
    assert not [c for c in calls(stub, "docker") if f":{SHA} " in c and " inspect " in c]


@pytest.mark.parametrize("bad", ["", "latest", "sha256:abc", "sha256:" + "G" * 64, '{"x":1}'])
def test_an_unusable_index_digest_in_the_create_result_fails(tmp_path, stub, bad):
    seed_digests(tmp_path, stub)
    (stub / "meta.json").write_text(json.dumps({"containerimage.digest": bad}))
    done = run_index(tmp_path, stub)
    assert done.returncode != 0
    out = tmp_path / "out"
    assert not out.exists() or "digest=" not in out.read_text()


def test_an_index_that_lists_other_manifests_fails(tmp_path, stub):
    seed_digests(tmp_path, stub, listed=(AMD, "sha256:" + "44" * 32))
    done = run_index(tmp_path, stub)
    assert done.returncode != 0
    assert "::error" in done.stdout


@pytest.mark.parametrize("bad", ["", "not-a-digest", "sha256:" + "1" * 63])
def test_a_bad_recorded_platform_digest_fails_before_anything_is_pushed(tmp_path, stub, bad):
    seed_digests(tmp_path, stub, arm=bad)
    done = run_index(tmp_path, stub)
    assert done.returncode != 0
    assert calls(stub, "docker buildx imagetools create") == []


def test_a_missing_platform_digest_fails_before_anything_is_pushed(tmp_path, stub):
    seed_digests(tmp_path, stub)
    (tmp_path / "runner" / "image-digests" / "image-digest-linux-arm64" / "digest.txt").unlink()
    done = run_index(tmp_path, stub)
    assert done.returncode != 0
    assert calls(stub, "docker buildx imagetools create") == []


def test_the_build_hands_each_platform_digest_to_the_merge_job():
    build = {s.get("name"): s for s in steps_of(jobs(load(RELEASE))["build"])}
    record = build["Record this platform's image digest"]
    assert record["env"]["DIGEST"] == "${{ steps.push.outputs.digest }}"
    assert "sha256:[0-9a-f]{64}" in record["run"]
    up = build["Hand the digest to the merge job"]
    assert str(up["uses"]).startswith("actions/upload-artifact@")
    assert up["with"]["name"] == "image-digest-${{ matrix.arch }}"
    order = [s.get("name") for s in steps_of(jobs(load(RELEASE))["build"])]
    assert order.index("Build and push this platform's image") < order.index(record["name"]) < order.index(up["name"])
    fetch = step("Fetch the per-platform digests")
    assert str(fetch["uses"]).startswith("actions/download-artifact@")
    assert names().index(fetch["name"]) < names().index(INDEX)


def test_one_publish_per_destination_and_ref_at_a_time_and_never_cancelled():
    merge = jobs(load(RELEASE))["merge"]
    group = merge["concurrency"]["group"]
    assert "needs.plan.outputs.ghcr" in group
    assert "github.ref" in group
    assert "github.sha" not in group, "runs of one ref must queue, not race, whatever their commit"
    assert "inputs.dockerhub" in group and "inputs.dockerhub-repository" in group
    assert merge["concurrency"]["cancel-in-progress"] is False


def test_the_merge_job_never_runs_on_either_pull_request_event():
    cond = str(jobs(load(RELEASE))["merge"]["if"])
    assert "github.event_name != 'pull_request'" in cond
    assert "github.event_name != 'pull_request_target'" in cond
    assert "inputs.push" in cond


def test_the_build_pushes_only_the_per_platform_tag_and_needs_the_plan():
    build = jobs(load(RELEASE))["build"]
    push = {s.get("name"): s for s in steps_of(build)}["Build and push this platform's image"]
    tags = [t for t in str(push["with"]["tags"]).splitlines() if t.strip()]
    assert tags == ["${{ needs.plan.outputs.ghcr }}:${{ github.sha }}-${{ matrix.arch }}"]
    assert push["with"]["push"] is True
    assert "needs.plan.result == 'success'" in str(build["if"])


def test_the_digest_download_is_this_runs_own_artifacts_only():
    fetch = step("Fetch the per-platform digests")
    assert set(fetch["with"]) == {"pattern", "path"}, "no run-id, github-token or repository input"
    assert fetch["with"]["pattern"] == "image-digest-*"
    assert "if" not in fetch or fetch["if"] == "inputs.push"


# --- the signer identity must be a strict, anchored, literal value ----------------

VALIDATE = "Validate the signer identity"


def run_validate(tmp_path: Path, value: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", "-c", step(VALIDATE)["run"]],
        env={"PATH": os.environ["PATH"], "IDENTITY_REGEXP": value},
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )


def test_the_default_signer_identity_passes_the_validator(tmp_path):
    default = triggers(load(RELEASE))["workflow_call"]["inputs"]["signer-identity-regexp"]["default"]
    assert run_validate(tmp_path, default).returncode == 0
    assert (
        run_validate(tmp_path, r"^https://github\.com/Some-Fork/my_fork/\.github/workflows/release\.yml@").returncode
        == 0
    )


BAD_IDENTITIES = [
    "",
    ".*",
    "^.*",
    "|x",
    r"^.*@",
    r"^https://github\.com/.*",
    r"^https://github\.com/o/r/\.github/workflows/x\.yml@.*",
    r"^https://github\.com/o/r/\.github/workflows/x\.yml@|^https://evil/",
    r"^https://github\.com/o|p/r/\.github/workflows/x\.yml@",
    r"^https://github.com/o/r/\.github/workflows/x\.yml@",  # unescaped dot
    r"https://github\.com/o/r/\.github/workflows/x\.yml@",  # unanchored
    r"^https://github\.com/o/r/\.github/workflows/x\.yml",  # no trailing @
    r"^https://github\.com/o/r/\.github/workflows/x\.yml@$",
    r"^https://github\.com/o/r/\.github/workflows/(x|y)\.yml@",
    r"^https://github\.com/o/r/\.github/workflows/[a-z]+\.yml@",
    r"^https://github\.com/o/r/\.github/workflows/x\.yml@v1" + "\n.*",
    r"^https://github\.com/o/r/blob/x\.yml@",
]


@pytest.mark.parametrize("value", BAD_IDENTITIES)
def test_the_validator_rejects_loose_identities(tmp_path, value):
    done = run_validate(tmp_path, value)
    assert done.returncode != 0, value
    assert "::error" in done.stdout


def job_step(job: str, name: str) -> dict:
    found = [s for s in steps_of(jobs(load(RELEASE))[job]) if s.get("name") == name]
    assert len(found) == 1, (job, name)
    return found[0]


def test_the_validator_runs_in_the_plan_before_any_build_leg_and_is_rechecked_in_merge():
    doc = load(RELEASE)
    assert "plan" in doc["jobs"]["build"]["needs"]
    for job in ("plan", "merge"):
        validator = job_step(job, VALIDATE)
        assert validator["env"]["IDENTITY_REGEXP"] == "${{ inputs.signer-identity-regexp }}"
        assert "if" not in validator, f"the {job} validator must run on every event"
        assert "continue-on-error" not in validator
    assert job_step("plan", VALIDATE)["run"] == job_step("merge", VALIDATE)["run"]
    assert names().index(VALIDATE) < names().index(INDEX)


# --- unsigned publishes need an explicit opt-in -----------------------------------

REQUIRE = "Require signing for a publish"


def run_require(step_: dict, **env: str) -> subprocess.CompletedProcess:
    full = {"PATH": os.environ["PATH"], **env}
    return subprocess.run(["bash", "-c", step_["run"]], env=full, capture_output=True, text=True, timeout=TIMEOUT)


def plan_require() -> dict:
    found = [s for s in steps_of(jobs(load(RELEASE))["plan"]) if s.get("name") == REQUIRE]
    assert len(found) == 1
    return found[0]


@pytest.mark.parametrize("off", ["SIGN", "SBOM", "PROVENANCE"])
def test_a_push_with_signing_off_fails_early_unless_allowed(off):
    on = {"PUSH": "true", "SIGN": "true", "SBOM": "true", "PROVENANCE": "true", "ALLOW_UNSIGNED": "false"}
    assert run_require(plan_require(), **on).returncode == 0
    refused = run_require(plan_require(), **{**on, off: "false"})
    assert refused.returncode != 0 and "::error" in refused.stdout
    assert run_require(plan_require(), **{**on, off: "false", "ALLOW_UNSIGNED": "true"}).returncode == 0
    assert run_require(plan_require(), **{**on, off: "false", "PUSH": "false"}).returncode == 0


@pytest.mark.parametrize("off", ["SIGN", "SBOM", "PROVENANCE"])
def test_the_tags_do_not_move_with_signing_off_unless_allowed(tmp_path, stub, off):
    (stub / "inspect.default.out").write_text(DIGEST + "\n")
    env = {**SIGNED, off: "false"}
    done = run_step(tmp_path, PUBLISH, stub, **{**env, "TAGS": "ghcr.io/o/r:latest"})
    assert done.returncode != 0 and "::error" in done.stdout
    assert calls(stub, "docker buildx imagetools create") == []
    ok = run_step(tmp_path, PUBLISH, stub, **{**env, "ALLOW_UNSIGNED": "true", "TAGS": "ghcr.io/o/r:latest"})
    assert ok.returncode == 0, ok.stdout + ok.stderr


def test_the_plan_signing_check_has_no_condition():
    check = plan_require()
    assert "if" not in check and "continue-on-error" not in check


def test_unsigned_publish_is_off_by_default_and_forwarded():
    inputs = triggers(load(RELEASE))["workflow_call"]["inputs"]
    assert inputs["allow-unsigned-publish"]["default"] is False
    thin = jobs(load(WORKFLOWS / "python-docker-release.yml"))["release"]["with"]
    assert thin["allow-unsigned-publish"] == "${{ inputs.allow-unsigned-publish }}"


# --- the gates themselves cannot be switched off -----------------------------------


def test_the_signing_steps_are_gated_exactly_on_their_inputs():
    assert step(SIGN)["if"] == "inputs.push && inputs.sign"
    assert step(ATTEST)["if"] == "inputs.push && inputs.sbom"
    assert step("Generate the SBOM with syft")["if"] == "inputs.push && inputs.sbom"
    assert step("Record build provenance")["if"] == "inputs.push && inputs.provenance"
    assert step(VERIFY)["if"] == "inputs.push && (inputs.sign || inputs.sbom)"
    assert step(PUBLISH)["if"] == "inputs.push"


def test_no_merge_step_is_disabled_by_a_constant_condition():
    for s in merge_steps():
        cond = str(s.get("if", "true")).strip().lower()
        assert cond not in ("false", "${{ false }}", "0", ""), s.get("name")
        assert not s.get("continue-on-error"), s.get("name")


def test_the_verify_step_runs_before_the_tags_and_after_the_provenance():
    order = names()
    assert order.index("Record build provenance") < order.index(VERIFY) < order.index(PUBLISH)


@pytest.mark.parametrize("empty", ["OIDC_ISSUER", "IDENTITY_REGEXP", "SOURCE_REPOSITORY", "WORKFLOW_SHA"])
def test_the_verify_step_refuses_an_empty_constraint(tmp_path, stub, empty):
    done = run_step(tmp_path, VERIFY, stub, SIGN="true", SBOM="true", **{empty: ""})
    assert done.returncode == 1
    assert calls(stub, "cosign") == []


def test_no_loop_word_splits_the_image_names():
    for s in merge_steps():
        assert "for image in $" not in s.get("run", ""), s.get("name")
