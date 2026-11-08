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
    assert "stage-${SHA}-${RUN_ID}-${RUN_ATTEMPT}" in script, "an immutable, run-scoped staging tag"
    assert 'registries+=("$HUB")' in script, "staging tag on both registries"
    publish = step("Publish the release tags")
    assert publish["env"]["TAGS"] == "${{ steps.meta.outputs.tags }}"
    assert '"${repo}@${DIGEST}"' in publish["run"], "tags are applied to the signed digest, not to a rebuilt image"


INDEX = "Create the multi-arch index"
WORKFLOW_TEXT = RELEASE.read_text()


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


GH_STUB = (
    "#!/bin/bash\n"
    'echo "gh $*" >> "$STUB/calls"\n'
    # Answers may change from one call to the next: gh.tags.N / gh.out.N answer the Nth
    # lookup of the release tags / the branch head; without one the plain file answers.
    'case " $* " in *matching-refs*)\n'
    '  n=$(grep -c "^gh api.*matching-refs" "$STUB/calls")\n'
    '  f="$STUB/gh.tags"; [ -f "$f.$n" ] && f="$f.$n"\n'
    '  r="$STUB/gh.tags.rc"; [ -f "$r.$n" ] && r="$r.$n"\n'
    '  [ -f "$r" ] && { echo "gh: Not Found (HTTP 404)" >&2; exit "$(cat "$r")"; }\n'
    '  [ -f "$f" ] && cat "$f"; exit 0;;\n'
    "esac\n"
    'n=$(grep -c "^gh api.*commits" "$STUB/calls")\n'
    'f="$STUB/gh.out"; [ -f "$f.$n" ] && f="$f.$n"\n'
    '[ -f "$f" ] && cat "$f"\n'
    '[ -f "$STUB/gh.rc" ] && exit "$(cat "$STUB/gh.rc")"\n'
    "exit 0\n"
)


def make_stubs(tmp_path: Path) -> Path:
    stub = tmp_path / "stub"
    stub.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool_name, text in (("cosign", COSIGN_STUB), ("docker", DOCKER_STUB), ("gh", GH_STUB)):
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
        "REGISTRY_BACKOFF_SECONDS": "0",
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


# --- the final verify -------------------------------------------------------


VERIFY = "Verify the image before publishing the tags"
PUBLISH = "Publish the release tags"
SIGNED = {
    "SIGN": "true",
    "SBOM": "true",
    "PROVENANCE": "true",
    "ALLOW_UNSIGNED": "false",
    "REF": "refs/tags/v1.0.0",
    "REPOSITORY": REPO,
    "GH_TOKEN": "stub",
    "HUB": "docker.io/u/r",
}


def test_the_final_verify_checks_signature_and_sbom_on_every_registry(tmp_path, stub):
    done = run_step(tmp_path, VERIFY, stub, SIGN="true", SBOM="true")
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(calls(stub, "cosign verify ")) == 2
    assert len(calls(stub, "cosign verify-attestation")) == 2
    for line in calls(stub, "cosign verify"):
        assert f"--certificate-identity-regexp {IDENTITY}" in line
        assert f"--certificate-github-workflow-repository {REPO}" in line
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


# --- the Rekor retry matcher covers every 5xx --------------------------------


def rekor_error(status: int) -> str:
    return f"Error: signing: [POST /api/v1/log/entries][{status}] createLogEntryDefault"


@pytest.mark.parametrize("status", [408, 425, 429, 500, 501, 502, 503, 504, 507, 599])
def test_every_documented_transient_status_is_retried(tmp_path, stub, status):
    script(stub, "sign", "1", 1, rekor_error(status))
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(calls(stub, "cosign sign")) == 3, "one retry for ghcr, then one call for Docker Hub"


@pytest.mark.parametrize("status", [400, 401, 403, 404, 600])
def test_other_statuses_are_not_retried(tmp_path, stub, status):
    script(stub, "sign", "default", 1, rekor_error(status))
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode != 0
    assert len(calls(stub, "cosign sign")) == 1


def test_a_409_without_the_equivalent_entry_text_is_neither_retried_nor_verified(tmp_path, stub):
    script(stub, "sign", "default", 1, rekor_error(409))
    done = run_step(tmp_path, SIGN, stub)
    assert done.returncode != 0
    assert len(calls(stub, "cosign sign")) == 1 and calls(stub, "cosign verify ") == []


def test_the_documented_retry_contract_matches_the_matcher():
    text = (WORKFLOWS.parent.parent / "README.md").read_text() + (
        WORKFLOWS.parent.parent / "docs" / "wiki" / "Workflow-container-release.md"
    ).read_text()
    assert "408, 425, 429 and every 5xx" in text


# --- a fake registry for the tag step ----------------------------------------

REGISTRY_STUB = r"""#!/usr/bin/env python3
import json, os, sys
path = os.path.join(os.environ["STUB"], "reg.json")
reg = json.load(open(path))
args = sys.argv[1:]
open(os.path.join(os.environ["STUB"], "calls"), "a").write("docker " + " ".join(args) + "\n")


def save():
    json.dump(reg, open(path, "w"))


TRANSIENT_ERR = "ERROR: unexpected status from request to the registry: 503 Service Unavailable"


def inspect(ref):
    k = reg.setdefault("inspects", {}).get(ref, 0) + 1
    reg["inspects"][ref] = k
    if k in reg.get("transient_inspect", {}).get(ref, []):
        save()
        print(TRANSIENT_ERR, file=sys.stderr)
        sys.exit(1)
    save()
    if ref in reg.get("unreadable", []):
        print("ERROR: unauthorized: authentication required", file=sys.stderr)
        sys.exit(1)
    if "@" in ref:
        if ref in reg["known"]:
            print(ref.split("@")[1])
            return
    elif ref in reg["tags"]:
        value = reg["tags"][ref]
        # Another publisher acts right after this read answered: the interleaving a
        # check-then-write has to survive.
        move = reg.get("after_inspect", {}).get(ref, {}).get(str(k))
        if move:
            reg["tags"][move["tag"]] = move["digest"]
            save()
        print(value)
        return
    print("ERROR: %s: not found" % ref, file=sys.stderr)
    sys.exit(1)


if args[:3] == ["buildx", "imagetools", "inspect"]:
    inspect(args[3])
elif args[:3] == ["buildx", "imagetools", "create"]:
    tag = args[args.index("--tag") + 1]
    src = args[-1]
    n = reg.setdefault("creates", {}).get(tag, 0) + 1
    reg["creates"][tag] = n
    if n in reg.get("fail_create", {}).get(tag, []):
        save()
        print("ERROR: denied: 403 Forbidden", file=sys.stderr)
        sys.exit(1)
    if n in reg.get("transient_create", {}).get(tag, []):
        save()
        print(TRANSIENT_ERR, file=sys.stderr)
        sys.exit(1)
    if src not in reg["known"]:
        save()
        print("ERROR: %s: not found" % src, file=sys.stderr)
        sys.exit(1)
    land = reg.get("wrong_landing", {}).get(tag, {}).get(str(n))
    reg["tags"][tag] = land or src.split("@")[1]
    hijack = reg.get("hijack", {}).get(tag)
    if hijack and n == 1:
        reg["tags"][hijack["tag"]] = hijack["digest"]
    # The world moves on after this write: files (a new branch head, a new release) appear.
    for name, text in reg.get("after_create", {}).get(tag, {}).get(str(n), {}).items():
        open(os.path.join(os.environ["STUB"], name), "w").write(text)
    save()
    if n in reg.get("commit_error", {}).get(tag, []):
        print("ERROR: connection closed after the write", file=sys.stderr)
        sys.exit(1)
else:
    sys.exit(2)
"""

OLD = "sha256:" + "0a" * 32
WRONG = "sha256:" + "ee" * 32
THIRD = "sha256:" + "dd" * 32
G_SHA, G_MAIN, G_LATEST = "ghcr.io/o/r:sha-1234567", "ghcr.io/o/r:main", "ghcr.io/o/r:latest"
H_LATEST = "docker.io/u/r:latest"
ALL_TAGS = "\n".join([G_LATEST, G_MAIN, G_SHA, H_LATEST])


def registry(tmp_path: Path, stub: Path, tags: dict | None = None, **inject) -> None:
    """Install a fake registry as `docker`. Tags default to existing at OLD, so a failure has something to restore."""
    path = tmp_path / "bin" / "docker"
    path.write_text(REGISTRY_STUB)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    known = [f"{r}@{d}" for r in ("ghcr.io/o/r", "docker.io/u/r") for d in (DIGEST, OLD)]
    state = {"tags": {t: OLD for t in (G_SHA, G_MAIN, G_LATEST, H_LATEST)} if tags is None else tags, "known": known}
    state.update(inject)
    (stub / "reg.json").write_text(json.dumps(state))


def reg_state(stub: Path) -> dict:
    return json.loads((stub / "reg.json").read_text())


def create_order(stub: Path) -> list[str]:
    out = []
    for line in calls(stub, "docker buildx imagetools create"):
        words = line.split()
        out.append(words[words.index("--tag") + 1])
    return out


def publish(tmp_path: Path, stub: Path, tags: str = ALL_TAGS, **env: str) -> subprocess.CompletedProcess:
    return run_step(tmp_path, PUBLISH, stub, **{**SIGNED, "TAGS": tags, **env})


def test_the_tags_move_one_at_a_time_from_their_own_registry_sha_first_and_latest_last(tmp_path, stub):
    registry(tmp_path, stub)
    done = publish(tmp_path, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert create_order(stub) == [G_SHA, G_MAIN, G_LATEST, H_LATEST]
    creates = calls(stub, "docker buildx imagetools create")
    assert creates[-1].endswith(f"--tag {H_LATEST} docker.io/u/r@{DIGEST}"), "a Hub tag comes from the Hub copy"
    assert creates[0].endswith(f"--tag {G_SHA} ghcr.io/o/r@{DIGEST}")
    assert set(reg_state(stub)["tags"].values()) == {DIGEST}


def test_latest_is_written_after_every_other_tag_whatever_the_input_order(tmp_path, stub):
    registry(tmp_path, stub)
    tags = "\n".join([G_LATEST, H_LATEST, "ghcr.io/o/r:1.2.3", G_SHA, "ghcr.io/o/r:1"])
    done = publish(tmp_path, stub, tags)
    assert done.returncode == 0, done.stdout + done.stderr
    order = create_order(stub)
    assert order[0] == G_SHA and order[-2:] == [G_LATEST, H_LATEST]


def test_absent_tags_are_new_and_publish_normally(tmp_path, stub):
    registry(tmp_path, stub, tags={})
    done = publish(tmp_path, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert len(reg_state(stub)["tags"]) == 4


def test_failure_on_the_first_tag_leaves_every_tag_where_it_was(tmp_path, stub):
    registry(tmp_path, stub, fail_create={G_SHA: [1]})
    before = reg_state(stub)["tags"]
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert "::error" in done.stdout
    assert reg_state(stub)["tags"] == before
    assert create_order(stub) == [G_SHA], "nothing after the failed tag was written"


def test_failure_on_a_later_tag_restores_the_earlier_tags(tmp_path, stub):
    registry(tmp_path, stub, fail_create={G_LATEST: [1]})
    before = reg_state(stub)["tags"]
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert reg_state(stub)["tags"] == before, "sha- and main moved and were put back on their old digest"
    assert f"{G_SHA} -> {OLD}" in done.stdout and f"{G_MAIN} -> {OLD}" in done.stdout
    assert "the tags this run moved were restored and read back" in done.stdout


def test_a_tag_that_did_not_exist_cannot_be_deleted_and_is_named(tmp_path, stub):
    old = {G_SHA: OLD, G_LATEST: OLD, H_LATEST: OLD}  # main is new
    registry(tmp_path, stub, tags=old, fail_create={G_LATEST: [1]})
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    state = reg_state(stub)["tags"]
    assert state[G_SHA] == OLD and state[G_LATEST] == OLD
    assert state[G_MAIN] == DIGEST, "a new tag cannot be removed; it stays on the signed digest"
    assert f"{G_MAIN} (new, now {DIGEST})" in done.stdout and "::warning title=new tags" in done.stdout


def test_a_tag_that_lands_on_another_digest_fails_the_job_and_is_named_not_overwritten(tmp_path, stub):
    registry(tmp_path, stub, wrong_landing={G_MAIN: {"1": WRONG}})
    before = reg_state(stub)["tags"]
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert f"{G_MAIN} reads back as {WRONG}" in done.stdout
    after = reg_state(stub)["tags"]
    assert after[G_SHA] == before[G_SHA], "the tag this run moved and still holds is restored"
    assert after[G_MAIN] == WRONG, "a digest this run did not promote is not overwritten"
    assert f"{G_MAIN} holds {WRONG}" in done.stdout and "::error title=rollback failed" in done.stdout
    assert G_LATEST not in create_order(stub), "the tags after the bad one were never written"


def test_a_rollback_does_not_overwrite_a_tag_changed_by_another_publisher(tmp_path, stub):
    # Every write and its own read-back pass. After latest is written, another writer moves the sha- tag.
    registry(tmp_path, stub, hijack={G_LATEST: {"tag": G_SHA, "digest": THIRD}})
    done = publish(tmp_path, stub, tags=f"{G_LATEST}\n{G_SHA}")
    assert done.returncode != 0
    assert f"{G_SHA} reads back as {THIRD} after the last write" in done.stdout
    state = reg_state(stub)["tags"]
    assert state[G_SHA] == THIRD, "the other writer's digest is left alone"
    assert state[G_LATEST] == OLD, "the tag this run moved and still holds is restored"
    assert "::error title=rollback failed" in done.stdout
    # the failure names the tag, what it holds, what this run promoted and the recorded previous digest
    line = next(x for x in done.stdout.splitlines() if "rollback failed" in x)
    for part in (G_SHA, f"holds {THIRD}", f"promoted {DIGEST}", f"previous digest is {OLD}", "concurrent change"):
        assert part in line, part
    assert [c for c in create_order(stub) if c == G_SHA] == [G_SHA], "no restore write for the changed tag"


def test_a_tag_already_back_on_its_previous_digest_is_not_written_again(tmp_path, stub):
    registry(tmp_path, stub, hijack={G_LATEST: {"tag": G_SHA, "digest": OLD}})
    done = publish(tmp_path, stub, tags=f"{G_LATEST}\n{G_SHA}")
    assert done.returncode != 0
    assert "could NOT be restored" not in done.stdout
    assert "the tags this run moved were restored and read back" in done.stdout
    state = reg_state(stub)["tags"]
    assert state[G_SHA] == OLD and state[G_LATEST] == OLD
    assert create_order(stub).count(G_SHA) == 1


def test_a_failed_rollback_fails_loudly_and_names_every_tag_and_digest_left_behind(tmp_path, stub):
    # latest fails to write; then the restore of the sha- tag and of main also fail
    registry(
        tmp_path,
        stub,
        fail_create={G_LATEST: [1], G_SHA: [2], G_MAIN: [2]},
    )
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert "::error title=rollback failed" in done.stdout
    assert f"{G_SHA} is {DIGEST}, was {OLD}" in done.stdout
    assert f"{G_MAIN} is {DIGEST}, was {OLD}" in done.stdout
    state = reg_state(stub)["tags"]
    assert state[G_SHA] == DIGEST and state[G_MAIN] == DIGEST
    assert "were restored and read back" not in done.stdout


def test_a_restore_is_read_back_not_trusted(tmp_path, stub):
    # the restore write is accepted but lands on the wrong digest: the read-back sees it
    registry(tmp_path, stub, fail_create={G_LATEST: [1]}, wrong_landing={G_SHA: {"2": WRONG}})
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert f"{G_SHA} is {WRONG}, was {OLD}" in done.stdout and "::error title=rollback failed" in done.stdout


def test_an_unreadable_tag_stops_the_run_before_anything_moves(tmp_path, stub):
    registry(tmp_path, stub, unreadable=[G_MAIN])
    done = publish(tmp_path, stub)
    assert done.returncode != 0 and "could not read the current digest" in done.stdout
    assert create_order(stub) == []


def test_a_missing_staged_index_stops_the_run_before_anything_moves(tmp_path, stub):
    registry(tmp_path, stub)
    state = reg_state(stub)
    state["known"] = [k for k in state["known"] if not k.startswith(f"docker.io/u/r@{DIGEST}")]
    (stub / "reg.json").write_text(json.dumps(state))
    done = publish(tmp_path, stub)
    assert done.returncode != 0 and "staged index" in done.stdout
    assert create_order(stub) == []


def test_a_tag_outside_the_staged_registries_is_refused(tmp_path, stub):
    registry(tmp_path, stub)
    done = publish(tmp_path, stub, tags=f"{G_SHA}\nghcr.io/other/x:latest")
    assert done.returncode != 0 and "not in a registry that holds the staged index" in done.stdout
    assert create_order(stub) == []


def test_the_tags_are_applied_to_the_signed_digest_and_checked(tmp_path, stub):
    registry(tmp_path, stub)
    done = publish(tmp_path, stub, tags=f"{G_LATEST}\n{H_LATEST}")
    assert done.returncode == 0, done.stdout + done.stderr
    state = reg_state(stub)["tags"]
    assert state[G_LATEST] == state[H_LATEST] == DIGEST and state[G_SHA] == state[G_MAIN] == OLD, (
        "only the named tags moved"
    )
    assert any(
        line.startswith("docker buildx imagetools inspect") and G_LATEST in line for line in calls(stub, "docker")
    )


def test_no_tags_is_an_error(tmp_path, stub):
    registry(tmp_path, stub)
    done = publish(tmp_path, stub, tags="")
    assert done.returncode != 0
    assert create_order(stub) == []


def test_the_publish_step_states_the_bounded_guarantee_in_its_comment():
    text = WORKFLOW_TEXT
    flat = text.replace("\n      # ", " ")
    assert "bounded, not atomic" in flat
    assert "did not exist before cannot be deleted" in flat
    assert "best effort" in flat and "is not verified again by this workflow" in flat


# --- registry calls are retried a bounded number of times -----------------------------


def attempts(stub: Path, prefix: str, needle: str) -> int:
    return len([c for c in calls(stub, prefix) if needle in c])


def test_a_transient_failure_on_the_latest_write_is_retried(tmp_path, stub):
    registry(tmp_path, stub, transient_create={G_LATEST: [1]})
    done = publish(tmp_path, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert create_order(stub).count(G_LATEST) == 2
    assert reg_state(stub)["tags"][G_LATEST] == DIGEST
    assert "::warning title=registry retry" in done.stderr


def test_a_transient_failure_on_a_read_back_is_retried(tmp_path, stub):
    # inspect #1 of latest is the pre-promotion read, #2 the read-back after its write
    registry(tmp_path, stub, transient_inspect={G_LATEST: [2]})
    done = publish(tmp_path, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert set(reg_state(stub)["tags"].values()) == {DIGEST}


def test_a_write_that_commits_but_returns_an_error_is_judged_by_its_read_back(tmp_path, stub):
    registry(tmp_path, stub, commit_error={G_LATEST: [1]})
    done = publish(tmp_path, stub)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "returned an error but the tag reads back" in done.stdout
    assert create_order(stub).count(G_LATEST) == 1, "an error that is not transient is not retried"
    assert set(reg_state(stub)["tags"].values()) == {DIGEST}


def test_a_failed_write_that_never_moved_the_tag_is_not_rolled_back(tmp_path, stub):
    registry(tmp_path, stub, fail_create={G_LATEST: [1]})
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert "writing ghcr.io/o/r:latest failed and the tag did not move" in done.stdout
    assert create_order(stub).count(G_LATEST) == 1, "no write to a tag that never moved"


def test_a_transient_failure_during_the_rollback_is_retried(tmp_path, stub):
    # latest fails for good; the restore of the sha- tag meets one transient failure first
    registry(tmp_path, stub, fail_create={G_LATEST: [1]}, transient_create={G_SHA: [2]})
    before = reg_state(stub)["tags"]
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert reg_state(stub)["tags"] == before
    assert create_order(stub).count(G_SHA) == 3, "the write, the failed restore attempt, the retried restore"


def test_a_non_retryable_4xx_is_tried_once(tmp_path, stub):
    registry(tmp_path, stub, fail_create={G_SHA: [1]})
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert create_order(stub).count(G_SHA) == 1
    assert "::warning title=registry retry" not in done.stderr


def test_retries_are_capped_at_four_attempts(tmp_path, stub):
    registry(tmp_path, stub, transient_create={G_SHA: [1, 2, 3, 4, 5, 6]})
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    assert create_order(stub).count(G_SHA) == 4


def function_text(script: str, name: str) -> str:
    start = script.index(f"{name}() {{")
    return script[start : script.index("\n}\n", start) + 3]


def test_the_registry_retry_helper_is_the_same_text_in_the_index_and_tag_steps():
    index, tags = step(INDEX)["run"], step(PUBLISH)["run"]
    for fn in ("registry_transient", "registry_retry"):
        assert function_text(index, fn) == function_text(tags, fn), fn


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


def test_the_signer_identity_input_defaults_to_the_reusable_workflow_and_is_forwarded():
    inputs = triggers(load(RELEASE))["workflow_call"]["inputs"]
    default = inputs["signer-identity-regexp"]["default"]
    assert default == IDENTITY, "must name this workflow file, not just the owner"
    assert inputs["signer-identity-regexp"]["type"] == "string"
    thin = jobs(load(WORKFLOWS / "python-docker-release.yml"))["release"]["with"]
    assert thin["signer-identity-regexp"] == "${{ inputs.signer-identity-regexp }}"


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
def test_a_publish_with_signing_off_fails_early_unless_allowed(off):
    on = {"PUBLISH": "true", "SIGN": "true", "SBOM": "true", "PROVENANCE": "true", "ALLOW_UNSIGNED": "false"}
    assert run_require(plan_require(), **on).returncode == 0
    refused = run_require(plan_require(), **{**on, off: "false"})
    assert refused.returncode != 0 and "::error" in refused.stdout
    assert run_require(plan_require(), **{**on, off: "false", "ALLOW_UNSIGNED": "true"}).returncode == 0
    # a run that does not publish pushes nothing, so it has no unsigned release to refuse
    assert run_require(plan_require(), **{**on, off: "false", "PUBLISH": "false"}).returncode == 0


def test_the_signing_check_is_keyed_on_the_publish_decision_and_runs_after_it():
    check = plan_require()
    assert check["env"]["PUBLISH"] == "${{ steps.publish.outputs.publish }}"
    order = [s.get("name") for s in steps_of(jobs(load(RELEASE))["plan"])]
    assert order.index("Decide whether to publish") < order.index(REQUIRE) < order.index("Plan the matrix")


@pytest.mark.parametrize("off", ["SIGN", "SBOM", "PROVENANCE"])
def test_the_tags_do_not_move_with_signing_off_unless_allowed(tmp_path, stub, off):
    registry(tmp_path, stub)
    done = publish(tmp_path, stub, tags=G_LATEST, **{off: "false"})
    assert done.returncode != 0 and "::error" in done.stdout
    assert create_order(stub) == []
    ok = publish(tmp_path, stub, tags=G_LATEST, **{off: "false", "ALLOW_UNSIGNED": "true"})
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

GATE = "needs.plan.outputs.publish == 'true'"


def test_the_signing_steps_are_gated_exactly_on_their_inputs():
    assert step(SIGN)["if"] == f"{GATE} && inputs.sign"
    assert step(ATTEST)["if"] == f"{GATE} && inputs.sbom"
    assert step("Generate the SBOM with syft")["if"] == f"{GATE} && inputs.sbom"
    assert step("Record build provenance")["if"] == f"{GATE} && inputs.provenance"
    assert step(VERIFY)["if"] == f"{GATE} && (inputs.sign || inputs.sbom)"
    assert step(PUBLISH)["if"] == GATE


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


# --- one publish at a time, never on a pull request -----------------------------------


def test_one_publish_per_destination_at_a_time_whatever_the_ref_and_never_cancelled():
    merge = jobs(load(RELEASE))["merge"]
    group = merge["concurrency"]["group"]
    assert "needs.plan.outputs.serialize" in group
    for event_data in ("github.ref", "github.sha", "github.head_ref", "github.event", "github.workflow"):
        assert event_data not in group, f"{event_data}: runs for different refs must queue, not race"
    assert "github." not in group, "the key is the destination image only, from caller inputs and the plan"
    assert merge["concurrency"]["cancel-in-progress"] is False


def test_the_merge_job_never_runs_on_a_pull_request_or_without_the_publish_decision():
    cond = str(jobs(load(RELEASE))["merge"]["if"])
    assert "github.event_name != 'pull_request'" in cond
    assert GATE in cond


def test_the_publish_step_runs_only_after_every_earlier_step_succeeded():
    """Normal success semantics: no step between the index and the tag step can be skipped past a failure."""
    order = names()
    start, end = order.index(INDEX), order.index(PUBLISH)
    assert step(PUBLISH)["if"] == GATE, "exactly the audited publish condition"
    for s in merge_steps()[start : end + 1]:
        cond = str(s.get("if", ""))
        for override in ("always()", "failure()", "cancelled()", "success() ||"):
            assert override not in cond, (s.get("name"), override)
        assert not s.get("continue-on-error"), s.get("name")
    for needed in (
        "Sign the image (keyless)",
        "Attach the SBOM as a cosign attestation",
        "Record build provenance",
        VERIFY,
    ):
        assert start < order.index(needed) < end, needed
    merge = jobs(load(RELEASE))["merge"]
    assert not merge.get("continue-on-error") and "always()" not in str(merge.get("if"))


def test_no_run_block_in_the_merge_job_writes_a_tag_outside_the_audited_steps():
    audited = {INDEX, PUBLISH}
    for s in merge_steps():
        run = s.get("run", "")
        if s.get("name") in audited:
            continue
        for forbidden in ("imagetools create", "--tag", "docker push", "docker tag", "imagetools"):
            assert forbidden not in run, (s.get("name"), forbidden)
    # inside the audited steps every create goes through the bounded retry helper
    for name in audited:
        for line in step(name)["run"].splitlines():
            if "imagetools create" in line and not line.lstrip().startswith("#"):
                assert "registry_retry docker buildx imagetools create" in line, (name, line)


def test_the_merge_job_needs_the_plan_and_the_build():
    merge = jobs(load(RELEASE))["merge"]
    assert merge["needs"] == ["plan", "build"], "without the plan the concurrency key is empty"


# --- a stale run does not move a branch's moving tags ----------------------------------

BRANCH_TAGS = f"{G_LATEST}\n{G_MAIN}\n{G_SHA}"


def publish_on_branch(tmp_path, stub, head: str | None, rc: int = 0, ref: str = "refs/heads/main"):
    registry(tmp_path, stub)
    if head is not None:
        (stub / "gh.out").write_text(head + "\n")
    (stub / "gh.rc").write_text(str(rc))
    return publish(tmp_path, stub, tags=BRANCH_TAGS, REF=ref)


def test_a_run_at_the_branch_head_moves_every_tag(tmp_path, stub):
    done = publish_on_branch(tmp_path, stub, SHA)
    assert done.returncode == 0, done.stdout + done.stderr
    assert create_order(stub) == [G_SHA, G_MAIN, G_LATEST]
    head = f"gh api repos/{REPO}/commits/main --jq .sha"
    assert calls(stub, "gh api") == [head] * 3, "once at the start, then right before main and before latest"


def test_a_stale_run_publishes_only_the_immutable_tag_and_does_not_fail(tmp_path, stub):
    done = publish_on_branch(tmp_path, stub, "f" * 40)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "::warning" in done.stdout
    assert create_order(stub) == [G_SHA]


def test_a_stale_run_with_no_immutable_tag_publishes_nothing_and_does_not_fail(tmp_path, stub):
    registry(tmp_path, stub)
    (stub / "gh.out").write_text("f" * 40 + "\n")
    done = publish(tmp_path, stub, tags=G_LATEST, REF="refs/heads/main")
    assert done.returncode == 0 and "::warning" in done.stdout
    assert create_order(stub) == []


@pytest.mark.parametrize("answer", [None, "", "not-a-sha", "ab" * 10])
def test_an_unreadable_branch_head_fails_and_moves_nothing(tmp_path, stub, answer):
    done = publish_on_branch(tmp_path, stub, answer, rc=1 if answer is None else 0)
    assert done.returncode != 0 and "::error" in done.stdout
    assert create_order(stub) == []


# --- a release tag ref moves the mutable tags only when it is the newest release ------------

R = "ghcr.io/o/r"
RELEASE_TAGS = "\n".join([f"{R}:1.9.0", f"{R}:1.9", f"{R}:1", f"{R}:latest", f"{R}:sha-1234567"])


def release(tmp_path, stub, ref: str, existing: list[str], tags: str = RELEASE_TAGS, **inject):
    registry(tmp_path, stub, tags={}, **inject)
    (stub / "gh.tags").write_text("".join(f"refs/tags/{t}\n" for t in existing))
    return publish(tmp_path, stub, tags=tags, REF=ref)


def test_the_newest_release_moves_every_tag(tmp_path, stub):
    done = release(tmp_path, stub, "refs/tags/v2.0.0", ["v1.9.0", "v2.0.0"], tags=RELEASE_TAGS.replace("1.9", "2.0"))
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"{R}:latest" in create_order(stub) and len(create_order(stub)) == 5
    assert any("matching-refs/tags/v" in c for c in calls(stub, "gh api"))


def test_an_older_release_publishes_only_its_version_and_sha_tags(tmp_path, stub):
    done = release(tmp_path, stub, "refs/tags/v1.9.0", ["v1.9.0", "v2.0.0"])
    assert done.returncode == 0, done.stdout + done.stderr
    assert sorted(create_order(stub)) == sorted([f"{R}:1.9.0", f"{R}:sha-1234567"])
    assert "::notice title=older release" in done.stdout and "v2.0.0 is newer" in done.stdout


@pytest.mark.parametrize(
    "ref,existing,newest",
    [
        ("refs/tags/v1.10.0", ["v1.9.0", "v1.10.0"], True),
        ("refs/tags/v1.9.0", ["v1.9.0", "v1.10.0"], False),
        ("refs/tags/v1.0.0", ["v1.0.0", "v1.0.0-rc.1"], True),
        ("refs/tags/v1.0.0-rc.1", ["v1.0.0-rc.1", "v1.0.0"], False),
        ("refs/tags/v1.0.0-rc.2", ["v1.0.0-rc.1", "v1.0.0-rc.2"], True),
        ("refs/tags/v1.0.0-rc.10", ["v1.0.0-rc.9", "v1.0.0-rc.10"], True),
        ("refs/tags/v1.0.0-alpha", ["v1.0.0-alpha", "v1.0.0-alpha.1"], False),
        ("refs/tags/v2.0.0", ["v2.0.0", "v3.0.0-rc.1"], True),
        ("refs/tags/v1.0.0+b2", ["v1.0.0+b1", "v1.0.0+b2"], True),
        ("refs/tags/v10.0.0", ["v9.9.9", "v10.0.0"], True),
    ],
)
def test_release_order_follows_semver_precedence(tmp_path, stub, ref, existing, newest):
    version = ref.removeprefix("refs/tags/v").split("+")[0]
    tags = f"{R}:{version}\n{R}:latest\n{R}:sha-1234567"
    done = release(tmp_path, stub, ref, existing, tags=tags)
    assert done.returncode == 0, done.stdout + done.stderr
    assert (f"{R}:latest" in create_order(stub)) is newest


def test_a_tag_ref_that_is_not_a_semver_release_publishes_only_its_own_name_and_sha_tags(tmp_path, stub):
    tags = f"{R}:nightly-7\n{R}:latest\n{R}:sha-1234567"
    done = release(tmp_path, stub, "refs/tags/nightly-7", [], tags=tags)
    assert done.returncode == 0, done.stdout + done.stderr
    assert sorted(create_order(stub)) == sorted([f"{R}:nightly-7", f"{R}:sha-1234567"])
    assert "::notice title=unordered tag" in done.stdout
    assert calls(stub, "gh api") == [], "no order to look up"


def test_the_release_tags_that_cannot_be_read_stop_the_run_with_nothing_moved(tmp_path, stub):
    registry(tmp_path, stub, tags={})
    (stub / "gh.tags.rc").write_text("1")
    done = publish(tmp_path, stub, tags=RELEASE_TAGS, REF="refs/tags/v1.9.0")
    assert done.returncode != 0 and "release order" in done.stdout
    assert create_order(stub) == []


def test_an_older_release_finishing_after_a_newer_one_does_not_move_latest(tmp_path, stub):
    """Interleaved runs on one fake registry: v2.0.0 publishes first, then v1.9.0 runs to the end."""
    existing = ["v1.9.0", "v2.0.0"]
    first = release(tmp_path, stub, "refs/tags/v2.0.0", existing, tags=RELEASE_TAGS.replace("1.9", "2.0"))
    assert first.returncode == 0, first.stdout + first.stderr
    state = reg_state(stub)
    assert state["tags"][f"{R}:latest"] == DIGEST
    state["known"].append(f"{R}@{OLD}")
    (stub / "reg.json").write_text(json.dumps(state))
    second = publish(tmp_path, stub, tags=RELEASE_TAGS, REF="refs/tags/v1.9.0", DIGEST=OLD, HUB="")
    assert second.returncode == 0, second.stdout + second.stderr
    after = reg_state(stub)["tags"]
    assert after[f"{R}:latest"] == DIGEST, "the older release did not move latest back"
    assert after[f"{R}:1"] == DIGEST and after[f"{R}:1.9.0"] == OLD, "its own version tag is still published"


def test_the_publish_step_has_the_api_env_and_the_job_can_read_contents():
    env = step(PUBLISH)["env"]
    assert env["REF"] == "${{ github.ref }}" and env["WORKFLOW_SHA"] == "${{ github.sha }}"
    assert env["REPOSITORY"] == "${{ github.repository }}" and env["GH_TOKEN"] == "${{ github.token }}"
    assert env["HUB"] == "${{ steps.names.outputs.dockerhub }}"
    assert jobs(load(RELEASE))["merge"]["permissions"]["contents"] == "read"


# --- the rollback restores only a tag that still holds this run's digest, read twice ------------


def test_a_tag_moved_between_the_rollback_check_and_the_restore_write_is_not_overwritten(tmp_path, stub):
    # latest fails to write, so the rollback runs. Its first read of main sees this run's digest;
    # another publisher moves main right after that read answered. The restore must re-read, see it and not write.
    registry(
        tmp_path,
        stub,
        fail_create={G_LATEST: [1]},
        after_inspect={G_MAIN: {"3": {"tag": G_MAIN, "digest": THIRD}}},
    )
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    state = reg_state(stub)["tags"]
    assert state[G_MAIN] == THIRD, "the other publisher's digest survives"
    assert create_order(stub).count(G_MAIN) == 1, "no restore write was made for the moved tag"
    assert state[G_SHA] == OLD, "a tag that did not move is still restored"
    assert "::error title=rollback failed" in done.stdout
    line = next(x for x in done.stdout.splitlines() if "rollback failed" in x)
    assert G_MAIN in line and f"holds {THIRD}" in line and "nothing was written" in line


def test_the_restore_reads_the_tag_again_immediately_before_it_writes(tmp_path, stub):
    registry(tmp_path, stub, fail_create={G_LATEST: [1]})
    done = publish(tmp_path, stub)
    assert done.returncode != 0
    seq = [c for c in calls(stub, "docker") if G_SHA in c and "imagetools" in c]
    kinds = ["create" if " create " in c else "inspect" for c in seq]
    last_write = len(kinds) - 1 - kinds[::-1].index("create")
    first_write = kinds.index("create")
    between = kinds[first_write + 1 : last_write]
    assert last_write > first_write and between == ["inspect"] * 3, "read-back, rollback check, re-read, then the write"


def test_the_restore_documents_what_the_registry_cannot_guarantee():
    flat = WORKFLOW_TEXT.replace("\n          # ", " ")
    assert "no conditional write" in flat and "window" in flat


# --- the serialization key covers the concrete destination --------------------------------------


def plan_group(tmp_path: Path, **env: str) -> str:
    plan = [s for s in steps_of(jobs(load(RELEASE))["plan"]) if s.get("name") == "Plan the matrix"]
    assert len(plan) == 1
    out = tmp_path / f"plan-out-{len(list(tmp_path.glob('plan-out-*')))}"
    base = {"PATH": os.environ["PATH"], "PLATFORMS": "linux/amd64", "GITHUB_OUTPUT": str(out)}
    done = subprocess.run(
        ["bash", "-c", plan[0]["run"]], env={**base, **env}, capture_output=True, text=True, timeout=TIMEOUT
    )
    assert done.returncode == 0, done.stdout + done.stderr
    lines = [x for x in out.read_text().splitlines() if x.startswith("serialize=")]
    assert len(lines) == 1, out.read_text()
    return lines[0].removeprefix("serialize=")


def hub(repository: str, image: str = "", on: str = "true", hub_repository: str = "") -> dict:
    return {
        "REPOSITORY": repository,
        "IMAGE_NAME": image,
        "DOCKERHUB": on,
        "DOCKERHUB_REPOSITORY": hub_repository,
    }


def test_the_publish_group_is_the_plan_destination_key_and_nothing_else():
    merge = jobs(load(RELEASE))["merge"]
    group = merge["concurrency"]["group"]
    assert "needs.plan.outputs.serialize" in group
    assert "inputs." not in group and "github." not in group
    plan = [s for s in steps_of(jobs(load(RELEASE))["plan"]) if s.get("name") == "Plan the matrix"][0]
    assert plan["env"]["DOCKERHUB"] == "${{ inputs.dockerhub }}"
    assert plan["env"]["DOCKERHUB_REPOSITORY"] == "${{ inputs.dockerhub-repository }}"
    assert jobs(load(RELEASE))["plan"]["outputs"]["serialize"] == "${{ steps.plan.outputs.serialize }}"


def test_two_callers_that_resolve_to_one_hub_destination_share_a_group(tmp_path):
    a = plan_group(tmp_path, **hub("owner/app-a", image="ghcr-a", hub_repository="shared"))
    b = plan_group(tmp_path, **hub("owner/app-b", image="ghcr-b", hub_repository="shared"))
    assert a == b, "different GHCR images, one Docker Hub repository: one queue"


def test_a_defaulted_hub_repository_resolves_like_the_explicit_one(tmp_path):
    defaulted = plan_group(tmp_path, **hub("one/Svc", image="x"))
    explicit = plan_group(tmp_path, **hub("two/other", image="y", hub_repository="svc"))
    assert defaulted == explicit


def test_different_destinations_do_not_share_a_group(tmp_path):
    base = plan_group(tmp_path, **hub("o/a", hub_repository="one"))
    assert plan_group(tmp_path, **hub("o/a", hub_repository="two")) != base
    ghcr_a = plan_group(tmp_path, **hub("o/a", on="false"))
    ghcr_b = plan_group(tmp_path, **hub("o/b", on="false"))
    assert ghcr_a != ghcr_b and ghcr_a != base
    assert plan_group(tmp_path, **hub("o/a", on="false", hub_repository="ignored")) == ghcr_a


# --- the newest-ref check is repeated right before each mutable tag write --------------------------

BRANCH_SEQ = f"{G_SHA}\n{G_MAIN}\n{G_LATEST}"


def test_a_branch_that_moves_after_the_first_check_stops_the_moving_tags(tmp_path, stub):
    registry(tmp_path, stub)
    (stub / "gh.out.1").write_text(SHA + "\n")
    (stub / "gh.out.2").write_text("f" * 40 + "\n")
    done = publish(tmp_path, stub, tags=BRANCH_TAGS, REF="refs/heads/main")
    assert done.returncode == 0, done.stdout + done.stderr
    assert create_order(stub) == [G_SHA], "only the immutable tag was written; main and latest were not"
    assert "::warning title=stale run" in done.stdout
    assert reg_state(stub)["tags"][G_MAIN] == OLD and reg_state(stub)["tags"][G_LATEST] == OLD


def test_a_branch_that_moves_between_two_moving_tags_rolls_back_the_one_already_moved(tmp_path, stub):
    registry(
        tmp_path,
        stub,
        after_create={G_MAIN: {"1": {"gh.out.3": "f" * 40 + "\n"}}},
    )
    (stub / "gh.out").write_text(SHA + "\n")
    done = publish(tmp_path, stub, tags=BRANCH_TAGS, REF="refs/heads/main")
    assert done.returncode != 0
    state = reg_state(stub)["tags"]
    assert state[G_LATEST] == OLD, "latest was never written"
    assert state[G_MAIN] == OLD, "main moved while the run was still newest, then was put back"
    assert "no longer the head" in done.stdout


def test_a_branch_head_that_cannot_be_read_before_a_moving_write_fails_and_writes_nothing_more(tmp_path, stub):
    registry(tmp_path, stub)
    (stub / "gh.out.1").write_text(SHA + "\n")
    (stub / "gh.out.2").write_text("not-a-sha\n")
    done = publish(tmp_path, stub, tags=BRANCH_TAGS, REF="refs/heads/main")
    assert done.returncode != 0 and "could not read the head of main before writing" in done.stdout
    assert G_MAIN not in create_order(stub) and G_LATEST not in create_order(stub)


def test_a_newer_release_that_appears_after_the_first_check_keeps_latest_where_it_is(tmp_path, stub):
    registry(tmp_path, stub, tags={})
    (stub / "gh.tags.1").write_text("refs/tags/v1.9.0\n")
    (stub / "gh.tags.2").write_text("refs/tags/v1.9.0\nrefs/tags/v2.0.0\n")
    done = publish(tmp_path, stub, tags=RELEASE_TAGS, REF="refs/tags/v1.9.0")
    assert done.returncode == 0, done.stdout + done.stderr
    order = create_order(stub)
    assert f"{R}:latest" not in order and f"{R}:1" not in order and f"{R}:1.9" not in order
    assert f"{R}:1.9.0" in order and f"{R}:sha-1234567" in order
    assert "v2.0.0 is newer" in done.stdout


def test_a_newer_release_that_appears_between_two_moving_writes_stops_the_rest(tmp_path, stub):
    registry(
        tmp_path,
        stub,
        tags={},
        after_create={f"{R}:1.9": {"1": {"gh.tags.3": "refs/tags/v1.9.0\nrefs/tags/v2.0.0\n"}}},
    )
    (stub / "gh.tags").write_text("refs/tags/v1.9.0\n")
    done = publish(tmp_path, stub, tags=RELEASE_TAGS, REF="refs/tags/v1.9.0")
    assert done.returncode != 0
    order = create_order(stub)
    assert f"{R}:latest" not in order, "latest, the last write, was refused"
    assert "v2.0.0 is newer" in done.stdout


def test_the_release_list_that_cannot_be_read_before_a_moving_write_fails_and_writes_nothing_more(tmp_path, stub):
    registry(tmp_path, stub, tags={})
    (stub / "gh.tags").write_text("refs/tags/v1.9.0\n")
    (stub / "gh.tags.rc.2").write_text("1")
    done = publish(tmp_path, stub, tags=RELEASE_TAGS, REF="refs/tags/v1.9.0")
    assert done.returncode != 0 and "could not read the release tags" in done.stdout
    order = create_order(stub)
    assert f"{R}:1.9" not in order and f"{R}:latest" not in order
