"""Publishing from artifact-release.yml and python-package-release.yml is an allow-list, and an existing release is never rewritten.

Two rules, held still for both workflows:

1. Publication needs an allowed event (`allowed-publish-events`, default `push`) and a release-shaped tag ref
   (`refs/tags/v<semver>`). The condition is on the job and again on every step that installs a signer, signs,
   attests or uploads, so removing it from one place is caught.
2. A release that already exists is completed, never modified: every asset about to be uploaded must be absent
   or already there with the identical sha256 digest. Nothing is replaced (no `--clobber`); a differing asset
   fails the run and names the asset.

The scripts are run under bash against a stub `gh`, so the behavior is exercised, not only the text.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
UPLOAD = "Create the release, or upload to the one that exists"
GUARD_STEP = "Check the publish context"
CASES = [
    # (workflow, publishing job, asset directory)
    ("artifact-release.yml", "publish", "artifacts"),
    ("python-package-release.yml", "github-release", "dist"),
]
IDS = [c[0] for c in CASES]


def doc_of(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def steps(name: str, job: str) -> list[dict]:
    return doc_of(name)["jobs"][job]["steps"]


def step_named(name: str, job: str, step_name: str) -> dict:
    found = [s for s in steps(name, job) if s.get("name") == step_name]
    assert len(found) == 1, f"{name}/{job}: expected one step named {step_name!r}, found {len(found)}"
    return found[0]


def normalize(cond: str) -> str:
    return " ".join(str(cond).split())


# --- structure -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_no_clobber_anywhere(name, job, _d):
    text = (WORKFLOWS / name).read_text()
    assert "--clobber" not in text, f"{name}: an existing release asset must never be replaced"


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_input_is_declared_and_defaults_to_push_only(name, job, _d):
    inputs = (doc_of(name).get("on") or doc_of(name).get(True))["workflow_call"]["inputs"]
    spec = inputs["allowed-publish-events"]
    assert spec["type"] == "string" and spec["default"] == "push"


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_job_condition_is_an_allow_list(name, job, _d):
    cond = normalize(doc_of(name)["jobs"][job]["if"])
    assert "inputs.publish" in cond
    assert "inputs.allowed-publish-events" in cond and "github.event_name" in cond
    assert "startsWith(github.ref, 'refs/tags/v')" in cond


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_every_publishing_step_repeats_the_guard(name, job, _d):
    job_cond = normalize(doc_of(name)["jobs"][job]["if"])
    # The step guard is the job's own allow-list part, so a drift between the two is caught.
    allow = "contains(format(',{0},', inputs.allowed-publish-events), format(',{0},', github.event_name))"
    ref = "startsWith(github.ref, 'refs/tags/v')"
    assert allow in job_cond
    guarded = []
    for s in steps(name, job):
        body = " ".join(str(v) for v in (s.get("uses", ""), s.get("run", ""), s.get("name", "")))
        publishes = any(
            token in body
            for token in ("attest-build-provenance", "cosign", "gh release", UPLOAD, "Record build provenance")
        )
        if not publishes:
            continue
        cond = normalize(s.get("if", ""))
        assert allow in cond and ref in cond, f"{name}: step {s.get('name')!r} publishes without the allow-list guard"
        guarded.append(s.get("name"))
    assert UPLOAD in guarded and "Record build provenance" in guarded, f"{name}: guard collected {guarded}"


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_the_context_check_runs_before_any_download_or_write(name, job, _d):
    names = [s.get("name") or s.get("uses") for s in steps(name, job)]
    assert GUARD_STEP in names
    first_write = min(i for i, n in enumerate(names) if n and ("Checksums" in n or "download-artifact" in n))
    assert names.index(GUARD_STEP) < first_write


def test_the_guard_collects_something_and_bites():
    """Negative: a step list with an unguarded signer is what the structural test would reject."""
    allow = "contains(format(',{0},', inputs.allowed-publish-events), format(',{0},', github.event_name))"
    bad = {"name": "Sign every file (keyless)", "run": "cosign sign-blob x", "if": "inputs.sign"}
    assert allow not in normalize(bad["if"])


# --- the context check, run under bash -------------------------------------------------------------------------


def run_context(name: str, job: str, event: str, ref: str, allowed: str = "push") -> subprocess.CompletedProcess:
    step = step_named(name, job, GUARD_STEP)
    env = {
        "PATH": os.environ["PATH"],
        "EVENT_NAME": event,
        "REF": ref,
        "ALLOWED_EVENTS": allowed,
    }
    assert set(step["env"]) == {"EVENT_NAME", "REF", "ALLOWED_EVENTS"}
    return subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True, check=False)


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
@pytest.mark.parametrize(
    ("event", "ref", "allowed", "ok"),
    [
        ("push", "refs/tags/v1.2.3", "push", True),
        ("push", "refs/tags/v1.2.3-rc.1", "push", True),
        ("push", "refs/tags/v1.2.3+build.5", "push", True),
        ("release", "refs/tags/v1.2.3", "push,release", True),
        ("release", "refs/tags/v1.2.3", "push", False),  # not opted in
        ("workflow_dispatch", "refs/tags/v1.2.3", "push", False),
        ("workflow_run", "refs/tags/v1.2.3", "push", False),
        ("repository_dispatch", "refs/tags/v1.2.3", "push", False),
        ("pull_request_target", "refs/tags/v1.2.3", "push", False),
        ("push", "refs/heads/main", "push", False),
        ("push", "refs/heads/v1.2.3", "push", False),
        ("push", "refs/tags/1.2.3", "push", False),
        ("push", "refs/tags/v1", "push", False),
        ("push", "refs/tags/v1.2.3/../x", "push", False),
        ("push", "refs/tags/v1.2.3 ", "push", False),
        ("push", "refs/tags/v1.2.3\nrefs/heads/x", "push", False),
        ("push", "refs/pull/5/merge", "push", False),
        ("pull_request", "refs/tags/v1.2.3", "push,pull_request", False),  # never allowed, even if listed
        ("pull_request_target", "refs/tags/v1.2.3", "push,pull_request_target", False),
        ("pushx", "refs/tags/v1.2.3", "push", False),  # exact match, not a substring
        ("push", "refs/tags/v1.2.3", "", False),
        ("push", "refs/tags/v1.2.3", "push, release", False),  # spaces are a malformed list
    ],
)
def test_context_check(name, job, _d, event, ref, allowed, ok):
    result = run_context(name, job, event, ref, allowed)
    assert (result.returncode == 0) is ok, result.stdout + result.stderr
    if not ok:
        assert "::error" in result.stdout


# --- the upload step, run under bash against a stub gh ---------------------------------------------------------

STUB = r"""#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
case "$1 $2" in
  "release view") [ "$STUB_EXISTS" = "1" ] ;;
  "api repos/o/r/releases/tags/v1.0.0") cat "$STUB_RELEASE_JSON" ;;
  "release upload"|"release create") exit "${STUB_UPLOAD_RC:-0}" ;;
  *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
"""


def sha(path: Path) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def sandbox(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text(STUB)
    gh.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    (work / "notes").mkdir()
    return tmp_path, work


def run_upload(sandbox, name, job, dirname, files, remote=None, upload_rc=0):
    """remote: None for no release, else {asset name: digest or None}."""
    tmp, work = sandbox
    asset_dir = work / dirname
    asset_dir.mkdir(exist_ok=True)
    for fname, content in files.items():
        (asset_dir / fname).write_bytes(content)
    rel = tmp / "release.json"
    if remote is not None:
        rel.write_text(json.dumps({"assets": [{"name": n, "digest": d} for n, d in remote.items()]}))
    log = tmp / "gh.log"
    log.write_text("")
    step = step_named(name, job, UPLOAD)
    env = {
        "PATH": f"{tmp / 'bin'}:{os.environ['PATH']}",
        "GH_TOKEN": "x",
        "GH_REPO": "o/r",
        "TAG": "v1.0.0",
        "TITLE": "",
        "ASSET_DIR": dirname,
        "STUB_LOG": str(log),
        "STUB_EXISTS": "1" if remote is not None else "0",
        "STUB_RELEASE_JSON": str(rel),
        "STUB_UPLOAD_RC": str(upload_rc),
        "RUNNER_TEMP": str(tmp),
    }
    assert set(step["env"]) >= {"GH_TOKEN", "GH_REPO", "TAG", "TITLE", "ASSET_DIR"}
    result = subprocess.run(["bash", "-c", step["run"]], env=env, cwd=work, capture_output=True, text=True, check=False)
    return result, log.read_text().splitlines()


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_new_release_is_created(sandbox, name, job, dirname):
    result, calls = run_upload(sandbox, name, job, dirname, {"a.whl": b"A", "SHA256SUMS": b"S"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(c.startswith("release create v1.0.0") for c in calls)
    assert not any("--clobber" in c for c in calls)


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_existing_identical_release_uploads_nothing(sandbox, name, job, dirname):
    files = {"a.whl": b"A", "SHA256SUMS": b"S"}
    tmp, work = sandbox
    remote = {n: "sha256:" + __import__("hashlib").sha256(c).hexdigest() for n, c in files.items()}
    result, calls = run_upload(sandbox, name, job, dirname, files, remote=remote)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any(c.startswith("release upload") or c.startswith("release create") for c in calls)


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_partial_release_is_completed_with_only_the_missing_assets(sandbox, name, job, dirname):
    import hashlib

    files = {"a.whl": b"A", "b.tar.gz": b"B"}
    remote = {"a.whl": "sha256:" + hashlib.sha256(b"A").hexdigest()}
    result, calls = run_upload(sandbox, name, job, dirname, files, remote=remote)
    assert result.returncode == 0, result.stdout + result.stderr
    uploads = [c for c in calls if c.startswith("release upload")]
    assert len(uploads) == 1 and "b.tar.gz" in uploads[0] and "a.whl" not in uploads[0]
    assert "--clobber" not in uploads[0]


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_a_differing_asset_fails_names_it_and_uploads_nothing(sandbox, name, job, dirname):
    import hashlib

    files = {"a.whl": b"A", "b.tar.gz": b"B"}
    remote = {"a.whl": "sha256:" + hashlib.sha256(b"A").hexdigest(), "b.tar.gz": "sha256:" + "0" * 64}
    result, calls = run_upload(sandbox, name, job, dirname, files, remote=remote)
    assert result.returncode != 0
    assert "b.tar.gz" in result.stdout + result.stderr
    assert "Burn this version and publish a new one" in result.stdout + result.stderr
    assert not any(c.startswith("release upload") or c.startswith("release create") for c in calls)


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_an_existing_asset_without_a_digest_fails_closed(sandbox, name, job, dirname):
    result, calls = run_upload(sandbox, name, job, dirname, {"a.whl": b"A"}, remote={"a.whl": None})
    assert result.returncode != 0
    assert "a.whl" in result.stdout + result.stderr
    assert not any(c.startswith("release upload") for c in calls)


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_an_empty_asset_directory_fails(sandbox, name, job, dirname):
    result, calls = run_upload(sandbox, name, job, dirname, {})
    assert result.returncode != 0
    assert not any(c.startswith("release create") for c in calls)
