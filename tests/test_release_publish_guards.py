"""Release publishing is an allow-list and an existing release is never rewritten (artifact and package release).

Held still for both workflows:

1. One step (`context`) decides whether this run may publish: an event named in `allowed-publish-events`
   (default `push`) and a SemVer 2.0.0 tag ref `refs/tags/v<semver>`. It fails the job otherwise and writes
   `publish=true` as a step output on success. The job condition and every signing, attesting and uploading step
   are compared with an exact approved form, so an appended `|| true`, a dropped condition, a `continue-on-error`
   or an unclassified step is a violation. Mutation tests apply each of those to the real workflows.
2. A release that already exists is completed, never modified: every asset about to be uploaded must be absent
   or already there with the identical sha256 digest, and the set is re-read and re-checked after the uploads.
   Nothing is replaced (no `--clobber`); lookup failures other than a 404 stop the run.
3. Every documented caller that publishes on the `release` event also sets `allowed-publish-events`.

The scripts are run under bash against a stub `gh`, so behavior is exercised, not only text.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO / ".github" / "workflows"
UPLOAD = "Create the release, or upload to the one that exists"
GUARD_STEP = "Check the publish context"
PUBLISH_OUT = "steps.context.outputs.publish == 'true'"
CASES = [
    # (workflow, publishing job, asset directory)
    ("artifact-release.yml", "publish", "artifacts"),
    ("python-package-release.yml", "github-release", "dist"),
]
IDS = [c[0] for c in CASES]

# The exact approved conditions. Anything else is a violation.
JOB_IF = (
    "inputs.publish && inputs.github-release && github.event_name != 'pull_request' && "
    "contains(format(',{0},', inputs.allowed-publish-events), format(',{0},', github.event_name)) && "
    "startsWith(github.ref, 'refs/tags/v')"
)
GUARDED = {
    "Record build provenance": f"inputs.attest && {PUBLISH_OUT}",
    "Install cosign": f"inputs.sign && {PUBLISH_OUT}",
    "Sign every file (keyless)": f"inputs.sign && {PUBLISH_OUT}",
    UPLOAD: PUBLISH_OUT,
}
REQUIRED = {
    "artifact-release.yml": set(GUARDED),
    "python-package-release.yml": {"Record build provenance", UPLOAD},
}


def is_safe(step: dict) -> bool:
    """Steps that neither sign, attest nor write to the release: egress checks, the context step, downloads, sums."""
    uses = str(step.get("uses", ""))
    name = str(step.get("name", ""))
    return (
        name.startswith("Validate the egress policy inputs")
        or name.startswith("Egress canary")
        or name in (GUARD_STEP, "Checksums")
        or uses.startswith(("step-security/harden-runner@", "actions/download-artifact@"))
    )


def doc_of(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())


def norm(cond) -> str:
    return " ".join(str(cond).split())


def violations(name: str, job: str, doc: dict) -> list[str]:
    """Every way the publishing job departs from the approved form. Empty means the guards are intact."""
    found: list[str] = []
    jobdef = doc["jobs"][job]
    if norm(jobdef.get("if", "")) != JOB_IF:
        found.append(f"job condition is not the approved form: {norm(jobdef.get('if', ''))!r}")
    if jobdef.get("continue-on-error"):
        found.append("job sets continue-on-error")
    steps = jobdef["steps"]
    context = [s for s in steps if s.get("name") == GUARD_STEP]
    if len(context) != 1:
        found.append(f"expected one {GUARD_STEP!r} step, found {len(context)}")
    else:
        ctx = context[0]
        if ctx.get("id") != "context":
            found.append("context step id is not 'context'")
        if "if" in ctx:
            found.append("context step is conditional")
        first_unsafe = next((i for i, s in enumerate(steps) if not is_safe(s) or "download" in str(s.get("uses"))), 0)
        if steps.index(ctx) > first_unsafe:
            found.append("context step runs after a download or a publishing step")
    seen = set()
    for s in steps:
        label = s.get("name") or s.get("uses")
        if s.get("continue-on-error"):
            found.append(f"step {label!r} sets continue-on-error")
        if is_safe(s):
            continue
        seen.add(s.get("name"))
        want = GUARDED.get(s.get("name"))
        if want is None:
            found.append(f"step {label!r} is not classified as safe or guarded")
        elif norm(s.get("if", "")) != want:
            found.append(f"step {label!r} condition is not the approved form: {norm(s.get('if', ''))!r}")
    for missing in REQUIRED[name] - seen:
        found.append(f"guarded step {missing!r} is missing")
    return found


def step_named(doc: dict, job: str, step_name: str) -> dict:
    found = [s for s in doc["jobs"][job]["steps"] if s.get("name") == step_name]
    assert len(found) == 1, f"expected one step named {step_name!r}, found {len(found)}"
    return found[0]


# --- structure ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_the_real_workflow_has_every_guard(name, job, _d):
    assert violations(name, job, doc_of(name)) == []


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_no_clobber_anywhere(name, job, _d):
    assert "--clobber" not in (WORKFLOWS / name).read_text()


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_input_is_declared_and_defaults_to_push_only(name, job, _d):
    doc = doc_of(name)
    spec = (doc.get("on") or doc.get(True))["workflow_call"]["inputs"]["allowed-publish-events"]
    assert spec["type"] == "string" and spec["default"] == "push"


def mutations(name: str, job: str):
    """(label, mutate(doc)) for each way of weakening a real guard."""
    out = []

    def job_if(suffix):
        def f(d):
            d["jobs"][job]["if"] = norm(d["jobs"][job]["if"]) + suffix

        return f

    out.append(("job-or-true", job_if(" || true")))
    out.append(("job-and-true", job_if(" && true")))
    out.append(
        (
            "job-drop-ref",
            lambda d: d["jobs"][job].update({"if": JOB_IF.replace(" && startsWith(github.ref, 'refs/tags/v')", "")}),
        )
    )
    out.append(
        (
            "job-old-form",
            lambda d: d["jobs"][job].update(
                {"if": "inputs.publish && inputs.github-release && github.event_name != 'pull_request'"}
            ),
        )
    )
    out.append(("job-continue-on-error", lambda d: d["jobs"][job].update({"continue-on-error": True})))

    def drop_context(d):
        d["jobs"][job]["steps"] = [s for s in d["jobs"][job]["steps"] if s.get("name") != GUARD_STEP]

    out.append(("context-removed", drop_context))
    out.append(
        ("context-continue-on-error", lambda d: step_named(d, job, GUARD_STEP).update({"continue-on-error": True}))
    )
    out.append(("context-conditional", lambda d: step_named(d, job, GUARD_STEP).update({"if": "always()"})))
    out.append(("context-renamed-id", lambda d: step_named(d, job, GUARD_STEP).update({"id": "other"})))

    def context_last(d):
        steps = d["jobs"][job]["steps"]
        ctx = step_named(d, job, GUARD_STEP)
        steps.remove(ctx)
        steps.append(ctx)

    out.append(("context-moved-last", context_last))

    def extra_step(d):
        d["jobs"][job]["steps"].append({"name": "Publish extra", "run": "gh release upload v1 x --clobber"})

    out.append(("unclassified-write-step", extra_step))
    for step_name in GUARDED:
        if step_name not in REQUIRED[name]:
            continue
        out.append(
            (
                f"{step_name}: or-true",
                lambda d, n=step_name: step_named(d, job, n).update({"if": f"{GUARDED[n]} || true"}),
            )
        )
        out.append(
            (
                f"{step_name}: always",
                lambda d, n=step_name: step_named(d, job, n).update({"if": f"always() && {GUARDED[n]}"}),
            )
        )
        out.append((f"{step_name}: dropped", lambda d, n=step_name: step_named(d, job, n).pop("if", None)))
        out.append(
            (
                f"{step_name}: old-form",
                lambda d, n=step_name: step_named(d, job, n).update({"if": "inputs.sign || inputs.attest"}),
            )
        )
        out.append(
            (
                f"{step_name}: continue-on-error",
                lambda d, n=step_name: step_named(d, job, n).update({"continue-on-error": True}),
            )
        )
        out.append(
            (
                f"{step_name}: removed",
                lambda d, n=step_name: d["jobs"][job].update(
                    {"steps": [s for s in d["jobs"][job]["steps"] if s.get("name") != n]}
                ),
            )
        )
    return out


def all_mutations():
    for name, job, _d in CASES:
        for label, fn in mutations(name, job):
            yield pytest.param(name, job, fn, id=f"{name}:{label}")


@pytest.mark.parametrize(("name", "job", "mutate"), list(all_mutations()))
def test_weakening_any_guard_is_caught(name, job, mutate):
    doc = copy.deepcopy(doc_of(name))
    mutate(doc)
    assert violations(name, job, doc), "the suite stayed green after weakening a guard"


def test_mutations_were_collected():
    assert len(list(all_mutations())) >= 40


# --- the context step, run under bash ----------------------------------------------------------------------


def run_context(tmp_path, name, job, event, ref, allowed="push", script=None):
    step = step_named(doc_of(name), job, GUARD_STEP)
    assert set(step["env"]) == {"EVENT_NAME", "REF", "ALLOWED_EVENTS"}
    out = tmp_path / "out"
    out.write_text("")
    env = {
        "PATH": os.environ["PATH"],
        "EVENT_NAME": event,
        "REF": ref,
        "ALLOWED_EVENTS": allowed,
        "GITHUB_OUTPUT": str(out),
    }
    result = subprocess.run(["bash", "-c", script or step["run"]], env=env, capture_output=True, text=True, check=False)
    return result, out.read_text()


VALID_TAGS = [
    "v0.0.0",
    "v1.2.3",
    "v10.20.30",
    "v1.2.3-rc.1",
    "v1.2.3-0.3.7",
    "v1.2.3-x.7.z.92",
    "v1.2.3-alpha-1",
    "v1.2.3-0a",
    "v1.2.3+build.5",
    "v1.2.3+001",
    "v1.2.3-beta+exp.sha.5114f85",
    "v1.2.3-rc.1+20130313144700",
]
INVALID_TAGS = [
    "v01.2.3",  # leading zero, major
    "v1.02.3",  # minor
    "v1.2.03",  # patch
    "v1.2.3-",  # empty prerelease
    "v1.2.3-+",  # empty prerelease then build
    "v1.2.3-.",  # lone dot
    "v1.2.3-.a",  # leading dot
    "v1.2.3-a.",  # trailing dot
    "v1.2.3-a..b",  # empty identifier
    "v1.2.3-01",  # numeric prerelease with leading zero
    "v1.2.3-a.01",
    "v1.2.3+",  # empty build
    "v1.2.3+.",
    "v1.2.3+a.",
    "v1.2.3+a..b",
    "v1.2.3+foo+bar",  # repeated plus
    "v1.2.3-a+b+c",
    "v1.2.3.4",
    "v1.2",
    "v1",
    "v1.2.3 ",
    "v1.2.3\nv1.2.4",
    "v1.2.3/../x",
    "v1.2.3-a_b",
    "V1.2.3",
    "1.2.3",
]


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
@pytest.mark.parametrize("tag", VALID_TAGS)
def test_semver_tags_are_accepted(tmp_path, name, job, _d, tag):
    result, out = run_context(tmp_path, name, job, "push", f"refs/tags/{tag}")
    assert result.returncode == 0, result.stdout + result.stderr
    assert out.strip() == "publish=true"


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
@pytest.mark.parametrize("tag", INVALID_TAGS)
def test_malformed_tags_are_refused(tmp_path, name, job, _d, tag):
    result, out = run_context(tmp_path, name, job, "push", f"refs/tags/{tag}")
    assert result.returncode != 0 and "::error" in result.stdout, result.stdout
    assert out == "", "a refused context must not write the publish output"


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
@pytest.mark.parametrize(
    ("event", "ref", "allowed", "ok"),
    [
        ("release", "refs/tags/v1.2.3", "push,release", True),
        ("release", "refs/tags/v1.2.3", "push", False),  # not opted in
        ("workflow_dispatch", "refs/tags/v1.2.3", "push", False),
        ("workflow_run", "refs/tags/v1.2.3", "push", False),
        ("repository_dispatch", "refs/tags/v1.2.3", "push", False),
        ("pull_request_target", "refs/tags/v1.2.3", "push", False),
        ("push", "refs/heads/main", "push", False),
        ("push", "refs/heads/v1.2.3", "push", False),
        ("push", "refs/pull/5/merge", "push", False),
        ("pull_request", "refs/tags/v1.2.3", "push,pull_request", False),  # never allowed, even if listed
        ("pull_request_target", "refs/tags/v1.2.3", "push,pull_request_target", False),
        ("pushx", "refs/tags/v1.2.3", "push", False),  # exact match, not a substring
        ("push", "refs/tags/v1.2.3", "", False),
        ("push", "refs/tags/v1.2.3", "push, release", False),  # spaces are a malformed list
    ],
)
def test_event_and_ref_matrix(tmp_path, name, job, _d, event, ref, allowed, ok):
    result, out = run_context(tmp_path, name, job, event, ref, allowed)
    assert (result.returncode == 0) is ok, result.stdout + result.stderr
    assert (out.strip() == "publish=true") is ok


@pytest.mark.parametrize(("name", "job", "_d"), CASES, ids=IDS)
def test_a_loosened_semver_pattern_would_be_caught(tmp_path, name, job, _d):
    """Mutate the real script: drop the leading-zero rule, and the matrix above must see an acceptance."""
    step = step_named(doc_of(name), job, GUARD_STEP)
    assert "(0|[1-9][0-9]*)" in step["run"]
    loose = step["run"].replace("(0|[1-9][0-9]*)", "[0-9]+")
    result, _ = run_context(tmp_path, name, job, "push", "refs/tags/v01.2.3", script=loose)
    assert result.returncode == 0, "the loosened script should accept a leading zero (proving the matrix bites)"


# --- the upload step, run under bash against a stub gh -----------------------------------------------------

STUB = r"""#!/usr/bin/env bash
echo "$*" >> "$STUB_LOG"
state="$STUB_STATE"
case "$1" in
  api)
    n=$(cat "$STUB_COUNT" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$STUB_COUNT"
    case "${STUB_API_MODE:-ok}" in
      401) echo "gh: Bad credentials (HTTP 401)" >&2; exit 1 ;;
      403) echo "gh: Resource not accessible by integration (HTTP 403)" >&2; exit 1 ;;
      429) echo "gh: rate limit exceeded (HTTP 429)" >&2; exit 1 ;;
      500) echo "gh: Server Error (HTTP 500)" >&2; exit 1 ;;
      network) echo "error connecting to api.github.com" >&2; exit 1 ;;
      malformed) echo "<html>not json"; exit 0 ;;
      noassets) echo '{"id": 1}'; exit 0 ;;
    esac
    if [ "$(jq -r .exists "$state")" != true ]; then echo "gh: Not Found (HTTP 404)" >&2; exit 1; fi
    if [ -n "${STUB_TAMPER:-}" ] && [ "$n" -ge "${STUB_TAMPER_FROM:-2}" ]; then
      if [ "$STUB_TAMPER_MODE" = delete ]; then
        jq --arg n "$STUB_TAMPER" '.assets |= map(select(.name != $n))' "$state" | jq '{assets: .assets}'
      else
        jq --arg n "$STUB_TAMPER" '.assets |= map(if .name == $n then .digest = "sha256:dead" else . end)' "$state" | jq '{assets: .assets}'
      fi
      exit 0
    fi
    jq '{assets: .assets}' "$state"
    ;;
  release)
    case "$2" in
      upload|create)
        [ "${STUB_UPLOAD_RC:-0}" = 0 ] || exit "$STUB_UPLOAD_RC"
        for a in "${@:3}"; do
          if [ -f "$a" ]; then
            d="sha256:$(sha256sum "$a" | cut -d' ' -f1)"
            jq --arg n "$(basename "$a")" --arg d "$d" '.assets += [{name: $n, digest: $d}] | .exists = true' "$state" > "$state.new"
            mv "$state.new" "$state"
          fi
        done
        jq '.exists = true' "$state" > "$state.new"; mv "$state.new" "$state"
        ;;
      *) echo "unexpected gh call: $*" >&2; exit 99 ;;
    esac
    ;;
  *) echo "unexpected gh call: $*" >&2; exit 99 ;;
esac
"""


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


@pytest.fixture
def sandbox(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    gh = bindir / "gh"
    gh.write_text(STUB)
    gh.chmod(0o755)
    work = tmp_path / "work"
    (work / "notes").mkdir(parents=True)
    return tmp_path, work


def run_upload(sandbox, name, job, dirname, files, remote=None, extra_env=None):
    """remote: None for no release, else {asset name: digest or None}."""
    tmp, work = sandbox
    asset_dir = work / dirname
    asset_dir.mkdir(exist_ok=True)
    for fname, content in files.items():
        (asset_dir / fname).write_bytes(content)
    state = tmp / "state.json"
    state.write_text(
        json.dumps(
            {"exists": remote is not None, "assets": [{"name": n, "digest": d} for n, d in (remote or {}).items()]}
        )
    )
    log, count = tmp / "gh.log", tmp / "count"
    log.write_text("")
    count.write_text("0")
    step = step_named(doc_of(name), job, UPLOAD)
    env = {
        "PATH": f"{tmp / 'bin'}:{os.environ['PATH']}",
        "GH_TOKEN": "x",
        "GH_REPO": "o/r",
        "TAG": "v1.0.0",
        "TITLE": "",
        "ASSET_DIR": dirname,
        "STUB_LOG": str(log),
        "STUB_STATE": str(state),
        "STUB_COUNT": str(count),
        "RUNNER_TEMP": str(tmp),
        "TMPDIR": str(tmp),
        **(extra_env or {}),
    }
    assert set(step["env"]) >= {"GH_TOKEN", "GH_REPO", "TAG", "TITLE", "ASSET_DIR"}
    result = subprocess.run(["bash", "-c", step["run"]], env=env, cwd=work, capture_output=True, text=True, check=False)
    return result, log.read_text().splitlines(), int(count.read_text())


def writes(calls):
    return [c for c in calls if c.startswith(("release upload", "release create"))]


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_new_release_is_created_then_rechecked(sandbox, name, job, dirname):
    result, calls, api_calls = run_upload(sandbox, name, job, dirname, {"a.whl": b"A", "SHA256SUMS": b"S"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert [c for c in calls if c.startswith("release create v1.0.0")]
    assert api_calls >= 2, "the asset set must be re-read after the create"
    assert not any("--clobber" in c for c in calls)


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_existing_identical_release_uploads_nothing(sandbox, name, job, dirname):
    files = {"a.whl": b"A", "SHA256SUMS": b"S"}
    result, calls, api_calls = run_upload(
        sandbox, name, job, dirname, files, remote={n: digest(c) for n, c in files.items()}
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert writes(calls) == []
    assert api_calls >= 2, "even with nothing to upload the set is re-read before success"


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_partial_release_is_completed_with_only_the_missing_assets(sandbox, name, job, dirname):
    files = {"a.whl": b"A", "b.tar.gz": b"B"}
    result, calls, _ = run_upload(sandbox, name, job, dirname, files, remote={"a.whl": digest(b"A")})
    assert result.returncode == 0, result.stdout + result.stderr
    ups = writes(calls)
    assert len(ups) == 1 and "b.tar.gz" in ups[0] and "a.whl" not in ups[0] and "--clobber" not in ups[0]


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_a_differing_asset_fails_names_it_and_uploads_nothing(sandbox, name, job, dirname):
    files = {"a.whl": b"A", "b.tar.gz": b"B"}
    result, calls, _ = run_upload(
        sandbox, name, job, dirname, files, remote={"a.whl": digest(b"A"), "b.tar.gz": "sha256:" + "0" * 64}
    )
    text = result.stdout + result.stderr
    assert result.returncode != 0 and "b.tar.gz" in text and "Burn this version and publish a new one" in text
    assert writes(calls) == []


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_an_existing_asset_without_a_digest_fails_closed(sandbox, name, job, dirname):
    result, calls, _ = run_upload(sandbox, name, job, dirname, {"a.whl": b"A"}, remote={"a.whl": None})
    assert result.returncode != 0 and "a.whl" in result.stdout + result.stderr
    assert writes(calls) == []


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_an_empty_asset_directory_fails(sandbox, name, job, dirname):
    result, calls, _ = run_upload(sandbox, name, job, dirname, {})
    assert result.returncode != 0 and writes(calls) == []


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
def test_a_failing_upload_fails_the_step(sandbox, name, job, dirname):
    result, _, _ = run_upload(sandbox, name, job, dirname, {"a.whl": b"A"}, extra_env={"STUB_UPLOAD_RC": "1"})
    assert result.returncode != 0


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
@pytest.mark.parametrize("mode", ["401", "403", "429", "500", "network", "malformed", "noassets"])
def test_lookup_failures_other_than_404_stop_the_run(sandbox, name, job, dirname, mode):
    result, calls, _ = run_upload(sandbox, name, job, dirname, {"a.whl": b"A"}, extra_env={"STUB_API_MODE": mode})
    assert result.returncode != 0, result.stdout
    assert "::error" in result.stdout
    assert writes(calls) == [], "an unclear lookup must never reach create or upload"


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
@pytest.mark.parametrize("tamper_mode", ["alter", "delete"])
def test_an_asset_changed_after_the_first_read_is_caught_when_nothing_is_uploaded(
    sandbox, name, job, dirname, tamper_mode
):
    result, calls, _ = run_upload(
        sandbox,
        name,
        job,
        dirname,
        {"a.whl": b"A"},
        remote={"a.whl": digest(b"A")},
        extra_env={"STUB_TAMPER": "a.whl", "STUB_TAMPER_MODE": tamper_mode},
    )
    assert result.returncode != 0 and "a.whl" in result.stdout + result.stderr
    assert writes(calls) == []


@pytest.mark.parametrize(("name", "job", "dirname"), CASES, ids=IDS)
@pytest.mark.parametrize("tamper_mode", ["alter", "delete"])
def test_an_asset_changed_during_the_uploads_is_caught(sandbox, name, job, dirname, tamper_mode):
    files = {"a.whl": b"A", "b.tar.gz": b"B"}
    result, calls, _ = run_upload(
        sandbox,
        name,
        job,
        dirname,
        files,
        remote={"a.whl": digest(b"A")},
        extra_env={"STUB_TAMPER": "a.whl", "STUB_TAMPER_MODE": tamper_mode, "STUB_TAMPER_FROM": "2"},
    )
    assert writes(calls), "the missing asset was uploaded first"
    assert result.returncode != 0 and "a.whl" in result.stdout + result.stderr


# --- documented callers -------------------------------------------------------------------------------------

DOC_FILES = [REPO / "README.md", *sorted((REPO / "docs").rglob("*.md")), *sorted((REPO / "fixture").rglob("*.md"))]
FENCE = re.compile(r"```ya?ml\n(.*?)```", re.S)
REUSABLES = ("python-package-release.yml@", "artifact-release.yml@")


def release_event_callers_without_allow_list(text: str) -> list[str]:
    """Fenced YAML blocks that call a publishing reusable workflow, publish on the release event, and omit the input."""
    bad = []
    for block in FENCE.findall(text):
        if not any(r in block for r in REUSABLES):
            continue
        keyed_on_release = re.search(r"^\s*publish:.*['\"]release['\"]", block, re.M) or re.search(
            r"^\s*release:", block, re.M
        )
        if not keyed_on_release:
            continue
        m = re.search(r"^\s*allowed-publish-events:\s*(\S+)", block, re.M)
        if not m or "release" not in m.group(1).split(","):
            bad.append(block.splitlines()[0])
    return bad


def test_every_documented_release_event_caller_sets_the_allow_list():
    scanned = 0
    for path in DOC_FILES:
        text = path.read_text()
        scanned += sum(1 for b in FENCE.findall(text) if any(r in b for r in REUSABLES))
        assert release_event_callers_without_allow_list(text) == [], f"{path.relative_to(REPO)}"
    assert scanned >= 3, "the scan found no caller examples; the pattern is broken"


def test_the_docs_scanner_bites():
    sample = (
        "```yaml\non:\n  release: { types: [published] }\njobs:\n  p:\n"
        "    uses: o/r/.github/workflows/python-package-release.yml@abc # v1\n"
        "    with:\n      publish: ${{ github.event_name == 'release' }}\n```\n"
    )
    assert release_event_callers_without_allow_list(sample)
    assert not release_event_callers_without_allow_list(
        sample.replace("    with:\n", "    with:\n      allowed-publish-events: push,release\n")
    )
    assert release_event_callers_without_allow_list(
        sample.replace("    with:\n", "    with:\n      allowed-publish-events: push\n")
    )
