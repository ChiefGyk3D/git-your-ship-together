"""container-release.yml: the multi-arch index is built from digests, and publishing is an allow-list.

The YAML tests pin the structure; the script tests run the real step bodies under bash with a stub `docker`,
the way a runner would, including cases that must be refused.
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
GATE = "needs.plan.outputs.publish == 'true'"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def step(job: str, name: str) -> dict:
    found = [s for s in steps_of(jobs(load(RELEASE))[job]) if s.get("name") == name]
    assert len(found) == 1, (job, name, len(found))
    return found[0]


def run_script(script: str, tmp_path: Path, env: dict[str, str], docker: str | None = None):
    out = tmp_path / "github_output"
    out.write_text("")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if docker is not None:
        fake = bin_dir / "docker"
        fake.write_text(docker)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    full = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "GITHUB_OUTPUT": str(out), **env}
    proc = subprocess.run(["bash", "-c", script], env=full, capture_output=True, text=True, cwd=tmp_path)
    written = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
    return proc.returncode, written, proc.stdout + proc.stderr


# --- the publish allow-list -------------------------------------------------


def decide(tmp_path, **env):
    base = {"PUSH": "true", "EVENT": "push", "REF": "refs/tags/v1.2.3", "ALLOWED_EVENTS": "push", "REQUIRE_TAG": "true"}
    code, written, out = run_script(step("plan", "Decide whether to publish")["run"], tmp_path, {**base, **env})
    assert code == 0, out
    return written["publish"]


def test_the_inputs_default_to_the_narrow_allow_list():
    inputs = triggers(load(RELEASE))["workflow_call"]["inputs"]
    assert inputs["allowed-publish-events"]["default"] == "push"
    assert inputs["require-tag-ref"]["default"] is True


@pytest.mark.parametrize("ref", ["refs/tags/v1.2.3", "refs/tags/v0.0.1-rc.1", "refs/tags/v9"])
def test_a_push_of_a_v_tag_publishes(tmp_path, ref):
    assert decide(tmp_path, REF=ref) == "true"


@pytest.mark.parametrize(
    "env",
    [
        {"EVENT": "pull_request"},
        {"EVENT": "pull_request_target"},
        {"EVENT": "workflow_dispatch"},
        {"EVENT": "workflow_run"},
        {"EVENT": "repository_dispatch"},
        {"EVENT": "schedule"},
        {"EVENT": "release"},
        {"EVENT": "Push"},
        {"EVENT": "push", "REF": "refs/heads/main"},
        {"EVENT": "push", "REF": "refs/heads/v1.2.3"},
        {"EVENT": "push", "REF": "refs/tags/1.2.3"},
        {"EVENT": "push", "REF": "refs/tags/release-v1"},
        {"EVENT": "push", "REF": "refs/pull/1/merge"},
        {"EVENT": "push", "REF": ""},
        {"PUSH": "false"},
        {"PUSH": ""},
        {"PUSH": "True"},
        {"EVENT": "pull_request", "ALLOWED_EVENTS": "*", "REQUIRE_TAG": "false"},
        {"EVENT": "pull_request", "ALLOWED_EVENTS": "pull_request", "REQUIRE_TAG": "false"},
        {"EVENT": "workflow_dispatch", "ALLOWED_EVENTS": "push, release"},
        {"EVENT": "push", "ALLOWED_EVENTS": ""},
    ],
    ids=lambda e: ",".join(f"{k}={v}" for k, v in e.items()),
)
def test_everything_else_is_refused(tmp_path, env):
    assert decide(tmp_path, **env) == "false"


def test_the_old_behaviour_is_reachable_only_through_explicit_inputs(tmp_path):
    old = {"ALLOWED_EVENTS": "*", "REQUIRE_TAG": "false", "REF": "refs/heads/main"}
    assert decide(tmp_path, EVENT="workflow_dispatch", **old) == "true"
    assert decide(tmp_path, EVENT="push", **old) == "true"
    assert decide(tmp_path, EVENT="pull_request", **old) == "false"
    # Each half is separate: widening the events alone still needs a tag.
    assert decide(tmp_path, EVENT="workflow_dispatch", ALLOWED_EVENTS="*", REF="refs/heads/main") == "false"
    assert decide(tmp_path, EVENT="workflow_dispatch", ALLOWED_EVENTS="push, workflow_dispatch") == "true"


# --- every step that pushes or signs is gated on the decision ----------------


def publishing_steps() -> list[tuple[str, dict]]:
    found = []
    for job_name in ("build", "merge"):
        for s in steps_of(jobs(load(RELEASE))[job_name]):
            uses = str(s.get("uses", ""))
            run = s.get("run", "") or ""
            with_ = s.get("with") or {}
            if (
                uses.startswith(("docker/login-action@", "actions/attest-build-provenance@", "anchore/sbom-action@"))
                or (uses.startswith("docker/build-push-action@") and with_.get("push") is True)
                or "cosign sign" in run
                or "cosign attest" in run
                or "imagetools create" in run
                or "digest" in str(s.get("id", ""))
            ):
                found.append((job_name, s))
    return found


def test_every_pushing_or_signing_step_is_gated_on_the_publish_decision():
    found = publishing_steps()
    assert len(found) >= 9, [s.get("name") for _, s in found]
    for job_name, s in found:
        cond = str(s.get("if", ""))
        assert GATE in cond, f"{job_name}: {s.get('name')!r} is not gated on the publish decision"
        assert "inputs.push" not in cond, f"{job_name}: {s.get('name')!r} still gates on the raw input"


def test_the_merge_job_is_gated_on_the_decision_and_never_runs_for_a_pull_request():
    cond = str(jobs(load(RELEASE))["merge"]["if"])
    assert GATE in cond and "github.event_name != 'pull_request'" in cond and "inputs.push" not in cond


def test_the_guard_bites_on_a_mutated_workflow():
    """Negative case: a step with the old gate is found by the same check."""
    old = {"name": "x", "uses": "docker/login-action@" + "0" * 40, "if": "inputs.push"}
    assert GATE not in str(old["if"])


def test_the_decision_is_made_in_the_plan_job_and_exported():
    plan = jobs(load(RELEASE))["plan"]
    assert plan["outputs"]["publish"] == "${{ steps.publish.outputs.publish }}"
    env = step("plan", "Decide whether to publish")["env"]
    assert env["EVENT"] == "${{ github.event_name }}" and env["REF"] == "${{ github.ref }}"
    assert env["ALLOWED_EVENTS"] == "${{ inputs.allowed-publish-events }}"
    assert env["REQUIRE_TAG"] == "${{ inputs.require-tag-ref }}"


# --- digests, not tags ------------------------------------------------------


def test_temporary_tags_carry_the_run_id_and_attempt():
    tags = step("build", "Build and push this platform's image")["with"]["tags"]
    for part in ("github.sha", "github.run_id", "github.run_attempt", "matrix.arch"):
        assert part in tags


def test_the_build_job_hands_each_platform_digest_to_merge_through_outputs():
    build = jobs(load(RELEASE))["build"]
    outputs = build["outputs"]
    assert len(outputs) >= 8
    for key, value in outputs.items():
        assert value == f"${{{{ steps.record.outputs.{key} }}}}"
    rec = step("build", "Record this platform's digest")
    assert rec["id"] == "record"
    assert rec["env"]["DIGEST"] == "${{ steps.push.outputs.digest }}"
    assert rec["env"]["PLATFORM"] == "${{ matrix.platform }}"


def test_the_index_is_created_from_digest_references_not_tags():
    s = step("merge", "Create the multi-arch index")
    assert "SHA" not in s["env"], "the index must not rebuild temporary tag names"
    run = s["run"]
    assert "${GHCR}:${SHA}" not in run and "${SHA}-" not in run
    assert "@${digest}" in run or "@$digest" in run
    for n in range(8):
        assert s["env"][f"D{n}"] == f"${{{{ needs.build.outputs.d{n} }}}}"


def test_the_plan_numbers_the_platforms_and_bounds_them():
    run = step("plan", "Plan the matrix")["run"]
    assert "idx" in run and "-gt 8" in run


# Stub registry: `docker buildx imagetools inspect REF --format ...` prints the config of the image at REF.
def stub(configs: dict[str, dict], tmp_path: Path) -> str:
    (tmp_path / "configs.json").write_text(json.dumps(configs))
    return f"""#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
cfg = json.load(open({str(tmp_path / "configs.json")!r}))
if a[:3] == ["buildx", "imagetools", "inspect"]:
    ref = a[3]
    if ref not in cfg:
        sys.exit(1)
    print(json.dumps(cfg[ref]))
elif a[:3] == ["buildx", "imagetools", "create"]:
    open({str(tmp_path / "create.log")!r}, "a").write(" ".join(a) + "\\n")
else:
    sys.exit(2)
"""


GHCR = "ghcr.io/owner/img"
AMD = {"os": "linux", "architecture": "amd64"}
ARM = {"os": "linux", "architecture": "arm64", "variant": "v8"}
MATRIX = json.dumps(
    [
        {"platform": "linux/amd64", "arch": "linux-amd64", "runner": "x", "idx": 0},
        {"platform": "linux/arm64", "arch": "linux-arm64", "runner": "y", "idx": 1},
    ]
)


def test_record_accepts_a_digest_whose_platform_matches(tmp_path):
    docker = stub({f"{GHCR}@{DIGEST_A}": AMD}, tmp_path)
    env = {"DIGEST": DIGEST_A, "PLATFORM": "linux/amd64", "IDX": "0", "GHCR": GHCR}
    code, out, log = run_script(step("build", "Record this platform's digest")["run"], tmp_path, env, docker)
    assert code == 0, log
    assert out["d0"] == f"linux/amd64 {DIGEST_A}"


@pytest.mark.parametrize(
    "env,configs",
    [
        ({"DIGEST": DIGEST_A}, {f"{GHCR}@{DIGEST_A}": ARM}),  # the digest is another architecture
        ({"DIGEST": ""}, {}),  # the push produced no digest
        ({"DIGEST": "latest"}, {}),
        ({"DIGEST": "sha256:abc"}, {}),
        ({"DIGEST": DIGEST_A + "\nx=y"}, {f"{GHCR}@{DIGEST_A}": AMD}),
        ({"DIGEST": DIGEST_A}, {}),  # the registry does not have it
    ],
)
def test_record_refuses_a_missing_malformed_or_mismatched_digest(tmp_path, env, configs):
    docker = stub(configs, tmp_path)
    full = {"PLATFORM": "linux/amd64", "IDX": "0", "GHCR": GHCR, **env}
    code, out, _ = run_script(step("build", "Record this platform's digest")["run"], tmp_path, full, docker)
    assert code != 0 and "d0" not in out


def index_env(**over):
    base = {
        "GHCR": GHCR,
        "TAGS": "ghcr.io/owner/img:1.2.3\nghcr.io/owner/img:latest",
        "PLATFORMS": "linux/amd64,linux/arm64",
        "MATRIX": MATRIX,
        "D0": f"linux/amd64 {DIGEST_A}",
        "D1": f"linux/arm64 {DIGEST_B}",
        **{f"D{n}": "" for n in range(2, 8)},  # a runner sets every slot, empty or not
    }
    base.update(over)
    return base


CONFIGS = {f"{GHCR}@{DIGEST_A}": AMD, f"{GHCR}@{DIGEST_B}": ARM, "ghcr.io/owner/img:1.2.3": AMD}


def test_the_index_step_merges_exactly_the_recorded_digests(tmp_path):
    docker = stub(CONFIGS, tmp_path)
    code, _, log = run_script(step("merge", "Create the multi-arch index")["run"], tmp_path, index_env(), docker)
    assert code == 0, log
    created = (tmp_path / "create.log").read_text()
    assert f"{GHCR}@{DIGEST_A}" in created and f"{GHCR}@{DIGEST_B}" in created
    assert "--tag ghcr.io/owner/img:1.2.3" in created
    assert "-linux-" not in created, "no temporary tag name may reach the merge"


@pytest.mark.parametrize(
    "over,configs",
    [
        ({"D1": ""}, CONFIGS),  # a platform produced no digest
        ({"D1": f"linux/amd64 {DIGEST_B}"}, CONFIGS),  # recorded under the wrong platform
        ({"D1": f"linux/arm64 {DIGEST_A}"}, CONFIGS),  # the digest is an amd64 image, labelled arm64
        ({"D1": f"linux/arm64 {DIGEST_B}", "D2": f"linux/arm64 {DIGEST_B}"}, CONFIGS),  # an extra slot
        ({"D1": "linux/arm64 sha256:xyz"}, CONFIGS),
        ({"D0": f"linux/amd64 {DIGEST_A}"}, {k: v for k, v in CONFIGS.items() if k != f"{GHCR}@{DIGEST_A}"}),
    ],
)
def test_the_index_step_refuses_a_missing_extra_or_mismatched_digest(tmp_path, over, configs):
    docker = stub(configs, tmp_path)
    code, _, _ = run_script(step("merge", "Create the multi-arch index")["run"], tmp_path, index_env(**over), docker)
    assert code != 0
    assert not (tmp_path / "create.log").exists(), "nothing may be merged after a refusal"
