"""container-release.yml: one build per leg, merge by digest, and publishing as an allow-list.

Structure tests parse the real workflow with a strict checker, and mutation tests weaken each guard in a copy and
require the same checker to go red. Script tests run the real step bodies under bash with a stub `docker`, the way a
runner would, including inputs that must be refused.
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

RELEASE = WORKFLOWS / "container-release.yml"
GATE = "needs.plan.outputs.publish == 'true'"
NOT_GATE = "needs.plan.outputs.publish != 'true'"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_IDX = "sha256:" + "c" * 64
GHCR = "ghcr.io/owner/img"

# Extra terms a gated step's condition may add after the gate, each joined by `&&`. Anything else is refused.
APPROVED_TERMS = {
    "inputs.sign",
    "inputs.sbom",
    "inputs.provenance",
    "(inputs.sign || inputs.sbom)",
    "inputs.dockerhub",
    "steps.names.outputs.dockerhub != ''",
    "github.event_name != 'pull_request'",
}
# Steps that may run without the gate: they hold no push, signing or attestation ability, or are gated by an
# output that only a gated step sets. A new step must be gated or be added here on purpose.
BUILD_UNGATED = {
    "Egress canary (EX-0001)",
    "Image metadata",
    "Require a non-root user",
    "Check the image",
    "Probe with a read-only root filesystem",
    "Suppress Trivy secret findings under installed Python package roots",
    "Scan the image with Trivy",
    "Upload Trivy results to the Security tab",
}
BUILD_UNGATED_USES = (
    "step-security/harden-runner@",
    "actions/checkout@",
    "docker/setup-qemu-action@",
    "docker/setup-buildx-action@",
)
MERGE_UNGATED = {
    "Validate the egress policy inputs (EX-0001)",
    "Egress canary (EX-0001)",
    "Fetch CI secrets from Doppler (OIDC)",  # gated by steps.doppler, which only a gated step sets
    "Fetch CI secrets from Doppler (Service Token)",
    "Resolve image names",
    "Image metadata",
}
MERGE_UNGATED_USES = ("step-security/harden-runner@", "docker/setup-buildx-action@")


def step(job: str, name: str, doc: dict | None = None) -> dict:
    found = [s for s in steps_of(jobs(doc or load(RELEASE))[job]) if s.get("name") == name]
    assert len(found) == 1, (job, name, len(found))
    return found[0]


def terms_ok(cond: str, first: str = GATE) -> bool:
    parts = cond.split(" && ")
    return parts[0] == first and all(p in APPROVED_TERMS for p in parts[1:])


PUBLISH_ONLY_USES = ("docker/login-action@", "actions/attest-build-provenance@", "sigstore/cosign-installer@")


def violations(doc: dict) -> list[str]:
    """Every way this workflow fails the publishing invariants; empty for the real file."""
    out = []
    build, local, merge = jobs(doc)["build"], jobs(doc)["build-local"], jobs(doc)["merge"]
    mcond = str(merge.get("if", ""))
    if not (mcond.split(" && ")[0] == GATE and set(mcond.split(" && ")[1:]) <= {"github.event_name != 'pull_request'"}):
        out.append(f"merge job condition: {mcond!r}")
    if merge.get("continue-on-error"):
        out.append("merge job continue-on-error")
    # the publishing build job runs only when publishing and the local-only job only when not publishing
    bterms = str(build.get("if", "")).split(" && ")
    if GATE not in bterms or NOT_GATE in bterms:
        out.append(f"build job condition: {build.get('if')!r}")
    lterms = str(local.get("if", "")).split(" && ")
    if NOT_GATE not in lterms or GATE in lterms:
        out.append(f"build-local job condition: {local.get('if')!r}")
    perms = local.get("permissions") or {}
    if perms != {"contents": "read", "security-events": "write"}:
        out.append(f"build-local permissions: {perms!r}")
    if local.get("continue-on-error"):
        out.append("build-local job continue-on-error")
    for s in steps_of(local):
        uses, run = str(s.get("uses", "")), str(s.get("run", ""))
        pushes = uses.startswith("docker/build-push-action@") and (s.get("with") or {}).get("push") is not False
        if (
            uses.startswith(PUBLISH_ONLY_USES)
            or pushes
            or "docker push" in run
            or "cosign" in run
            or "imagetools" in run
            or "secrets." in json.dumps(s)
        ):
            out.append(f"build-local: {s.get('name') or uses} can publish or sign")
    for job_name, job, ungated, ungated_uses in (
        ("build", build, BUILD_UNGATED, BUILD_UNGATED_USES),
        ("merge", merge, MERGE_UNGATED, MERGE_UNGATED_USES),
    ):
        for s in steps_of(job):
            label = f"{job_name}: {s.get('name') or s.get('uses')}"
            name, uses = s.get("name"), str(s.get("uses", ""))
            cond = s.get("if")
            if name in ungated or uses.startswith(ungated_uses):
                if cond is not None and GATE in str(cond):
                    out.append(f"{label}: unexpectedly gated, update the allow-list")
                continue
            if name == "Doppler" or uses.startswith("docker/setup-qemu-action@"):
                continue
            if cond is None or not terms_ok(str(cond)):
                out.append(f"{label}: condition {cond!r} is not the approved publish gate")
            if s.get("continue-on-error"):
                out.append(f"{label}: continue-on-error on a guarded step")
    return out


def guarded_steps(doc: dict) -> list[tuple[str, str]]:
    return [
        (j, s["name"])
        for j in ("build", "merge")
        for s in steps_of(jobs(doc)[j])
        if s.get("name") and GATE in str(s.get("if", "")) and not str(s.get("name")).startswith("Fetch CI")
    ]


def test_the_real_workflow_satisfies_every_publishing_invariant():
    assert violations(load(RELEASE)) == []
    assert len(guarded_steps(load(RELEASE))) >= 14


def mutate(doc: dict, kind: str, job: str, name: str) -> dict:
    d = copy.deepcopy(doc)
    s = step(job, name, d)
    cond = s.get("if")
    if kind == "remove-if":
        del s["if"]
    elif kind == "or-true":
        s["if"] = f"{cond} || true"
    elif kind == "or-always":
        s["if"] = f"{cond} || always()"
    elif kind == "always-first":
        s["if"] = f"always() && {cond}"
    elif kind == "raw-input":
        s["if"] = "inputs.push"
    elif kind == "continue-on-error":
        s["continue-on-error"] = True
    return d


MUTATIONS = ["remove-if", "or-true", "or-always", "always-first", "raw-input", "continue-on-error"]


@pytest.mark.parametrize("kind", MUTATIONS)
@pytest.mark.parametrize("job,name", guarded_steps(load(RELEASE)), ids=lambda v: str(v)[:40])
def test_weakening_any_publish_guard_is_caught(kind, job, name):
    doc = load(RELEASE)
    assert violations(doc) == []
    assert violations(mutate(doc, kind, job, name)), f"{kind} on {job}/{name} went unnoticed"


@pytest.mark.parametrize("cond", ["inputs.push", "true", f"{GATE} || true", "always()", f"{GATE} && always()"])
def test_weakening_the_merge_job_condition_is_caught(cond):
    d = load(RELEASE)
    d["jobs"]["merge"]["if"] = cond
    assert violations(d)


LOCAL_MUTATIONS = {
    "packages write": lambda d: d["jobs"]["build-local"]["permissions"].update({"packages": "write"}),
    "id-token write": lambda d: d["jobs"]["build-local"]["permissions"].update({"id-token": "write"}),
    "no job condition": lambda d: d["jobs"]["build-local"].pop("if"),
    "publish condition": lambda d: d["jobs"]["build-local"].update({"if": f"x && {GATE}"}),
    "login step": lambda d: d["jobs"]["build-local"]["steps"].append(
        {"name": "login", "uses": "docker/login-action@" + "0" * 40}
    ),
    "push build": lambda d: d["jobs"]["build-local"]["steps"].append(
        {"name": "p", "uses": "docker/build-push-action@" + "0" * 40, "with": {"push": True}}
    ),
    "secret use": lambda d: d["jobs"]["build-local"]["steps"].append(
        {"name": "s", "run": "echo", "env": {"T": "${{ secrets.GITHUB_TOKEN }}"}}
    ),
    "continue-on-error": lambda d: d["jobs"]["build-local"].update({"continue-on-error": True}),
    "build job not gated": lambda d: d["jobs"]["build"].update({"if": "${{ !cancelled() }}"}),
}


@pytest.mark.parametrize("name", list(LOCAL_MUTATIONS))
def test_weakening_the_local_only_job_is_caught(name):
    d = load(RELEASE)
    assert violations(d) == []
    LOCAL_MUTATIONS[name](d)
    assert violations(d), name


def test_the_local_only_job_has_no_package_write_and_no_publish_step():
    local = jobs(load(RELEASE))["build-local"]
    assert local["permissions"] == {"contents": "read", "security-events": "write"}
    assert steps_of(local), "collected nothing"
    for s in steps_of(local):
        assert not str(s.get("uses", "")).startswith(PUBLISH_ONLY_USES), s.get("name")
        assert "secrets." not in json.dumps(s)
    build = jobs(load(RELEASE))["build"]
    assert build["permissions"]["packages"] == "write"
    merge_needs = jobs(load(RELEASE))["merge"]["needs"]
    assert "build" in merge_needs and "build-local" not in merge_needs


# The checks are one copy of text in two jobs; this holds them identical so they cannot drift.
SHARED_STEPS = (
    "Egress canary (EX-0001)",
    "Image metadata",
    "Require a non-root user",
    "Check the image",
    "Probe with a read-only root filesystem",
    "Suppress Trivy secret findings under installed Python package roots",
    "Scan the image with Trivy",
    "Upload Trivy results to the Security tab",
)


@pytest.mark.parametrize("name", SHARED_STEPS)
def test_the_check_steps_are_identical_in_the_publishing_and_the_local_job(name):
    assert step("build", name) == step("build-local", name)


def test_the_egress_policy_check_is_identical_in_both_build_jobs():
    first = [jobs(load(RELEASE))[j]["steps"][0] for j in ("build", "build-local")]
    assert first[0]["name"] == "Validate the egress policy inputs (EX-0001)" and first[0] == first[1]


def test_the_setup_steps_are_identical_in_both_build_jobs():
    prefixes = (
        "step-security/harden-runner@",
        "actions/checkout@",
        "docker/setup-qemu-action@",
        "docker/setup-buildx-action@",
    )

    def uses_of(job):
        return [s for s in steps_of(jobs(load(RELEASE))[job]) if str(s.get("uses", "")).startswith(prefixes)]

    assert uses_of("build") == uses_of("build-local") and len(uses_of("build")) == 4


def test_a_new_ungated_step_in_the_merge_job_is_caught():
    d = load(RELEASE)
    d["jobs"]["merge"]["steps"].append({"name": "Push something else", "run": "docker push x"})
    assert violations(d)
    d = load(RELEASE)
    d["jobs"]["build"]["steps"].append({"name": "Push something else", "run": "docker push x"})
    assert violations(d)


# --- one build per leg ------------------------------------------------------


def evaluate(cond: str | None, publish: bool) -> bool:
    """Evaluate the small condition language used on build steps; unknown terms count as true."""
    if cond is None:
        return True
    for term in str(cond).split(" && "):
        if term == GATE and not publish:
            return False
        if term == NOT_GATE and publish:
            return False
    return True


def builds(doc: dict, publish: bool) -> list[str]:
    """Build-push steps that would run on a leg, over both build jobs, given the publish decision."""
    return [
        s["name"]
        for job in ("build", "build-local")
        if evaluate(jobs(doc)[job].get("if"), publish)
        for s in steps_of(jobs(doc)[job])
        if str(s.get("uses", "")).startswith("docker/build-push-action@") and evaluate(s.get("if"), publish)
    ]


@pytest.mark.parametrize("publish", [True, False])
def test_a_leg_builds_the_dockerfile_exactly_once(publish):
    assert len(builds(load(RELEASE), publish)) == 1


def test_a_publishing_leg_tests_the_pushed_image_and_a_non_publishing_leg_the_local_one():
    doc = load(RELEASE)
    assert builds(doc, True) == ["Build and push this platform's image"]
    assert builds(doc, False) == ["Build for this platform and load it"]
    names = [s.get("name") for s in steps_of(jobs(doc)["build"])]
    push, pull = names.index("Build and push this platform's image"), names.index("Pull and verify the pushed image")
    checks = [
        names.index(n)
        for n in (
            "Require a non-root user",
            "Check the image",
            "Probe with a read-only root filesystem",
            "Scan the image with Trivy",
        )
    ]
    assert push < pull < min(checks), "every check runs against the image pulled back by digest"
    assert names.index("Record this platform's digest") > max(checks), (
        "only a digest that passed the checks is handed on"
    )


def test_the_guard_for_two_builds_bites():
    doc = load(RELEASE)
    del doc["jobs"]["build-local"]["if"]
    assert len(builds(doc, True)) == 2
    assert violations(doc)


# --- the publish decision ---------------------------------------------------


def run_script(script: str, tmp_path: Path, env: dict[str, str], docker: str | None = None):
    out = tmp_path / "github_output"
    out.write_text("")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if docker is not None:
        fake = bin_dir / "docker"
        fake.write_text(docker)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    full = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(out),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        **env,
    }
    proc = subprocess.run(["bash", "-c", script], env=full, capture_output=True, text=True, cwd=tmp_path)
    written = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
    return proc.returncode, written, proc.stdout + proc.stderr


BASE = {"PUSH": "true", "EVENT": "push", "REF": "refs/tags/v1.2.3", "ALLOWED_EVENTS": "push", "REQUIRE_TAG": "true"}


def decide(tmp_path, script: str | None = None, **env):
    code, written, out = run_script(
        script or step("plan", "Decide whether to publish")["run"], tmp_path, {**BASE, **env}
    )
    return code, written.get("publish"), out


def test_the_inputs_default_to_the_narrow_allow_list():
    inputs = triggers(load(RELEASE))["workflow_call"]["inputs"]
    assert inputs["allowed-publish-events"]["default"] == "push"
    assert inputs["require-tag-ref"]["default"] is True


@pytest.mark.parametrize(
    "ref",
    [
        "refs/tags/v1.2.3",
        "refs/tags/v0.0.1",
        "refs/tags/v10.20.300",
        "refs/tags/v1.2.3-rc.1",
        "refs/tags/v1.2.3-0",
        "refs/tags/v1.2.3-alpha-1.x.9",
        "refs/tags/v1.2.3+build.5",
        "refs/tags/v1.2.3-rc.1+build.5.7",
        "refs/tags/v1.2.3-0a",
    ],
)
def test_a_push_of_a_semver_tag_publishes(tmp_path, ref):
    assert decide(tmp_path, REF=ref)[:2] == (0, "true")


# Refused: not an allowed event, not a SemVer 2.0.0 tag, or push not requested.
REFUSE_REFS = [
    "refs/tags/v9",
    "refs/tags/v1.2",
    "refs/tags/vX",
    "refs/tags/v-malware",
    "refs/tags/vnot-a-release",
    "refs/tags/v1.2.3-anything-goes!",
    "refs/tags/v01.2.3",
    "refs/tags/v1.02.3",
    "refs/tags/v1.2.03",
    "refs/tags/v1.2.3-01",
    "refs/tags/v1.2.3-rc.01",
    "refs/tags/v1.2.3-",
    "refs/tags/v1.2.3-.rc",
    "refs/tags/v1.2.3-rc.",
    "refs/tags/v1.2.3-rc..1",
    "refs/tags/v1.2.3+",
    "refs/tags/v1.2.3+a..b",
    "refs/tags/v1.2.3+a.",
    "refs/tags/v1.2.3+a+b",
    "refs/tags/v1.2.3-rc.1+",
    "refs/tags/v1.2.3.4",
    "refs/tags/v1.2.3\n",
    "refs/tags/v1.2.3\nx",
    "refs/tags/V1.2.3",
    "refs/tags/1.2.3",
    "refs/tags/release-v1.2.3",
    "refs/tags/v1.2.3/extra",
    "refs/heads/main",
    "refs/heads/v1.2.3",
    "refs/pull/1/merge",
    "",
]
REFUSE_ENV = [
    {"EVENT": "pull_request"},
    {"EVENT": "pull_request_target"},
    {"EVENT": "workflow_dispatch"},
    {"EVENT": "workflow_run"},
    {"EVENT": "repository_dispatch"},
    {"EVENT": "schedule"},
    {"EVENT": "release"},
    {"EVENT": "Push"},
    {"EVENT": ""},
    {"PUSH": "false"},
    {"PUSH": ""},
    {"PUSH": "True"},
    {"EVENT": "pull_request", "ALLOWED_EVENTS": "*", "REQUIRE_TAG": "false"},
    {"EVENT": "pull_request_target", "ALLOWED_EVENTS": "*", "REQUIRE_TAG": "false"},
    {"EVENT": "pull_request", "ALLOWED_EVENTS": "pull_request", "REQUIRE_TAG": "false"},
    {"EVENT": "workflow_dispatch", "ALLOWED_EVENTS": "push,release"},
    {"EVENT": "push", "REF": "refs/heads/main"},
    {"EVENT": "push", "REF": "refs/heads/main", "REQUIRE_TAG": ""},
    {"EVENT": "push", "REF": "refs/heads/main", "REQUIRE_TAG": "False"},
]
REFUSE_CASES = [{"REF": r} for r in REFUSE_REFS] + REFUSE_ENV


def case_id(env):
    return ",".join(f"{k}={v!r}" for k, v in env.items())


@pytest.mark.parametrize("env", REFUSE_CASES, ids=case_id)
def test_everything_else_does_not_publish(tmp_path, env):
    code, publish, out = decide(tmp_path, **env)
    assert code == 0 and publish == "false", out


def test_a_refused_publish_is_loud_and_names_the_inputs(tmp_path):
    code, publish, out = decide(tmp_path, EVENT="schedule", REF="refs/heads/main")
    assert publish == "false"
    assert "::warning" in out and "allowed-publish-events" in out and "require-tag-ref" in out
    summary = (tmp_path / "summary").read_text()
    assert "allowed-publish-events" in summary and "require-tag-ref: false" in summary
    # a run that did not ask to push stays quiet
    code, publish, out = decide(tmp_path, PUSH="false", EVENT="pull_request")
    assert "::warning" not in out


REFUSAL_REASONS = [
    ({"EVENT": "schedule", "REF": "refs/heads/main"}, "is not in allowed-publish-events"),
    ({"EVENT": "workflow_dispatch", "REF": "refs/heads/main"}, "is not in allowed-publish-events"),
    ({"EVENT": "push", "REF": "refs/heads/main"}, "is not a vMAJOR.MINOR.PATCH release tag"),
    ({"EVENT": "push", "REF": "refs/tags/v1.2"}, "is not a vMAJOR.MINOR.PATCH release tag"),
    ({"EVENT": "pull_request", "REF": "refs/pull/1/merge"}, "pull requests never publish"),
    ({"EVENT": "pull_request_target", "REF": "refs/heads/main"}, "pull requests never publish"),
]


@pytest.mark.parametrize("env,reason", REFUSAL_REASONS, ids=lambda v: case_id(v) if isinstance(v, dict) else v[:20])
def test_a_push_true_caller_in_a_refused_context_gets_a_prominent_warning_and_does_not_publish(tmp_path, env, reason):
    code, publish, out = decide(tmp_path, **env)
    assert code == 0 and publish == "false"
    assert "::warning title=publish skipped::" in out, "an annotation, not a log line"
    assert "::error" not in out, "a warning, not a failure"
    summary = (tmp_path / "summary").read_text()
    for text in (out, summary):
        assert reason in text
        assert "allowed-publish-events" in text and "require-tag-ref" in text
    assert "### Publish skipped" in summary and "did NOT publish" in summary
    assert f"event '{env['EVENT']}'" in summary and f"ref '{env['REF']}'" in summary


def test_the_allowed_direction_publishes_and_says_nothing_about_a_skip(tmp_path):
    code, publish, out = decide(tmp_path, EVENT="push", REF="refs/tags/v1.2.3")
    assert code == 0 and publish == "true"
    assert "publish skipped" not in out and "::warning" not in out
    summary = tmp_path / "summary"
    assert not summary.exists() or summary.read_text() == ""
    # the widened inputs of the migration note publish from a branch, schedule and manual run
    for event in ("push", "schedule", "workflow_dispatch"):
        sub = tmp_path / event
        sub.mkdir()
        code, publish, out = decide(
            sub,
            EVENT=event,
            REF="refs/heads/main",
            ALLOWED_EVENTS="push,schedule,workflow_dispatch",
            REQUIRE_TAG="false",
        )
        assert publish == "true" and "publish skipped" not in out


def test_a_refused_run_skips_the_publishing_jobs_and_runs_only_the_local_build():
    doc = load(RELEASE)
    ran = {
        publish: [j for j in ("build", "build-local", "merge") if evaluate(jobs(doc)[j].get("if"), publish)]
        for publish in (True, False)
    }
    assert ran == {True: ["build", "merge"], False: ["build-local"]}


def test_the_breaking_change_is_documented_with_the_caller_inputs():
    root = WORKFLOWS.parent.parent
    for doc in (root / "README.md", root / "docs" / "wiki" / "Workflow-container-release.md"):
        text = doc.read_text()
        assert "BREAKING" in text, doc.name
        for needle in (
            "allowed-publish-events",
            "require-tag-ref: false",
            "penguin-overlord",
            "solarstorm_scout",
            "hypeman",
            "vMAJOR.MINOR.PATCH",
        ):
            assert needle in text, (doc.name, needle)


def test_the_docker_hub_cross_registry_copy_is_documented_as_observed_behavior():
    root = WORKFLOWS.parent.parent
    for doc in (root / "README.md", root / "docs" / "wiki" / "Workflow-container-release.md"):
        text = doc.read_text()
        assert "41512180852" in text and "observed" in text and "Stream-Daemon" in text, doc.name
    assert "41512180852" in Path(__file__).read_text(), "the stub documents where its default comes from"


@pytest.mark.parametrize(
    "value",
    [
        "p u s h",
        " push",
        "push ",
        "push, release",
        "push,",
        ",push",
        "push,,release",
        "Push",
        "PUSH",
        "push\nrelease",
        "pu\nsh",
        "push;",
        "push-x",
        "push1",
        "*,push",
        "push,*",
        "**",
        "?",
        "",
        "push,push",
        "pu*",
        "push\t",
    ],
)
def test_a_malformed_event_list_is_an_error_not_normalized(tmp_path, value):
    code, publish, out = decide(tmp_path, ALLOWED_EVENTS=value)
    assert code != 0 and publish is None and "allowed-publish-events" in out


@pytest.mark.parametrize(
    "value", ["push", "push,release", "workflow_dispatch,schedule,push", "*", "repository_dispatch"]
)
def test_a_well_formed_event_list_is_accepted(tmp_path, value):
    assert decide(tmp_path, ALLOWED_EVENTS=value)[0] == 0


def test_the_old_behaviour_is_reachable_only_through_explicit_inputs(tmp_path):
    old = {"ALLOWED_EVENTS": "*", "REQUIRE_TAG": "false", "REF": "refs/heads/main"}
    assert decide(tmp_path, EVENT="workflow_dispatch", **old)[1] == "true"
    assert decide(tmp_path, EVENT="schedule", **old)[1] == "true"
    assert decide(tmp_path, EVENT="pull_request", **old)[1] == "false"
    assert decide(tmp_path, EVENT="workflow_dispatch", ALLOWED_EVENTS="*", REF="refs/heads/main")[1] == "false"
    assert decide(tmp_path, EVENT="workflow_dispatch", ALLOWED_EVENTS="push,workflow_dispatch")[1] == "true"
    assert decide(tmp_path, EVENT="push", REF="refs/heads/main", REQUIRE_TAG="false")[1] == "true"


def any_refused_case_publishes(tmp_path_factory, script: str) -> bool:
    for env in REFUSE_CASES:
        tmp = tmp_path_factory.mktemp("m")
        _, publish, _ = decide(tmp, script=script, **env)
        if publish == "true":
            return True
    return False


def weakened_scripts() -> dict[str, str]:
    s = step("plan", "Decide whether to publish")["run"]
    pr = 'pull_request | pull_request_target | "")'
    assert pr in s
    start = s.index("is_semver_release_tag() {")
    end = s.index("\n}\n", start) + 3
    out = {
        "no pull_request refusal": s.replace(pr, '"")'),
        "tag check always passes": s[:start] + "is_semver_release_tag() { return 0; }\n" + s[end:],
        "tag check ignored": s.replace('"$REQUIRE_TAG" != "false"', '"$REQUIRE_TAG" = "never"'),
        "any event allowed": s.replace('*",$EVENT,"*)', "*)"),
        "push input ignored": s.replace('if [ "$PUSH" = "true" ]; then', "if true; then"),
        "leading zeroes allowed": s.replace("(0|[1-9][0-9]*)", "[0-9]+"),
    }
    for name, mutated in out.items():
        assert mutated != s, name
    return out


@pytest.mark.parametrize("name", list(weakened_scripts()))
def test_weakening_the_decision_script_is_caught(tmp_path_factory, name):
    real = step("plan", "Decide whether to publish")["run"]
    assert not any_refused_case_publishes(tmp_path_factory, real)
    assert any_refused_case_publishes(tmp_path_factory, weakened_scripts()[name]), name


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


def test_the_build_job_hands_each_platform_digest_to_merge_through_distinct_outputs():
    outputs = jobs(load(RELEASE))["build"]["outputs"]
    assert sorted(outputs) == [f"d{n}" for n in range(8)]
    for key, value in outputs.items():
        assert value == f"${{{{ steps.record.outputs.{key} }}}}"
    rec = step("build", "Record this platform's digest")
    assert rec["id"] == "record" and rec["env"]["IDX"] == "${{ matrix.idx }}"
    assert rec["env"]["DIGEST"] == "${{ steps.push.outputs.digest }}"


def function_text(script: str, name: str) -> str:
    start = script.index(f"{name}() {{")
    return script[start : script.index("\n}\n", start) + 3]


def test_the_platform_check_is_the_same_function_in_both_jobs():
    a = function_text(step("build", "Pull and verify the pushed image")["run"], "verify_platform_image")
    b = function_text(step("merge", "Create the multi-arch index")["run"], "verify_platform_image")
    assert a == b


def test_the_index_is_staged_under_a_run_scoped_tag_and_promoted_by_digest():
    s = step("merge", "Create the multi-arch index")
    assert "SHA" in s["env"] and "RUN_ID" in s["env"] and "RUN_ATTEMPT" in s["env"]
    assert s["env"]["RUN_ID"] == "${{ github.run_id }}" and s["env"]["RUN_ATTEMPT"] == "${{ github.run_attempt }}"
    run = s["run"]
    assert "stage-${SHA}-${RUN_ID}-${RUN_ATTEMPT}" in run
    assert '"${GHCR}@${digest}"' in run, "final tags are created from the validated digest"
    for n in range(8):
        assert s["env"][f"D{n}"] == f"${{{{ needs.build.outputs.d{n} }}}}"


# A stateful stub registry with one manifest store per registry host. `create --tag T src...` resolves each source
# in its own host, copies a source from another host into the destination host (what buildx was observed to do in a
# production run: "copying <digest> from ghcr.io/... to docker.io/..."; `strict` models the stricter reading of the
# documentation, where a source must already exist in the destination registry and create fails), builds an index
# from the sources (a single index source is copied unchanged), and moves every named tag. `hooks` simulate another
# writer moving a tag after the Nth create; `drops_last` / `adds_extra` (optionally for one `flaw_host`) simulate a
# misbehaving create. What it cannot model is a real registry and the real buildx output format.
# DEFAULT: cross-registry copy is allowed. That is observed behavior of the original workflow in production:
# ChiefGyk3D/Stream-Daemon run 41512180852 (2026-11-02, success, dockerhub enabled) shows buildx logging
# `copying sha256:... from ghcr.io/... to docker.io/...` and publishing one index digest to both registries.
# `strict` stays as a documented risk: the Docker documentation says sources must already exist in the
# destination registry; if a future buildx enforced that, the Docker Hub path fails closed (see the
# strict-mode test) before anything is signed.
STUB = r"""#!/usr/bin/env python3
import hashlib, json, sys
STATE = %(state)r
a = sys.argv[1:]
db = json.load(open(STATE))
open(%(log)r, "a").write(" ".join(a) + "\n")


def save():
    json.dump(db, open(STATE, "w"))


def host(ref):
    return ref.split("/")[0]


def store(h):
    return db["hosts"].setdefault(h, {})


def resolve(ref):
    h = host(ref)
    if "@" in ref:
        d = ref.split("@", 1)[1]
    else:
        d = db["tags"].get(ref)
    if d is None or d not in store(h):
        sys.exit(1)
    return d


def copy(d, src, dst):
    m = store(src)[d]
    for c in m.get("manifests", []):
        copy(c["digest"], src, dst)
    store(dst)[d] = m


if a[:3] == ["buildx", "imagetools", "inspect"]:
    raw = "--raw" in a
    fmt = a[a.index("--format") + 1] if "--format" in a else ""
    ref = [x for x in a[3:] if not x.startswith("--") and x != fmt][0]
    d = resolve(ref)
    m = store(host(ref))[d]
    if raw:
        print(json.dumps(m))
    elif fmt == "{{.Manifest.Digest}}":
        print(d)
    elif fmt == "{{json .Image}}":
        if "manifests" in m:
            print(json.dumps({c["platform"]: db["configs"][c["digest"]] for c in m["manifests"]}))
        elif d in db["configs"]:
            print(json.dumps(db["configs"][d]))
        else:
            print("{}")
    else:
        sys.exit(3)
elif a[:3] == ["buildx", "imagetools", "create"]:
    open(%(creates)r, "a").write(" ".join(a) + "\n")
    tags = [a[i + 1] for i, x in enumerate(a) if x == "--tag"]
    srcs = [x for i, x in enumerate(a[3:], 3) if x != "--tag" and a[i - 1] != "--tag"]
    dst = host(tags[0])
    if any(host(t) != dst for t in tags):
        sys.exit(1)
    digs = []
    for s in srcs:
        d = resolve(s)
        if host(s) != dst:
            if db.get("strict"):
                print("source manifest must exist in the destination registry", file=sys.stderr)
                sys.exit(1)
            copy(d, host(s), dst)
        digs.append(d)
    if len(digs) == 1 and "manifests" in store(dst)[digs[0]]:
        new = digs[0]
    else:
        kids = list(digs)
        if db.get("reverse_host") == dst:
            kids.reverse()
        if db.get("flaw_host") in (None, dst):
            if db.get("drops_last"):
                kids = kids[:-1]
            if db.get("adds_extra"):
                kids.append(db["adds_extra"])
        for k in kids:
            if k not in store(dst):
                copy(k, "ghcr.io", dst)
        idx = {"schemaVersion": 2, "manifests": [{"digest": k, "platform": db["platform_of"][k]} for k in kids]}
        new = "sha256:" + hashlib.sha256(json.dumps(idx, sort_keys=True).encode()).hexdigest()
        store(dst)[new] = idx
    for t in tags:
        db["tags"][t] = new
    db["creates"] = db.get("creates", 0) + 1
    for h in db.get("hooks", []):
        if h["after_create"] == db["creates"]:
            db["tags"][h["tag"]] = h["digest"]
    save()
elif a[0] == "pull":
    if a[-1].split("@", 1)[-1] not in store(host(a[-1])):
        sys.exit(1)
elif a[0] == "tag":
    pass
else:
    sys.exit(2)
"""


def stub(db: dict, tmp_path: Path) -> str:
    state = tmp_path / "registry.json"
    state.write_text(json.dumps(db))
    return STUB % {"state": str(state), "log": str(tmp_path / "docker.log"), "creates": str(tmp_path / "create.log")}


def registry_state(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "registry.json").read_text())


SINGLE_A = {"schemaVersion": 2, "config": {"digest": "sha256:" + "1" * 64}, "layers": []}
SINGLE_B = {"schemaVersion": 2, "config": {"digest": "sha256:" + "2" * 64}, "layers": []}
MULTI = {"schemaVersion": 2, "manifests": [{"digest": DIGEST_A, "platform": "linux/amd64"}]}
AMD = {"os": "linux", "architecture": "amd64"}
ARM = {"os": "linux", "architecture": "arm64", "variant": "v8"}
ARM_NOVAR = {"os": "linux", "architecture": "arm64"}
STAGE = f"{GHCR}:stage-deadbeef-7-1"
TAG1 = "ghcr.io/owner/img:1.2.3"
TAGL = "ghcr.io/owner/img:latest"
HUB = "docker.io/user/img"
HSTAGE = f"{HUB}:stage-deadbeef-7-1"
HTAG1 = f"{HUB}:1.2.3"
HTAGL = f"{HUB}:latest"


def make_db(manifests=None, **over):
    db = {
        "hosts": {
            "ghcr.io": manifests or {DIGEST_A: SINGLE_A, DIGEST_B: SINGLE_B, DIGEST_IDX: MULTI},
            "docker.io": {},
        },
        "configs": {DIGEST_A: AMD, DIGEST_B: ARM},
        "platform_of": {DIGEST_A: "linux/amd64", DIGEST_B: "linux/arm64", DIGEST_IDX: "linux/amd64"},
        "tags": {},
    }
    db.update(over)
    return db


# --- the pull/verify step (build) and the record step -----------------------


def pull_env(**over):
    base = {"DIGEST": DIGEST_A, "PLATFORM": "linux/amd64", "GHCR": GHCR}
    base.update(over)
    return base


def test_the_pushed_image_is_pulled_by_digest_and_becomes_the_image_under_test(tmp_path):
    docker = stub(make_db(), tmp_path)
    code, _, log = run_script(step("build", "Pull and verify the pushed image")["run"], tmp_path, pull_env(), docker)
    assert code == 0, log
    calls = (tmp_path / "docker.log").read_text()
    assert f"pull --platform linux/amd64 {GHCR}@{DIGEST_A}" in calls
    assert f"tag {GHCR}@{DIGEST_A} release-candidate:local" in calls


@pytest.mark.parametrize(
    "env,db",
    [
        ({"DIGEST": DIGEST_B}, {}),  # an arm64 image where amd64 was planned
        ({"DIGEST": ""}, {}),
        ({"DIGEST": "latest"}, {}),
        ({"DIGEST": "sha256:abc"}, {}),
        ({"DIGEST": "sha256:" + "A" * 64}, {}),
        ({"DIGEST": DIGEST_A + "\nx=y"}, {}),
        ({"DIGEST": "sha256:" + "9" * 64}, {}),  # the registry does not have it
        ({"DIGEST": DIGEST_IDX}, {"configs": {DIGEST_A: AMD, DIGEST_IDX: AMD}}),  # an index passes as a single image
        ({"PLATFORM": "linux/arm/v6", "DIGEST": DIGEST_B}, {}),
    ],
)
def test_a_missing_malformed_mismatched_or_multi_platform_digest_is_refused(tmp_path, env, db):
    docker = stub(make_db(**db), tmp_path)
    code, out, _ = run_script(
        step("build", "Pull and verify the pushed image")["run"], tmp_path, pull_env(**env), docker
    )
    assert code != 0
    log = tmp_path / "docker.log"
    calls = log.read_text().splitlines() if log.exists() else []
    assert not [c for c in calls if c.split()[0] in ("pull", "tag")], "nothing is pulled or tagged after a refusal"


@pytest.mark.parametrize(
    "platform,config,ok",
    [
        ("linux/arm64", ARM, True),  # omitted variant means the default, v8
        ("linux/arm64", ARM_NOVAR, True),
        ("linux/arm64/v8", ARM, True),
        ("linux/arm64/v8", ARM_NOVAR, True),
        ("linux/arm", {"os": "linux", "architecture": "arm", "variant": "v7"}, True),
        ("linux/arm", {"os": "linux", "architecture": "arm"}, True),
        ("linux/arm/v7", {"os": "linux", "architecture": "arm", "variant": "v7"}, True),
        ("linux/arm", {"os": "linux", "architecture": "arm", "variant": "v6"}, False),
        ("linux/arm/v7", {"os": "linux", "architecture": "arm", "variant": "v6"}, False),
        ("linux/arm/v6", {"os": "linux", "architecture": "arm", "variant": "v7"}, False),
        ("linux/arm/v6", {"os": "linux", "architecture": "arm"}, False),
        ("linux/arm64", {"os": "linux", "architecture": "arm64", "variant": "v9"}, False),
        ("linux/amd64", {"os": "linux", "architecture": "amd64", "variant": "v3"}, False),
        ("linux/amd64", {"os": "linux", "architecture": "arm64"}, False),
        ("linux/amd64", {"os": "windows", "architecture": "amd64"}, False),
        ("linux/amd64", {}, False),
    ],
)
def test_the_platform_must_match_including_the_variant(tmp_path, platform, config, ok):
    docker = stub(make_db(configs={DIGEST_A: config}), tmp_path)
    code, _, log = run_script(
        step("build", "Pull and verify the pushed image")["run"], tmp_path, pull_env(PLATFORM=platform), docker
    )
    assert (code == 0) == ok, log


def test_record_writes_the_slot_only_for_a_valid_digest(tmp_path):
    s = step("build", "Record this platform's digest")["run"]
    code, out, log = run_script(s, tmp_path, {"DIGEST": DIGEST_A, "PLATFORM": "linux/amd64", "IDX": "1"})
    assert code == 0 and out["d1"] == f"linux/amd64 {DIGEST_A}", log
    for env in ({"DIGEST": "x"}, {"DIGEST": ""}, {"IDX": "8"}, {"IDX": "a"}, {"IDX": "1\n2"}):
        full = {"DIGEST": DIGEST_A, "PLATFORM": "linux/amd64", "IDX": "1", **env}
        code, out, _ = run_script(s, tmp_path, full)
        assert code != 0 and not out


# --- the index step (merge) --------------------------------------------------


MATRIX = json.dumps(
    [
        {"platform": "linux/amd64", "arch": "linux-amd64", "runner": "x", "idx": 0},
        {"platform": "linux/arm64", "arch": "linux-arm64", "runner": "y", "idx": 1},
    ]
)


def index_env(hub: bool = False, **over):
    base = {
        "GHCR": GHCR,
        "HUB": HUB if hub else "",
        "TAGS": f"{TAG1}\n{TAGL}" + (f"\n{HTAG1}\n{HTAGL}" if hub else ""),
        "MATRIX": MATRIX,
        "SHA": "deadbeef",
        "RUN_ID": "7",
        "RUN_ATTEMPT": "1",
        "D0": f"linux/amd64 {DIGEST_A}",
        "D1": f"linux/arm64 {DIGEST_B}",
        **{f"D{n}": "" for n in range(2, 8)},  # a runner sets every slot, empty or not
    }
    base.update(over)
    return base


INDEX_SCRIPT = step("merge", "Create the multi-arch index")["run"]


def run_index(tmp_path, db=None, script=None, hub=False, **over):
    docker = stub(db or make_db(), tmp_path)
    return run_script(script or INDEX_SCRIPT, tmp_path, index_env(hub=hub, **over), docker)


def create_calls(tmp_path):
    p = tmp_path / "create.log"
    return p.read_text().splitlines() if p.exists() else []


def test_the_index_is_created_from_digests_and_creation_causes_the_verified_state(tmp_path):
    code, out, log = run_index(tmp_path)
    assert code == 0, log
    state = registry_state(tmp_path)
    digest = out["digest"]
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    stage_create = f"buildx imagetools create --tag {STAGE} {GHCR}@{DIGEST_A} {GHCR}@{DIGEST_B}"
    assert create_calls(tmp_path) == [
        stage_create,
        f"buildx imagetools create --tag {TAG1} {GHCR}@{digest}",
        f"buildx imagetools create --tag {TAGL} {GHCR}@{digest}",
    ]
    assert state["tags"] == {STAGE: digest, TAG1: digest, TAGL: digest}
    assert [c["digest"] for c in state["hosts"]["ghcr.io"][digest]["manifests"]] == [DIGEST_A, DIGEST_B]
    assert state["hosts"]["docker.io"] == {}, "Docker Hub off: nothing touches it"
    assert not [c for c in (tmp_path / "docker.log").read_text().splitlines() if "docker.io" in c]
    # the staged tag is read only after it was created, and the final tags are read after their creates
    order = (tmp_path / "docker.log").read_text().splitlines()
    first_inspect = next(i for i, c in enumerate(order) if "inspect" in c and STAGE in c)
    assert order.index(stage_create) < first_inspect
    last_create = max(i for i, c in enumerate(order) if "imagetools create" in c)
    assert any("inspect" in c and TAG1 in c for c in order[last_create:])


def test_with_docker_hub_each_registry_gets_its_own_verified_index(tmp_path):
    code, out, log = run_index(tmp_path, hub=True)
    assert code == 0, log
    state = registry_state(tmp_path)
    digest = out["digest"]
    assert create_calls(tmp_path) == [
        f"buildx imagetools create --tag {STAGE} {GHCR}@{DIGEST_A} {GHCR}@{DIGEST_B}",
        f"buildx imagetools create --tag {TAG1} {GHCR}@{digest}",
        f"buildx imagetools create --tag {TAGL} {GHCR}@{digest}",
        f"buildx imagetools create --tag {HSTAGE} {GHCR}@{DIGEST_A} {GHCR}@{DIGEST_B}",
        f"buildx imagetools create --tag {HTAG1} {HUB}@{digest}",
        f"buildx imagetools create --tag {HTAGL} {HUB}@{digest}",
    ]
    hub = state["hosts"]["docker.io"]
    assert digest in hub and DIGEST_A in hub and DIGEST_B in hub, "the Docker Hub repository holds its own copies"
    assert state["tags"][HTAG1] == state["tags"][HTAGL] == state["tags"][HSTAGE] == digest


def test_a_registry_that_requires_sources_to_exist_locally_fails_closed_for_docker_hub_only(tmp_path):
    strict = make_db(strict=True)
    on = tmp_path / "on"
    on.mkdir()
    code, out, _ = run_index(on, strict, hub=True)
    assert code != 0 and "digest" not in out
    off = tmp_path / "off"
    off.mkdir()
    assert run_index(off, strict, hub=False)[0] == 0


def test_docker_hub_digests_are_verified_on_their_own_and_must_match(tmp_path):
    # a Docker Hub index that differs from the GHCR one is refused, not assumed equal
    differ = make_db(adds_extra=DIGEST_IDX, flaw_host="docker.io")
    code, out, log = run_index(tmp_path, differ, hub=True)
    assert code != 0 and "digest" not in out


BAD_SLOTS = [
    {"D1": ""},  # a platform produced no digest
    {"D1": f"linux/amd64 {DIGEST_B}"},  # recorded under the wrong platform
    {"D1": f"linux/arm64 {DIGEST_A}"},  # an amd64 image labelled arm64
    {"D2": f"linux/arm64 {DIGEST_B}"},  # an extra slot
    {"D1": "linux/arm64 sha256:xyz"},
]


@pytest.mark.parametrize("hub", [False, True])
@pytest.mark.parametrize("over", BAD_SLOTS)
def test_a_bad_slot_is_refused_before_anything_is_created(tmp_path, over, hub):
    code, out, _ = run_index(tmp_path, hub=hub, **over)
    assert code != 0 and "digest" not in out and create_calls(tmp_path) == []


@pytest.mark.parametrize(
    "db",
    [
        {"manifests": {DIGEST_A: SINGLE_A, DIGEST_B: MULTI, DIGEST_IDX: MULTI}},  # one source is itself an index
        {"configs": {DIGEST_A: AMD, DIGEST_B: {"os": "linux", "architecture": "arm", "variant": "v6"}}},
    ],
)
def test_a_multi_platform_or_wrong_variant_source_is_refused_before_anything_is_created(tmp_path, db):
    code, out, _ = run_index(tmp_path, make_db(**db))
    assert code != 0 and "digest" not in out and create_calls(tmp_path) == []


HOSTILE = {
    "drops a platform": {"drops_last": True},
    "adds a manifest": {"adds_extra": DIGEST_IDX},
    "stage tag replaced": {"hooks": [{"after_create": 1, "tag": STAGE, "digest": DIGEST_A}]},
    "final tag replaced": {"hooks": [{"after_create": 2, "tag": TAG1, "digest": DIGEST_B}]},
    "last tag replaced": {"hooks": [{"after_create": 3, "tag": TAGL, "digest": DIGEST_B}]},
    "hub digest differs": {"reverse_host": "docker.io"},  # same children, other order: a different index digest
}
HOSTILE_HUB = {
    "hub drops a platform": {"drops_last": True, "flaw_host": "docker.io"},
    "hub adds a manifest": {"adds_extra": DIGEST_IDX, "flaw_host": "docker.io"},
    "hub stage tag replaced": {"hooks": [{"after_create": 4, "tag": HSTAGE, "digest": DIGEST_A}]},
    "hub final tag replaced": {"hooks": [{"after_create": 5, "tag": HTAG1, "digest": DIGEST_B}]},
    "hub last tag replaced": {"hooks": [{"after_create": 6, "tag": HTAGL, "digest": DIGEST_B}]},
}


@pytest.mark.parametrize("name", [n for n in HOSTILE if n != "hub digest differs"])
def test_a_wrong_index_or_a_replaced_tag_stops_the_job_before_the_digest_is_published(tmp_path, name):
    code, out, _ = run_index(tmp_path, make_db(**HOSTILE[name]))
    assert code != 0 and "digest" not in out


@pytest.mark.parametrize("name", list(HOSTILE_HUB))
def test_the_same_holds_for_docker_hub(tmp_path, name):
    code, out, _ = run_index(tmp_path, make_db(**HOSTILE_HUB[name]), hub=True)
    assert code != 0 and "digest" not in out


def mutated_index_scripts() -> dict[str, tuple[str, str | None, bool]]:
    """name -> (weakened script, the hostile case only that guard stops or None, Docker Hub enabled)."""
    s = INDEX_SCRIPT
    stage_create = 'docker buildx imagetools create --tag "$staging" "${sources[@]}"'
    promote = 'docker buildx imagetools create --tag "$tag" "${repo}@${digest}"'
    verify = '[ "$(docker buildx imagetools inspect "$tag" --format \'{{.Manifest.Digest}}\')" = "$first_digest" ]'
    registries = 'registries+=("$HUB")'
    same = '[ "$digest" = "$first_digest" ]'
    for needle in (stage_create, promote, verify, registries, same):
        assert needle in s, needle
    swapped = 'docker buildx imagetools create --tag "$tag" "${sources[0]}"'
    out = {
        "no staging create": (s.replace(stage_create, "true"), None, False),
        "no promotion": (s.replace(promote, "true"), None, False),
        "promote from the first source": (s.replace(promote, swapped), None, False),
        "no hub registry": (s.replace(registries, "true"), None, True),
        "no final tag check": (s.replace(verify, "true"), "final tag replaced", False),
        "no content binding": (s.replace('[ "$got" = "$want_set" ]', "true"), "adds a manifest", False),
        "no cross-registry equality (nor final check)": (
            s.replace(same, "true").replace(verify, "true"),
            "hub digest differs",
            True,
        ),
    }
    for name, (mutated, _, _) in out.items():
        assert mutated != s, name
    return out


@pytest.mark.parametrize("name", list(mutated_index_scripts()))
def test_removing_or_redirecting_a_step_of_the_index_script_is_caught(tmp_path, name):
    mutated, hostile, hub = mutated_index_scripts()[name]
    real = tmp_path / "real"
    real.mkdir()
    assert run_index(real, hub=hub)[0] == 0
    weak = tmp_path / "weak"
    weak.mkdir()
    if hostile is None:
        code, out, _ = run_index(weak, script=mutated, hub=hub)
        assert code != 0 and "digest" not in out
    else:
        # only this guard stops the hostile registry: the real script refuses, the weakened one publishes
        refused = tmp_path / "refused"
        refused.mkdir()
        assert run_index(refused, make_db(**HOSTILE[hostile]), hub=hub)[0] != 0
        code, out, _ = run_index(weak, make_db(**HOSTILE[hostile]), script=mutated, hub=hub)
        assert code == 0 and "digest" in out


# --- the re-check of the final tags ------------------------------------------

RECHECKS = ("Re-check the final tags before signing", "Re-check the final tags after attestation")


def recheck_env(**over):
    return {"TAGS": f"{TAG1}\n{TAGL}\n{HTAG1}", "DIGEST": DIGEST_IDX, **over}


@pytest.mark.parametrize("name", RECHECKS)
def test_the_recheck_passes_only_when_every_final_tag_resolves_to_the_digest(tmp_path, name):
    script = step("merge", name)["run"]
    base = {TAG1: DIGEST_IDX, TAGL: DIGEST_IDX, HTAG1: DIGEST_IDX}
    cases = [
        (base, True),
        ({**base, TAGL: DIGEST_A}, False),  # the second tag moved
        ({**base, TAG1: DIGEST_A}, False),  # the first tag moved
        ({**base, HTAG1: DIGEST_A}, False),  # the Docker Hub tag moved
        ({TAG1: DIGEST_IDX, TAGL: DIGEST_IDX}, False),  # a tag is gone
    ]
    for n, (tags, ok) in enumerate(cases):
        sub = tmp_path / str(n)
        sub.mkdir()
        db = make_db(tags=tags)
        db["hosts"]["docker.io"] = {DIGEST_IDX: MULTI, DIGEST_A: SINGLE_A}
        db["hosts"]["ghcr.io"][DIGEST_IDX] = MULTI
        code, _, out = run_script(script, sub, recheck_env(), stub(db, sub))
        assert (code == 0) == ok, out
        assert ok or "::error" in out


def test_the_recheck_steps_are_the_same_script_before_signing_and_after_attestation():
    names = [s.get("name") for s in steps_of(jobs(load(RELEASE))["merge"])]
    a, b = (step("merge", n) for n in RECHECKS)
    assert a["run"] == b["run"] and a["env"] == b["env"]
    assert a["env"]["DIGEST"] == "${{ steps.index.outputs.digest }}"
    assert names.index(RECHECKS[0]) < names.index("Install cosign") < names.index("Sign the image (keyless)")
    assert names.index(RECHECKS[1]) > names.index("Record build provenance")
    assert names.index(RECHECKS[1]) < names.index("Summary")


def test_the_documentation_states_what_the_final_tag_check_does_not_guarantee():
    text = (WORKFLOWS.parent.parent / "README.md").read_text()
    assert "does not make a tag immutable" in text and "deploy by digest" in text
    assert "only the gated login step uses" not in text, "every action in a job can read the job token"


# --- the platform list, duplicates ---------------------------------------------


def run_plan(tmp_path, platforms: str):
    env = {"PLATFORMS": platforms, "REPOSITORY": "Owner/Img", "IMAGE_NAME": ""}
    return run_script(step("plan", "Plan the matrix")["run"], tmp_path, env)


@pytest.mark.parametrize(
    "platforms",
    [
        "linux/amd64,linux/amd64",
        "linux/arm64,linux/arm64/v8",
        "linux/arm64/v8,linux/arm64",
        "linux/arm,linux/arm/v7",
        "linux/amd64,linux/arm64,linux/amd64/v1",
        "linux/amd64,linux/arm64,linux/arm64",
    ],
)
def test_a_duplicate_platform_is_refused_by_the_plan(tmp_path, platforms):
    code, out, log = run_plan(tmp_path, platforms)
    assert code != 0 and "matrix" not in out and "duplicate" in log


@pytest.mark.parametrize(
    "platforms",
    [
        "lin ux/am d64",
        "linux/amd64,,linux/arm64",
        "linux/amd64,",
        ",linux/amd64",
        " linux/amd64",
        "linux/amd64 ",
        "linux/amd64, linux/arm64",
        "linux/amd64 ,linux/arm64",
        " linux/amd64 , linux/amd64",
        "linux/amd64\tlinux/arm64",
        "linux/amd64\n",
        "linux/amd64,\nlinux/arm64",
        "linux/amd\n64",
        "Linux/amd64",
        "linux/AMD64",
        "windows/amd64",
        "linux",
        "linux/",
        "linux/amd64/",
        "linux/amd64/8",
        "linux/amd64/v",
        "linux/amd64/v8/x",
        "linux/amd64;linux/arm64",
        "linux/amd64,linux/arm64,,",
        ",",
        "",
        " ",
    ],
)
def test_a_malformed_platform_list_is_an_error_not_repaired(tmp_path, platforms):
    code, out, log = run_plan(tmp_path, platforms)
    assert code != 0 and "matrix" not in out and "::error title=platforms" in log


@pytest.mark.parametrize(
    "platforms", ["linux/amd64", "linux/amd64,linux/arm64", "linux/arm/v6,linux/arm/v7", "linux/arm64,linux/arm/v7"]
)
def test_distinct_platforms_are_planned_with_distinct_temporary_tags(tmp_path, platforms):
    code, out, log = run_plan(tmp_path, platforms)
    assert code == 0, log
    matrix = json.loads(out["matrix"])
    assert len({m["arch"] for m in matrix}) == len(matrix) == len(platforms.split(","))
    assert [m["idx"] for m in matrix] == list(range(len(matrix)))


def test_nine_platforms_are_refused(tmp_path):
    nine = ",".join(f"linux/arm/v{n}" for n in range(1, 10))
    code, out, log = run_plan(tmp_path, nine)
    assert code != 0 and "matrix" not in out


def test_the_signing_steps_use_only_the_validated_index_digest():
    doc = load(RELEASE)
    for name in ("Sign the image (keyless)", "Attach the SBOM as a cosign attestation"):
        assert step("merge", name, doc)["env"]["DIGEST"] == "${{ steps.index.outputs.digest }}"
    assert step("merge", "Generate the SBOM with syft", doc)["with"]["image"].endswith(
        "@${{ steps.index.outputs.digest }}"
    )
    assert (
        step("merge", "Record build provenance", doc)["with"]["subject-digest"] == "${{ steps.index.outputs.digest }}"
    )
    for s in steps_of(jobs(doc)["merge"]):
        allowed = ("Create the multi-arch index", *RECHECKS)
        assert "imagetools inspect" not in (s.get("run") or "") or s.get("name") in allowed


def test_the_plan_numbers_the_platforms_and_bounds_them():
    run = step("plan", "Plan the matrix")["run"]
    assert "idx: length" in run and "-gt 8" in run


def test_release_tag_function_is_a_small_named_function():
    s = step("plan", "Decide whether to publish")["run"]
    fn = function_text(s, "is_semver_release_tag")
    assert len(fn.splitlines()) <= 8 and "refs/tags/v" in fn
    assert re.search(r"\(0\|\[1-9\]\[0-9\]\*\)", fn)
