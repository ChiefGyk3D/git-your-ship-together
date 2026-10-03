"""Image hardening in container-release.yml: hadolint, the non-root check, the read-only probe."""

from __future__ import annotations

import re

from test_workflows import WORKFLOWS, jobs, load, steps_of, triggers

RELEASE = WORKFLOWS / "container-release.yml"


def build_steps() -> dict:
    return {s.get("name"): s for s in steps_of(jobs(load(RELEASE))["build"])}


def test_hadolint_is_a_cached_download_checked_against_a_pinned_hash_on_disk():
    steps = list(steps_of(jobs(load(RELEASE))["build"]))
    names = [s.get("name") for s in steps]
    cache = next(s for s in steps if s.get("name") == "Restore the cached hadolint binary")
    fetch = next(s for s in steps if s.get("name") == "Fetch hadolint at the pinned version")
    assert names.index(cache["name"]) < names.index(fetch["name"]) < names.index("Lint the Dockerfile (hadolint)")
    key = cache["with"]["key"]
    for part in ("tool-hadolint", "inputs.hadolint-version", "runner.os", "runner.arch"):
        assert part in key
    assert cache["with"]["path"] == fetch["env"]["CACHE_DIR"]
    assert str(cache["uses"]).startswith("actions/cache@")
    env = fetch["env"]
    assert env["VERSION"] == "${{ inputs.hadolint-version }}"
    assert env["AMD64_SHA256"] == "${{ inputs.hadolint-sha256-amd64 }}"
    assert env["ARM64_SHA256"] == "${{ inputs.hadolint-sha256-arm64 }}"
    body = fetch["run"]
    lines = body.splitlines()
    curl_line = next(line for line in lines if "curl" in line)
    check_lines = [line for line in lines if re.search(r"sha256sum -c -$", line)]
    last = check_lines[-1]
    assert lines.index(last) > lines.index(curl_line), "the last hash check must follow the download"
    assert "--status" not in last, "the final hash check is the one that fails the job"
    indent = lambda line: len(line) - len(line.lstrip())  # noqa: E731
    assert indent(last) < indent(curl_line), "the hash check must also run on a cached binary"
    assert "hadolint-linux-x86_64" in body and "hadolint-linux-arm64" in body


def test_the_hadolint_defaults_are_a_real_release_with_a_hash_per_architecture():
    inputs = triggers(load(RELEASE))["workflow_call"]["inputs"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", inputs["hadolint-version"]["default"])
    for arch in ("amd64", "arm64"):
        assert re.fullmatch(r"[0-9a-f]{64}", inputs[f"hadolint-sha256-{arch}"]["default"])
    assert inputs["hadolint"]["default"] is True
    assert inputs["hadolint-args"]["default"] == "--failure-threshold warning"
    assert inputs["hadolint-continue-on-error"]["default"] is False


def test_every_hadolint_step_is_gated_on_its_input_and_the_lint_can_be_made_advisory():
    steps = build_steps()
    for name in (
        "Restore the cached hadolint binary",
        "Fetch hadolint at the pinned version",
        "Lint the Dockerfile (hadolint)",
    ):
        assert steps[name]["if"] == "inputs.hadolint", name
    lint = steps["Lint the Dockerfile (hadolint)"]
    assert lint["continue-on-error"] == "${{ inputs.hadolint-continue-on-error }}"
    assert lint["env"]["DOCKERFILE"] == "${{ inputs.dockerfile }}"
    assert "inputs." not in lint["run"], "inputs reach the shell through env, never interpolated"


def test_the_non_root_check_follows_the_load_build_and_is_gated_on_its_input():
    names = [s.get("name") for s in steps_of(jobs(load(RELEASE))["build"])]
    step = build_steps()["Require a non-root user"]
    assert step["if"] == "inputs.require-non-root"
    assert names.index("Build for this platform and load it") < names.index("Require a non-root user")
    assert names.index("Require a non-root user") < names.index("Check the image")
    assert "--entrypoint id" in step["run"] and "-u" in step["run"] and "USER" in step["run"]
    assert triggers(load(RELEASE))["workflow_call"]["inputs"]["require-non-root"]["default"] is True


def test_the_read_only_probe_is_off_by_default_and_gated_on_its_input():
    inputs = triggers(load(RELEASE))["workflow_call"]["inputs"]
    assert inputs["probe-read-only"]["default"] is False
    assert inputs["probe-command"]["default"] == ""
    step = build_steps()["Probe with a read-only root filesystem"]
    assert step["if"] == "inputs.probe-read-only"
    assert step["env"]["PROBE_COMMAND"] == "${{ inputs.probe-command }}"
    assert "--read-only --tmpfs /tmp" in step["run"]
    assert "inputs." not in step["run"]


def test_the_fixture_exercises_the_hardening():
    with_ = jobs(load(WORKFLOWS / "ci.yml"))["fixture-release"]["with"]
    assert with_["docker-test-command"].strip() == 'docker run --rm "$IMAGE" --version'
    assert with_["probe-read-only"] is True and with_["probe-command"] == "--version"
    assert with_["trivy-exit-code"] == "1"
