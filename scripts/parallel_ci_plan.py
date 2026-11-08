#!/usr/bin/env python3
"""Validate parallel-ci.yml's inputs and decide which check jobs run.

Standard library only; the workflow `parallel-ci.yml` carries a byte-identical copy of this file
(tests/test_parallel_ci.py holds the two together). Every value arrives through the environment, none is
interpolated into a shell script, and everything that reaches the step's outputs is either a validated
token or single-line JSON, so no caller input can add a line to $GITHUB_OUTPUT.

Environment:
    PLAN_JOBS                  JSON list of check jobs (required)
    PLAN_AREAS                 JSON object, area name -> list of glob patterns (default {})
    PLAN_BUILD_OUTPUT_PATH     directory the build writes, relative to the workspace (required)
    PLAN_EXTRA_OUTPUT_PATH     optional second directory; workspace-relative or RUNNER_TEMP/<path>
    PLAN_ARTIFACT_NAME         prefix of the artifact names
    PLAN_RETENTION_DAYS        artifact retention, 1 to 7
    PLAN_CACHE_PIP_FILES       JSON list of pin files whose hash keys the pip download cache
    PLAN_BUILD_PIP_CACHE       `true` to restore that cache in the build job too
    PLAN_CACHE_TOOL_PATH       optional directory of one cached tool download
    PLAN_CACHE_TOOL_KEY_FILES  JSON list of pin files whose hash keys that cache
    PLAN_EVENT                 github.event_name
    PLAN_REF                   github.ref
    PLAN_DEFAULT_BRANCH        the repository's default branch
    RUNNER_TEMP                absolute path, for RUNNER_TEMP/ output paths

Usage:
    python3 -I parallel_ci_plan.py --output FILE [--changed FILE]

--changed is the NUL-separated output of `git diff --no-renames --name-only -z`. Passing it means the diff
worked; leaving it out means it did not (or the event is not a pull request).

Selecting jobs fails CLOSED: every job runs unless the event is a pull request that does not target the
default branch's own ref, the diff is present and non-empty, every changed path is plain text, and every
changed path matches one of the caller's area rules. A path that matches none, a path with a control character
or invalid UTF-8, an empty diff, no diff, a push (to any branch), a schedule, a manual run: all run everything.
A job with no `areas` runs whatever changed. Invalid inputs are an error, not a fail-closed run: the exit code
is 1 and nothing is written.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import sys
from pathlib import Path

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}")
AREA = re.compile(r"[A-Za-z0-9_-]{1,32}")
ARTIFACT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,48}")
BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,200}")
SEGMENT = re.compile(r"[A-Za-z0-9._][A-Za-z0-9._-]*")
JOB_KEYS = {"name", "command", "timeout", "areas", "pip-cache", "tools", "build"}
MAX_JOBS = 32
MAX_COMMAND = 50_000
MAX_PATTERN = 200
MAX_PATTERNS = 200
MAX_PIN_BYTES = 64 << 20
TEMP_PREFIX = "RUNNER_TEMP/"


class PlanError(Exception):
    """An input is invalid. The message names the input and never repeats the value in full."""


def q(value: object) -> str:
    """A value safe to print: JSON-escaped, one line, bounded."""
    text = value if isinstance(value, str) else repr(value)
    return json.dumps(text[:80], ensure_ascii=True)


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def parse_json(label: str, text: str) -> object:
    try:
        return json.loads(text, object_pairs_hook=reject_duplicates)
    except (ValueError, RecursionError) as exc:
        raise PlanError(f"{label} is not valid JSON ({type(exc).__name__})") from exc


def json_list(label: str, text: str) -> list[object]:
    value = parse_json(label, text)
    if not isinstance(value, list):
        raise PlanError(f"{label} must be a JSON list")
    return value


def json_object(label: str, text: str) -> dict[str, object]:
    value = parse_json(label, text)
    if not isinstance(value, dict):
        raise PlanError(f"{label} must be a JSON object")
    return value


def plain_path(label: str, value: object, *, allow_temp: bool = False) -> str:
    """A relative path of plain segments: no `..`, no leading `-`, no `.git`, no absolute or backslash form."""
    if not isinstance(value, str) or not value or len(value) > 200:
        raise PlanError(f"{label} must be a non-empty relative path of at most 200 characters")
    rest = value
    if allow_temp and rest.startswith(TEMP_PREFIX):
        rest = rest[len(TEMP_PREFIX) :]
    for segment in rest.split("/"):
        if not SEGMENT.fullmatch(segment) or segment in (".", "..", ".git") or segment.startswith("-"):
            raise PlanError(f"{label} must be a relative path of plain segments (got {q(value)})")
    return value


def resolve_output(label: str, value: str) -> str:
    """The path as the later steps use it: workspace-relative as is, RUNNER_TEMP/x as an absolute path."""
    if not value.startswith(TEMP_PREFIX):
        return value
    temp = os.environ.get("RUNNER_TEMP", "")
    if not re.fullmatch(r"/[A-Za-z0-9._/-]{1,200}", temp):
        raise PlanError(f"{label} uses RUNNER_TEMP/ but RUNNER_TEMP is not a plain absolute path")
    return f"{temp}/{value[len(TEMP_PREFIX) :]}"


def read_areas(text: str) -> dict[str, list[str]]:
    raw = json_object("areas", text or "{}")
    areas: dict[str, list[str]] = {}
    for name, patterns in raw.items():
        if not AREA.fullmatch(name):
            raise PlanError(f"areas: the area name {q(name)} must match [A-Za-z0-9_-]{{1,32}}")
        if not isinstance(patterns, list) or not patterns or len(patterns) > MAX_PATTERNS:
            raise PlanError(f"areas: {q(name)} must be a non-empty list of glob patterns")
        checked: list[str] = []
        for pattern in patterns:
            if (
                not isinstance(pattern, str)
                or not pattern
                or len(pattern) > MAX_PATTERN
                or any(ord(c) < 0x20 or ord(c) == 0x7F for c in pattern)
            ):
                raise PlanError(f"areas: {q(name)} has a pattern that is not a short single-line string")
            checked.append(pattern)
        areas[name] = checked
    return areas


def read_jobs(text: str, areas: dict[str, list[str]]) -> list[dict[str, object]]:
    raw = json_list("jobs", text)
    if not raw:
        raise PlanError("jobs is empty: a check list with nothing in it would pass with nothing checked")
    if len(raw) > MAX_JOBS:
        raise PlanError(f"jobs has more than {MAX_JOBS} entries")
    jobs: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        where = f"jobs[{index}]"
        if not isinstance(entry, dict):
            raise PlanError(f"{where} must be an object")
        unknown = set(entry) - JOB_KEYS
        if unknown:
            raise PlanError(f"{where} has unknown keys {sorted(map(str, unknown))} (allowed: {sorted(JOB_KEYS)})")
        name = entry.get("name")
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise PlanError(f"{where}.name must match [A-Za-z0-9][A-Za-z0-9 ._()-]{{0,63}}")
        if name.lower() in seen:
            raise PlanError(f"{where}.name {q(name)} is used twice")
        seen.add(name.lower())
        command = entry.get("command")
        if not isinstance(command, str) or not command.strip() or len(command) > MAX_COMMAND or "\x00" in command:
            raise PlanError(f"{where}.command must be a non-empty string without NUL, at most {MAX_COMMAND} characters")
        timeout = entry.get("timeout", 15)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 360:
            raise PlanError(f"{where}.timeout must be an integer from 1 to 360 (minutes)")
        job_areas = entry.get("areas", [])
        if not isinstance(job_areas, list) or not all(isinstance(a, str) for a in job_areas):
            raise PlanError(f"{where}.areas must be a list of area names")
        for area in job_areas:
            if area not in areas:
                raise PlanError(f"{where}.areas names {q(area)}, which the areas input does not define")
        flags: dict[str, bool] = {}
        for key, default in (("pip-cache", False), ("tools", False), ("build", True)):
            value = entry.get(key, default)
            if not isinstance(value, bool):
                raise PlanError(f"{where}.{key} must be true or false")
            flags[key] = value
        jobs.append(
            {
                "name": name,
                "command": command,
                "timeout": timeout,
                "areas": list(job_areas),
                "pip-cache": flags["pip-cache"],
                "tools": flags["tools"],
                "build": flags["build"],
            }
        )
    return jobs


def classify(path: str, areas: dict[str, list[str]]) -> str | None:
    """The first area whose pattern matches the path, or None. Patterns are shell-style (`*` crosses `/`)."""
    for name, patterns in areas.items():
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns):
            return name
    return None


def read_changed(path: Path) -> list[str] | None:
    """The changed paths, or None when the list cannot be trusted (any odd byte, an empty list)."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    parts = data.split(b"\x00")
    if parts and parts[-1] == b"":
        parts.pop()
    if not parts:
        return None
    names: list[str] = []
    for part in parts:
        try:
            name = part.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not name or any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
            return None
        names.append(name)
    return names


def changed_areas(
    event: str, ref: str, default_branch: str, changed: list[str] | None, areas: dict[str, list[str]]
) -> set[str] | None:
    """The areas the change touches, or None for "run everything"."""
    if event != "pull_request":
        return None
    if not BRANCH.fullmatch(default_branch) or ref == f"refs/heads/{default_branch}":
        return None
    if changed is None:
        return None
    found: set[str] = set()
    for name in changed:
        area = classify(name, areas)
        if area is None:
            return None
        found.add(area)
    return found


def runs(job: dict[str, object], found: set[str] | None) -> bool:
    """Whether a job is selected: everything when found is None, else only a job with no areas or a shared one."""
    job_areas = job["areas"]
    assert isinstance(job_areas, list)
    return found is None or not job_areas or bool(found & set(job_areas))


def pin_key(label: str, text: str) -> str:
    """A hash over the named pin files, or "" when none are named. A file that is missing is an error."""
    files = json_list(label, text or "[]")
    if len(files) > 50:
        raise PlanError(f"{label} has more than 50 files")
    if not files:
        return ""
    digest = hashlib.sha256()
    root = Path.cwd().resolve()
    for index, name in enumerate(files):
        plain_path(f"{label}[{index}]", name)
        path = root / str(name)
        resolved = path.resolve()
        if path.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
            raise PlanError(f"{label}[{index}] {q(name)} is not a regular file inside the workspace")
        if resolved.stat().st_size > MAX_PIN_BYTES:
            raise PlanError(f"{label}[{index}] {q(name)} is larger than {MAX_PIN_BYTES} bytes")
        inner = hashlib.sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                inner.update(chunk)
        digest.update(f"{name}\x00{inner.hexdigest()}\n".encode())
    return digest.hexdigest()


def plan(env: dict[str, str], changed_file: Path | None) -> dict[str, str]:
    areas = read_areas(env.get("PLAN_AREAS", ""))
    jobs = read_jobs(env.get("PLAN_JOBS", ""), areas)

    output = plain_path("build-output-path", env.get("PLAN_BUILD_OUTPUT_PATH", ""))
    extra_raw = env.get("PLAN_EXTRA_OUTPUT_PATH", "")
    extra = ""
    if extra_raw:
        extra = resolve_output("extra-output-path", plain_path("extra-output-path", extra_raw, allow_temp=True))
    artifact = env.get("PLAN_ARTIFACT_NAME", "")
    if not ARTIFACT.fullmatch(artifact):
        raise PlanError("artifact-name must match [A-Za-z0-9][A-Za-z0-9_-]{0,48}")
    if not re.fullmatch(r"[1-7](\.0)?", env.get("PLAN_RETENTION_DAYS", "")):
        raise PlanError("artifact-retention-days must be a whole number from 1 to 7")

    tool_raw = env.get("PLAN_CACHE_TOOL_PATH", "")
    tool_key = pin_key("cache-tool-key-files", env.get("PLAN_CACHE_TOOL_KEY_FILES", ""))
    if bool(tool_raw) != bool(tool_key):
        raise PlanError("cache-tool-path and cache-tool-key-files must be given together")
    tool_path = ""
    if tool_raw:
        tool_path = resolve_output("cache-tool-path", plain_path("cache-tool-path", tool_raw, allow_temp=True))
    pip_key = pin_key("cache-pip-files", env.get("PLAN_CACHE_PIP_FILES", ""))

    changed = read_changed(changed_file) if changed_file else None
    found = changed_areas(
        env.get("PLAN_EVENT", ""), env.get("PLAN_REF", ""), env.get("PLAN_DEFAULT_BRANCH", ""), changed, areas
    )
    selected = [job for job in jobs if runs(job, found)]
    skipped = [str(job["name"]) for job in jobs if not runs(job, found)]
    matrix = [{k: job[k] for k in ("name", "command", "timeout", "pip-cache", "tools", "build")} for job in selected]
    return {
        "matrix": json.dumps(matrix, separators=(",", ":"), ensure_ascii=True),
        "count": str(len(selected)),
        "skipped-jobs": ",".join(skipped),
        "everything": "true" if found is None else "false",
        "areas": "" if found is None else ",".join(sorted(found)),
        "output-path": output,
        "extra-path": extra,
        "artifact-name": artifact,
        "pip-key": pip_key,
        "build-pip-key": pip_key if env.get("PLAN_BUILD_PIP_CACHE", "") == "true" else "",
        "tool-key": tool_key,
        "tool-path": tool_path,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--changed", type=Path)
    args = parser.parse_args(argv)
    try:
        result = plan(dict(os.environ), args.changed)
    except PlanError as exc:
        print(f"::error title=parallel-ci input::{exc}")
        return 1
    if any("\n" in value or "\r" in value for value in result.values()):
        print("::error title=parallel-ci::an output has a line break")
        return 1
    with args.output.open("a", encoding="utf-8") as handle:
        for key, value in result.items():
            handle.write(f"{key}={value}\n")
    scope = "everything" if result["everything"] == "true" else f"areas {result['areas']}"
    print(f"plan: {result['count']} job(s) selected ({scope}); skipped: {result['skipped-jobs'] or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
