#!/usr/bin/env python3
"""Decide whether a pull request changes only files a caller calls "docs only".

The answer feeds a deliberate skip: a caller leaves a job out of a docs-only
pull request, and `scripts/ci_gate.py` counts that skip as a pass. It must
therefore err one way only. Every doubt is `docs-only=false`, which runs the job.

Inputs reach the script through the environment, never through its text:

  CC_EVENT_NAME      github.event_name; anything but `pull_request` is never docs only
  CC_REPO            OWNER/REPO whose pull request it is
  CC_PR              pull request number
  CC_HEAD_SHA        the head commit the event was started for
  CC_CHANGED_FILES   the event's own count of changed files
  CC_PATTERNS        newline-separated globs; a path is docs only when it matches one
  CC_NEVER_SKIP      newline-separated globs that always run the job, on top of `.github/**`
  GH_TOKEN           a token that can read the pull request (pull-requests: read)
  GITHUB_OUTPUT      where `docs-only`, `reason` and `changed` are written
  CC_FILES_JSON      tests only: a file holding the API's answer, in place of calling it

Glob syntax (anchored at the repository root, matched against the whole path):
`*` any characters but `/`, `?` one such character, `**` anything including `/`,
`**/` zero or more directories. Nothing else is special. A pattern that would
match every path, starts with `/` or `!`, or contains `..` is a usage error.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable

# The API lists at most this many files of a pull request; a list this long may be cut short.
API_FILE_LIMIT = 3000
# Never docs only, whatever the caller's patterns say: the workflows, actions and rule files that
# decide what runs. Changing them is changing the gate.
ALWAYS_RUN = (".github/**",)


class UsageError(Exception):
    pass


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out), re.DOTALL)


def compile_patterns(text: str, what: str, reject_catch_all: bool) -> list[re.Pattern[str]]:
    compiled = []
    for raw in text.splitlines():
        pattern = raw.strip()
        if not pattern:
            continue
        if pattern.startswith(("/", "!", "#")) or ".." in pattern.split("/"):
            raise UsageError(f"{what}: {pattern!r} must be a path glob relative to the root (no leading / ! #, no ..)")
        rx = glob_to_regex(pattern)
        # A catch-all would turn the fast path into "skip everything".
        if reject_catch_all and (rx.fullmatch("x") or rx.fullmatch("a/b/c.tf")):
            raise UsageError(f"{what}: {pattern!r} matches every path; name the directories or files instead")
        compiled.append(rx)
    return compiled


def paths_of(files: Iterable[dict]) -> set[str]:
    """Every path a change touches: the new name, and the old one of a rename (it left its directory)."""
    paths: set[str] = set()
    for f in files:
        paths.add(f["filename"])
        if f.get("previous_filename"):
            paths.add(f["previous_filename"])
    return paths


def classify(files: list[dict], patterns: list[re.Pattern[str]], never: list[re.Pattern[str]]) -> tuple[bool, str]:
    if not patterns:
        return False, "no docs-only patterns were given"
    if not files:
        return False, "the pull request lists no changed files"
    always = [glob_to_regex(p) for p in ALWAYS_RUN]
    for path in sorted(paths_of(files)):
        # The API never returns these forms; a list that does is not one to trust.
        if path.startswith("/") or {"", ".", ".."} & set(path.split("/")):
            return False, f"{path!r} is not a normal repository path"
        if any(rx.fullmatch(path) for rx in always) or any(rx.fullmatch(path) for rx in never):
            return False, f"{path!r} is a path that always runs every job"
        if not any(rx.fullmatch(path) for rx in patterns):
            return False, f"{path!r} is not on the docs-only list"
    return True, "every changed path is on the docs-only list"


def gh_json(args: list[str]) -> object:
    done = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=120, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"gh api {args[-1]} failed: {done.stderr.strip()[:200]!r}")
    return json.loads(done.stdout)


def fetch_files(repo: str, pr: str, head_sha: str, changed: str) -> list[dict]:
    """The pull request's files from the API, checked against what the event itself says.

    Raises RuntimeError on any mismatch; the caller turns that into docs-only=false."""
    if os.environ.get("CC_FILES_JSON"):
        with open(os.environ["CC_FILES_JSON"], encoding="utf-8") as fh:
            files = json.load(fh)
    else:
        meta = gh_json([f"repos/{repo}/pulls/{pr}"])
        if not isinstance(meta, dict) or meta.get("head", {}).get("sha") != head_sha:
            raise RuntimeError("the pull request head is no longer the commit this run was started for")
        pages = gh_json(["--paginate", "--slurp", f"repos/{repo}/pulls/{pr}/files?per_page=100"])
        files = [f for page in pages for f in page]
    if not changed.isdigit() or int(changed) != len(files):
        raise RuntimeError(f"the API listed {len(files)} files but the event says {changed!r}")
    if len(files) >= API_FILE_LIMIT:
        raise RuntimeError("the file list may be cut short by the API limit")
    return files


def write_outputs(docs_only: bool, reason: str, changed: int) -> None:
    reason = " ".join(reason.split())
    line = f"docs-only={'true' if docs_only else 'false'}\nreason={reason}\nchanged={changed}\n"
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line)
    print(line, end="")


def main() -> int:
    env = os.environ
    try:
        patterns = compile_patterns(env.get("CC_PATTERNS", ""), "patterns", True)
        never = compile_patterns(env.get("CC_NEVER_SKIP", ""), "never-skip", False)
    except UsageError as err:
        print(f"::error title=classify-changes::{err}")
        return 1
    if env.get("CC_EVENT_NAME") != "pull_request":
        write_outputs(False, f"the event is {env.get('CC_EVENT_NAME', '')!r}, not a pull request", 0)
        return 0
    try:
        files = fetch_files(
            env.get("CC_REPO", ""), env.get("CC_PR", ""), env.get("CC_HEAD_SHA", ""), env.get("CC_CHANGED_FILES", "")
        )
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as err:
        print(f"::warning title=classify-changes::running every job: {err}")
        write_outputs(False, "the changed files could not be read and confirmed", 0)
        return 0
    docs_only, reason = classify(files, patterns, never)
    print(f"::notice title=classify-changes::docs-only={str(docs_only).lower()}: {reason}")
    write_outputs(docs_only, reason, len(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
