#!/usr/bin/env python3
"""Fail when a vendored file has drifted from its pin, or the pin from its source repository.

Generic on purpose: stdlib only, no repository-specific names. The workflow `token-drift.yml` carries a
byte-identical copy of this file (tests/test_token_drift.py holds the two together).

Usage:
    python3 -I check_token_drift.py --lock vendor/x.lock.json [--root DIR]
        [--expect-vendored PATH] [--expect-source-repo OWNER/NAME] [--expect-source-path PATH]
        [--check-live [--source-ref REF]] [--advisory]

The lock is the same file `vendored-drift.yml` reads: one JSON object with exactly these keys:

    vendored   path of the vendored file, relative to --root
    sha256     the pinned SHA-256 of that file (64 lowercase hex characters)
    source     {"repo": "owner/name", "path": "path/upstream", "commit": "<40 hex>"}

Checks, in order. Malformed input is an error; a difference is drift. Both exit 1, every problem is printed
(one `FAIL` line each), and nothing is skipped silently.
  1. the lock is well formed, and agrees with every --expect-* value given (a lock edited to point somewhere
     else is caught by the caller's own workflow file, which an attacker has to change in the open);
  2. the vendored file is a regular file inside the root and its SHA-256 equals the pin (drift);
  3. with --check-live: --source-ref (empty means the repository's default branch) is resolved to ONE commit
     through api.github.com, the source file is fetched at exactly that commit, and its SHA-256 must equal
     the pin (drift). The lock's own commit is printed beside it; the file, not the commit id, is compared,
     because upstream may move on without touching the file.

--advisory turns drift (not errors) into WARN lines and exit 0, and writes `drifted=true|false` to
$GITHUB_OUTPUT. It exists for a fixture that must prove the check fires without leaving every run red.

The live fetch sends GITHUB_TOKEN (the job's read-only token) only to api.github.com, never follows a
redirect, reads at most MAX_BYTES, and needs a public source repository (the job token cannot read another
private one). Lock files and vendored files are data: nothing in them is executed, and values taken from
them are printed JSON-escaped so they cannot forge a log line or a workflow command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
REF = re.compile(r"[A-Za-z0-9._/-]{1,200}")
LOCK_KEYS = {"vendored", "sha256", "source"}
SOURCE_KEYS = {"repo", "path", "commit"}
MAX_LOCK_BYTES = 1 << 20
MAX_BYTES = 16 << 20
API = "https://api.github.com"
API_VERSION = "2022-11-28"
TIMEOUT = 30


class Error(Exception):
    """Malformed input or an unreachable source: always a failure, never advisory."""


def q(value: object) -> str:
    """A value from a lock or a response, safe to print: JSON-escaped, one line, bounded."""
    text = value if isinstance(value, str) else repr(value)
    return json.dumps(text[:200], ensure_ascii=True)


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {key!r}")
        out[key] = value
    return out


def relative(value: object) -> str | None:
    """The path if it is a plain relative path with no `..`, no NUL and no backslash."""
    if not isinstance(value, str) or not value or len(value) > 1000:
        return None
    if "\x00" in value or "\\" in value or value.startswith("/"):
        return None
    if any(part in ("", ".", "..") for part in value.split("/")):
        return None
    return value


def inside(root: Path, value: object) -> Path | None:
    """Resolve value under root, following symlinks; None if it is not a relative path that stays inside."""
    rel = relative(value)
    if rel is None:
        return None
    try:
        path = (root / rel).resolve()
    except (OSError, RuntimeError):
        return None
    return path if path.is_relative_to(root.resolve()) else None


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_lock(path: Path) -> object:
    if not path.is_file():
        raise ValueError("not a regular file")
    if path.stat().st_size > MAX_LOCK_BYTES:
        raise ValueError(f"larger than {MAX_LOCK_BYTES} bytes")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def parse_lock(root: Path, lock_path: Path) -> dict[str, object]:
    """The lock as a dict, or Error listing what is wrong with it."""
    name = q(str(lock_path))
    try:
        resolved = lock_path.resolve()
    except (OSError, RuntimeError) as exc:
        raise Error(f"{name}: cannot read the lock ({type(exc).__name__})") from exc
    if not resolved.is_relative_to(root):
        raise Error(f"{name}: the lock must be a path that stays inside the root")
    try:
        lock = read_lock(resolved)
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise Error(f"{name}: cannot read the lock ({type(exc).__name__}: {q(str(exc))})") from exc
    if not isinstance(lock, dict):
        raise Error(f"{name}: the lock must be a JSON object")
    problems: list[str] = []
    if set(lock) != LOCK_KEYS:
        problems.append(f"{name}: keys must be exactly {sorted(LOCK_KEYS)}, got {q(sorted(map(str, lock)))}")
    pin = lock.get("sha256")
    if not isinstance(pin, str) or not SHA256.fullmatch(pin):
        problems.append(f"{name}: sha256 must be 64 lowercase hex characters")
    source = lock.get("source")
    if not isinstance(source, dict) or set(source) != SOURCE_KEYS:
        problems.append(f"{name}: source must be an object with exactly repo, path and commit")
    else:
        if not isinstance(source["repo"], str) or not REPO.fullmatch(source["repo"]):
            problems.append(f"{name}: source.repo must look like owner/name")
        if relative(source["path"]) is None:
            problems.append(f"{name}: source.path must be a plain relative path")
        if not isinstance(source["commit"], str) or not COMMIT.fullmatch(source["commit"]):
            problems.append(f"{name}: source.commit must be a 40-character lowercase hex commit id")
    if relative(lock.get("vendored")) is None:
        problems.append(f"{name}: vendored must be a plain relative path")
    if problems:
        raise Error("\n".join(problems))
    return lock


def check_expectations(lock: dict, args: argparse.Namespace) -> list[str]:
    problems = []
    pairs = (
        ("vendored", lock["vendored"], args.expect_vendored),
        ("source.repo", lock["source"]["repo"], args.expect_source_repo),
        ("source.path", lock["source"]["path"], args.expect_source_path),
    )
    for label, actual, wanted in pairs:
        if wanted and actual != wanted:
            problems.append(f"the lock's {label} is {q(actual)}, but the workflow input says {q(wanted)}")
    return problems


def check_vendored(root: Path, lock: dict) -> list[str]:
    vendored = inside(root, lock["vendored"])
    shown = q(lock["vendored"])
    if vendored is None:
        return [f"vendored {shown} must be a relative path that stays inside the root"]
    if not vendored.is_file():  # a missing file, a directory, a FIFO or a device
        return [f"vendored file {shown} is not a regular file"]
    if vendored.stat().st_size > MAX_BYTES:
        return [f"vendored file {shown} is larger than {MAX_BYTES} bytes"]
    actual = sha256_of(vendored)
    if actual != lock["sha256"]:
        return [f"hash mismatch: {shown} is {actual}, the lock pins {lock['sha256']}"]
    return []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirects are refused", headers, fp)


def api_get(path: str, accept: str, limit: int) -> bytes:
    """GET https://api.github.com{path}; no redirect is followed and at most `limit` bytes are read."""
    headers = {"Accept": accept, "X-GitHub-Api-Version": API_VERSION, "User-Agent": "gyst-token-drift"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(API + path, headers=headers, method="GET")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=TIMEOUT) as response:
            body = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        raise Error(f"GET {path.split('?')[0]} answered HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise Error(f"GET {path.split('?')[0]} failed ({type(exc).__name__})") from exc
    if len(body) > limit:
        raise Error(f"GET {path.split('?')[0]} returned more than {limit} bytes")
    return body


def resolve_commit(repo: str, ref: str) -> str:
    """The one commit `ref` (empty: the default branch) names right now."""
    if ref and (
        not REF.fullmatch(ref) or ".." in ref or ref.startswith(("/", "-")) or ref.endswith("/") or "//" in ref
    ):
        raise Error(f"source-ref {q(ref)} is not a plain branch, tag or commit name")
    target = urllib.parse.quote(ref or "HEAD", safe="")
    body = api_get(f"/repos/{repo}/commits/{target}", "application/vnd.github.sha", 200)
    commit = body.decode("ascii", errors="replace").strip()
    if not COMMIT.fullmatch(commit):
        raise Error(f"the API did not answer a commit id for {q(ref or 'the default branch')}")
    return commit


def check_live(lock: dict, ref: str) -> list[str]:
    source = lock["source"]
    commit = resolve_commit(source["repo"], ref)
    path = urllib.parse.quote(source["path"], safe="/")
    body = api_get(
        f"/repos/{source['repo']}/contents/{path}?ref={commit}", "application/vnd.github.raw+json", MAX_BYTES
    )
    actual = hashlib.sha256(body).hexdigest()
    note = "the lock's commit" if commit == source["commit"] else f"commit {commit} (the lock says {source['commit']})"
    print(f"live {source['repo']}:{q(source['path'])} at {note} is {actual}")
    if actual != lock["sha256"]:
        return [
            f"drift: {q(source['path'])} in {source['repo']} at commit {commit} is {actual}, "
            f"the lock pins {lock['sha256']} ({q(lock['vendored'])} is stale or the lock is wrong)"
        ]
    return []


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--lock", type=Path, default=None)
    parser.add_argument("--expect-vendored", default="")
    parser.add_argument("--expect-source-repo", default="")
    parser.add_argument("--expect-source-path", default="")
    parser.add_argument("--check-live", action="store_true")
    parser.add_argument("--source-ref", default="")
    parser.add_argument("--advisory", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"--root {str(args.root)!r} is not a directory")
    if args.lock is None:
        parser.error("--lock is required: nothing to check is not a pass")
    if args.source_ref and not args.check_live:
        parser.error("--source-ref only means something with --check-live")

    errors: list[str] = []
    drift: list[str] = []
    try:
        lock = parse_lock(root, root / args.lock)
        errors.extend(check_expectations(lock, args))
        if not errors:
            drift.extend(check_vendored(root, lock))
            if args.check_live:
                drift.extend(check_live(lock, args.source_ref))
    except Error as exc:
        errors.append(str(exc))

    for problem in errors:
        print(f"FAIL {problem}")
    for problem in drift:
        print(f"{'WARN' if args.advisory else 'FAIL'} {problem}")
    out = os.environ.get("GITHUB_OUTPUT")
    if args.advisory and out:
        with open(out, "a", encoding="utf-8") as handle:
            handle.write(f"drifted={'true' if drift else 'false'}\n")
    if errors or (drift and not args.advisory):
        return 1
    if drift:
        print("ok   drift reported (advisory)")
    else:
        scope = " and the source file at the resolved commit" if args.check_live else ""
        print(f"ok   the vendored file matches its pin{scope}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
