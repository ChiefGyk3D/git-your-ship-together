#!/usr/bin/env python3
"""Fail when a vendored file, its pin, or its generated outputs have drifted.

Generic on purpose: stdlib only, no repository-specific names. Generalized from a
design-token drift check; the workflow `vendored-drift.yml` carries a byte-identical
copy of this file (tests/test_vendored_drift.py holds the two together).

Usage:
    python3 -I check_vendored_drift.py --lock vendor/x.lock.json [--lock ...]
        [--root DIR] [--generator-command "python3 scripts/gen.py"]

A lock file is one JSON object with exactly these keys:

    vendored   path of the vendored file, relative to --root
    sha256     the pinned SHA-256 of that file (64 lowercase hex characters)
    source     {"repo": "owner/name", "path": "path/upstream", "commit": "<40 hex>"}

For every lock the checks are, in order: the lock is well formed; the vendored file is a
regular file inside the root; its SHA-256 equals the pin. Then, once, the optional
generator command runs from the root with `--check` appended and no shell; a non-zero
exit is drift. Every problem is printed (one `FAIL` line each); exit 1 if there is any,
2 on bad usage, else 0. Nothing is skipped silently: no lock at all is a failure.

The generator command is code the caller chose, run with the caller's own privileges.
Lock files and vendored files are data: nothing in them is executed, and values taken
from them are printed JSON-escaped so they cannot forge a log line or a workflow command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

SHA256 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
LOCK_KEYS = {"vendored", "sha256", "source"}
SOURCE_KEYS = {"repo", "path", "commit"}
MAX_LOCK_BYTES = 1 << 20
MAX_VENDORED_BYTES = 256 << 20
GENERATOR_TIMEOUT = 300
OUTPUT_LINES = 20
OUTPUT_COLUMNS = 200


def q(value: object) -> str:
    """A value from a lock or a process, safe to print: JSON-escaped, one line, bounded."""
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


def check_lock(root: Path, lock_path: Path) -> list[str]:
    name = q(str(lock_path))
    try:
        lock = read_lock(lock_path)
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as exc:
        return [f"{name}: cannot read the lock ({type(exc).__name__}: {q(str(exc))})"]
    if not isinstance(lock, dict):
        return [f"{name}: the lock must be a JSON object"]

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

    vendored = inside(root, lock.get("vendored"))
    if vendored is None:
        problems.append(f"{name}: vendored must be a relative path that stays inside the root")
    elif not vendored.is_file():  # a missing file, a directory, a FIFO or a device
        problems.append(f"{name}: vendored file {q(lock.get('vendored'))} is not a regular file")
    elif vendored.stat().st_size > MAX_VENDORED_BYTES:
        problems.append(f"{name}: vendored file {q(lock.get('vendored'))} is larger than {MAX_VENDORED_BYTES} bytes")
    elif isinstance(pin, str) and SHA256.fullmatch(pin):
        actual = sha256_of(vendored)
        if actual != pin:
            problems.append(f"hash mismatch: {q(lock.get('vendored'))} is {actual}, {name} pins {pin}")
    return problems


def check_generator(root: Path, command: str) -> list[str]:
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        return [f"generator command cannot be parsed ({q(str(exc))})"]
    if not argv:
        return ["generator command is empty"]
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")}
    try:
        done = subprocess.run(
            [*argv, "--check"],
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=GENERATOR_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [f"generator --check did not finish in {GENERATOR_TIMEOUT} seconds"]
    except OSError as exc:
        return [f"generator --check could not start ({type(exc).__name__}: {q(str(exc))})"]
    if done.returncode == 0:
        return []
    lines = (done.stdout + done.stderr).splitlines()[:OUTPUT_LINES]
    # Prefixed, so no generator output line can begin with `::` and act as a workflow command.
    detail = "".join(f"\n    | {line[:OUTPUT_COLUMNS]!r}" for line in lines)
    return [f"drift: generator --check exited {done.returncode}{detail}"]


def run(root: Path, locks: list[Path], generator: str) -> list[str]:
    if not locks:
        return ["no lock file given; there is nothing to check"]
    problems: list[str] = []
    seen: set[Path] = set()
    for lock in locks:
        try:
            resolved = (root / lock).resolve()
        except (OSError, RuntimeError):
            resolved = None
        if resolved is None or not resolved.is_relative_to(root):
            problems.append(f"{q(str(lock))}: the lock must be a path that stays inside the root")
            continue
        if resolved in seen:
            problems.append(f"{q(str(lock))}: listed twice")
            continue
        seen.add(resolved)
        problems.extend(check_lock(root, resolved))
    if generator:
        problems.extend(check_generator(root, generator))
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--lock", type=Path, action="append", default=[])
    parser.add_argument("--generator-command", default="")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"--root {str(args.root)!r} is not a directory")
    problems = run(root, args.lock, args.generator_command)
    for problem in problems:
        print(f"FAIL {problem}")
    if problems:
        return 1
    print(f"ok   {len(args.lock)} lock(s): pin{' and generator' if args.generator_command else ''} agree")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
