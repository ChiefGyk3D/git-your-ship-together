#!/usr/bin/env python3
"""Fail when a `# vX.Y.Z` comment on a SHA-pinned `uses:` line does not name the pinned commit.

Stdlib only. The workflow `pin-comments.yml` carries a byte-identical copy of this file
(tests/test_pin_comments.py holds the two together); a caller can also run it locally.

Usage:
    python3 -I check_pin_comments.py [--root DIR] [--unverified fail|warn] [--api-base URL]

Scans `.github/workflows/*.yml|yaml` and `.github/actions/**/action.yml|yaml` under --root for
`uses: owner/repo[/path]@<40 hex>` lines. Each needs a version comment (`# v1.2.3`, `# v4`), and that
tag, looked up once per repository and tag through the GitHub API (`GITHUB_TOKEN` is sent when set, and
only over https), must resolve to the pinned commit. Local `./` and `docker://` references and
references that are not pinned to a full commit are not this check's business.

Outcomes, one line each: `FAIL` (missing comment, no such tag, a different commit), `UNVERIFIED` (the lookup
failed, timed out, was rate limited, answered something unreadable, or the lookup budget ran out). Unverified
is never green: exit 1 unless `--unverified warn`, which still prints every line and exits 0 only when
nothing FAILed. Exit 2 on bad usage. Nothing is skipped silently: no workflow file at all is a failure.

Lookups are bounded: 10 s per request, 1 MiB per answer, 200 lookups and 120 s in all.
Values taken from files are printed JSON-escaped so they cannot forge a log line or a workflow command.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

USES = re.compile(
    r"^\s*(?:-\s+)?uses:\s*['\"]?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(/[^\s@'\"#]*)?"
    r"@([0-9a-f]{40})['\"]?(?P<rest>.*)$"
)
VERSION = re.compile(r"^\s*#\s*(v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?)(?:\s|$)")
COMMIT = re.compile(r"[0-9a-f]{40}")
REQUEST_TIMEOUT = 10
MAX_BODY = 1 << 20
MAX_FILE = 4 << 20
MAX_LOOKUPS = 200
TOTAL_SECONDS = 120.0
DEFAULT_API = "https://api.github.com"


def q(value: object) -> str:
    """A value from a file or a process, safe to print: JSON-escaped, one line, bounded."""
    text = value if isinstance(value, str) else repr(value)
    return json.dumps(text[:200], ensure_ascii=True)


def files_under(root: Path) -> list[Path]:
    found: list[Path] = []
    for pattern in ("*.yml", "*.yaml"):
        found += (root / ".github" / "workflows").glob(pattern)
        found += (root / ".github" / "actions").glob("**/action" + pattern[1:])
    return sorted(p for p in found if p.is_file() and not p.is_symlink())


def scan(path: Path) -> list[tuple[int, str, str, str | None]]:
    """(line number, owner/repo, sha, version comment or None) for each SHA-pinned uses line."""
    if path.stat().st_size > MAX_FILE:
        raise ValueError(f"larger than {MAX_FILE} bytes")
    out = []
    for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        match = USES.match(line)
        if match:
            version = VERSION.match(match.group("rest"))
            out.append((number, match.group(1), match.group(3), version.group(1) if version else None))
    return out


class NoSuchTag(Exception):
    pass


def make_resolver(api_base: str, token: str | None) -> Callable[[str, str], str | None]:
    """repo, tag -> the commit id the tag points at, None when there is no such tag; raises on anything else."""
    base = urlsplit(api_base)
    if base.scheme not in ("http", "https") or not base.netloc:
        raise ValueError("--api-base must be an http(s) URL")

    class SameHostOnly(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            target = urlsplit(newurl)
            if (target.scheme, target.netloc) != (base.scheme, base.netloc):
                raise urllib.error.URLError("redirect off the API host refused")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(SameHostOnly)

    def resolve(repo: str, tag: str) -> str | None:
        request = urllib.request.Request(
            f"{api_base.rstrip('/')}/repos/{repo}/commits/refs/tags/{tag}",
            headers={"Accept": "application/vnd.github+json", "User-Agent": "gyst-pin-comments"},
        )
        if token and base.scheme == "https":
            request.add_header("Authorization", f"Bearer {token}")
        try:
            with opener.open(request, timeout=REQUEST_TIMEOUT) as reply:
                body = reply.read(MAX_BODY + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (404, 422):
                return None
            raise OSError(f"HTTP {exc.code}") from exc
        if len(body) > MAX_BODY:
            raise ValueError("answer too large")
        sha = json.loads(body).get("sha") if body else None
        if not isinstance(sha, str) or not COMMIT.fullmatch(sha):
            raise ValueError("answer has no commit id")
        return sha

    return resolve


def run(
    root: Path,
    resolve: Callable[[str, str], str | None],
    max_lookups: int = MAX_LOOKUPS,
    deadline: float = TOTAL_SECONDS,
) -> tuple[list[str], list[str]]:
    """(failures, unverified notes)."""
    problems: list[str] = []
    notes: list[str] = []
    files = files_under(root)
    if not files:
        return ["no workflow or action file found; nothing to check"], notes
    pending: dict[tuple[str, str], list[tuple[str, int, str]]] = {}
    for path in files:
        name = q(str(path.relative_to(root)))
        try:
            entries = scan(path)
        except (OSError, ValueError) as exc:
            problems.append(f"{name}: cannot read the file ({type(exc).__name__}: {q(str(exc))})")
            continue
        for number, repo, sha, version in entries:
            if version is None:
                problems.append(f"{name}:{number}: {q(repo)} is pinned to {sha} with no version comment (# vX.Y.Z)")
            else:
                pending.setdefault((repo, version), []).append((name, number, sha))
    start = time.monotonic()
    lookups = 0
    for (repo, tag), places in sorted(pending.items()):
        where = ", ".join(f"{n}:{i}" for n, i, _ in places[:3])
        if lookups >= max_lookups or time.monotonic() - start > deadline:
            notes.append(f"unverified: {q(repo)} {q(tag)} at {where}: lookup budget or deadline used up")
            continue
        lookups += 1
        try:
            actual = resolve(repo, tag)
        except Exception as exc:  # noqa: BLE001 - any failure to look up is "unverified", never a pass
            notes.append(f"unverified: {q(repo)} {q(tag)} at {where}: {type(exc).__name__}: {q(str(exc))}")
            continue
        for name, number, sha in places:
            if actual is None:
                problems.append(f"{name}:{number}: no such tag: {q(repo)} has no tag {q(tag)}")
            elif actual != sha:
                problems.append(f"{name}:{number}: mismatch: {q(repo)} {q(tag)} is {actual}, the pin is {sha}")
    return problems, notes


def exit_code(problems: list[str], notes: list[str], unverified: str) -> int:
    if problems:
        return 1
    return 1 if notes and unverified != "warn" else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--unverified", choices=("fail", "warn"), default="fail")
    parser.add_argument("--api-base", default=DEFAULT_API)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        parser.error(f"--root {str(args.root)!r} is not a directory")
    try:
        resolve = make_resolver(args.api_base, os.environ.get("GITHUB_TOKEN"))
    except ValueError as exc:
        parser.error(str(exc))
    problems, notes = run(root, resolve)
    for problem in problems:
        print(f"FAIL {problem}")
    for note in notes:
        print(f"UNVERIFIED {note}")
    code = exit_code(problems, notes, args.unverified)
    if code == 0:
        print(f"ok   every version comment names its pinned commit{' (some unverified)' if notes else ''}")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
