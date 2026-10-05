#!/usr/bin/env python3
"""Build the GitHub wiki from wiki/ and refuse a tree that would publish broken.

    python scripts/gen_wiki.py --out DIR [--commit SHA]

A GitHub wiki stores pages as flat Markdown files, and .github/workflows/
wiki.yml replaces the wiki with whatever this writes, so the wiki is a mirror
of wiki/ and a web edit is lost. Before writing anything this checks what a
reader would trip over:

- Home.md exists, and nothing but Markdown files sits in wiki/ (a wiki is flat);
- every [text](Page) link names a page that exists, and every Page#anchor
  names a heading that page has;
- every page is in _Sidebar.md, so no page is reachable only by guessing.

`{{commit}}` and `{{commit_short}}` in _Footer.md become the commit being
published; no other page is rewritten, so a page can talk about them.
Standard library only: the runner needs no install step.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "wiki"
LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")
SPECIAL = ("_Sidebar.md", "_Footer.md", "_Header.md")


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"[`*_]", "", heading).lower()
    return re.sub(r"[^\w\- ]", "", text).strip().replace(" ", "-")


def anchors(text: str) -> set[str]:
    found: set[str] = set()
    counts: dict[str, int] = {}
    in_fence = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        match = None if in_fence else HEADING.match(line)
        if match:
            base = slug(match.group(1))
            n = counts.get(base, 0)
            counts[base] = n + 1
            found.add(base if n == 0 else f"{base}-{n}")
    return found


def links(text: str) -> list[str]:
    """Link targets outside code fences and inline code."""
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out += LINK.findall(re.sub(r"`[^`]*`", "", line))
    return out


def problems(src: Path = SRC) -> list[str]:
    errors: list[str] = []
    if not src.is_dir():
        return [f"{src} is not a directory"]
    entries = sorted(src.iterdir())
    for entry in entries:
        if entry.is_dir():
            errors.append(f"{entry.name}/: a wiki is flat, no subdirectories")
        elif entry.suffix != ".md":
            errors.append(f"{entry.name}: only Markdown files belong in the wiki source")
    pages = {p.stem: p.read_text() for p in entries if p.is_file() and p.suffix == ".md"}
    if "Home" not in pages:
        errors.append("Home.md is missing: a wiki without it has no front page")
    page_anchors = {name: anchors(text) for name, text in pages.items()}
    for name, text in pages.items():
        for target in links(text):
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("mailto:"):
                continue
            page, _, anchor = target.partition("#")
            page = page or name
            if page not in pages:
                errors.append(f"{name}.md: link to '{target}' names no page")
            elif anchor and anchor not in page_anchors[page]:
                errors.append(f"{name}.md: link to '{target}': {page} has no heading '#{anchor}'")
    sidebar = links(pages.get("_Sidebar", ""))
    listed = {t.partition("#")[0] for t in sidebar}
    for name in sorted(pages):
        if f"{name}.md" not in SPECIAL and name not in listed:
            errors.append(f"{name}.md: not in _Sidebar.md")
    return errors


def build(out: Path, commit: str, src: Path = SRC) -> list[str]:
    errors = problems(src)
    if errors:
        return errors
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for page in sorted(src.glob("*.md")):
        text = page.read_text()
        if page.name == "_Footer.md":
            text = text.replace("{{commit_short}}", commit[:7]).replace("{{commit}}", commit)
        (out / page.name).write_text(text)
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", required=True, type=Path, help="directory to write the pages into")
    parser.add_argument("--commit", default="main", help="the commit being published (stamped in the footer)")
    args = parser.parse_args()
    errors = build(args.out, args.commit)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"wrote {len(list(args.out.glob('*.md')))} pages to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
