#!/usr/bin/env python3
"""Generate the GitHub wiki from docs/wiki/.

The wiki is not a second place to write. The pages are the Markdown under
`docs/wiki/`, rewritten for a flat namespace, and `.github/workflows/wiki.yml`
replaces the wiki's contents with this output on every push to main, so a page
edited in the wiki UI is overwritten and a page typed there cannot drift.

What is written into the directory named by `--out`:

* one wiki page per `docs/wiki/*.md`, under the same name (`Home.md` is the
  home page, `_Sidebar.md` the sidebar). A page's name is its file name, so
  `Doppler-and-OIDC.md` is the wiki page `Doppler-and-OIDC`.
* `_Footer.md`, naming the source commit given with `--commit`. Never a clock
  or a hostname: the output is a function of the tree and the commit.

Two things are generated rather than typed:

* **Input tables.** A page named `Workflow-<name>.md` is about
  `.github/workflows/<name>.yml`. Where it holds the line `<!-- inputs -->`,
  the generator writes that workflow's `workflow_call` inputs, secrets and
  outputs (name, type, default, whether required, description) read from the
  YAML, so the table cannot say what the workflow does not. A workflow page
  with no marker is an error, and so is a marker on any other page.
* **Links.** A relative link to another page of `docs/wiki/` becomes that
  page's wiki name (no extension, anchor kept). A relative link to anything
  else in the repository (a workflow file, BASELINE.md) becomes a link to the
  file on GitHub `main`. A link to something that does not exist is an error.

Needs no network.

Usage:
    scripts/gen_wiki.py --out DIR [--commit SHA]     # write the wiki tree
    scripts/gen_wiki.py --check [--out DIR]          # validate; compare DIR if it exists
"""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "docs" / "wiki"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
REPO_URL = "https://github.com/ChiefGyk3D/git-your-ship-together"
REF = "main"

MARKER = "<!-- inputs -->"
PAGE_PREFIX = "Workflow-"
RESERVED = {"_footer"}

FENCE = re.compile(r"^\s*(```|~~~)")
INLINE = re.compile(r"(\]\()([^)\s]+)((?:\s+\"[^\"]*\")?\))")
REFDEF = re.compile(r"^(\s{0,3}\[[^\]]+\]:\s*)(\S+)(.*)$")
EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//|#|/|<)", re.IGNORECASE)


class WikiError(Exception):
    """A tree the wiki cannot be generated from."""


# ---------------------------------------------------------------------------
# The workflow tables
# ---------------------------------------------------------------------------


def workflow_call(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text())
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = doc.get("on") if "on" in doc else doc.get(True)
    if not isinstance(triggers, dict) or "workflow_call" not in triggers:
        raise WikiError(f"{path.name} is not a reusable workflow (no workflow_call)")
    return triggers["workflow_call"] or {}


def reusable_workflows() -> list[str]:
    """The stems of every workflow a caller may `uses:`."""
    out = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(path.read_text())
        triggers = doc.get("on") if "on" in doc else doc.get(True)
        if isinstance(triggers, dict) and "workflow_call" in triggers:
            out.append(path.stem)
    return out


def _cell(text: Any) -> str:
    """One Markdown table cell: one line, pipes escaped."""
    one_line = " ".join(str(text).split())
    return one_line.replace("|", "\\|")


def _default(spec: dict[str, Any]) -> str:
    if "default" not in spec:
        return "required" if spec.get("required") else "none"
    value = spec["default"]
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    if value is None or value == "":
        return "empty"
    return "`" + _cell(value).replace("`", "'") + "`"


def render_tables(stem: str) -> str:
    call = workflow_call(WORKFLOWS / f"{stem}.yml")
    out: list[str] = []

    inputs = call.get("inputs") or {}
    if inputs:
        out.append(f"**Inputs** ({len(inputs)}), read from `{stem}.yml`:\n")
        out.append("| Input | Type | Default | Meaning |")
        out.append("|---|---|---|---|")
        for name, spec in inputs.items():
            required = " (required)" if spec.get("required") else ""
            meaning = _cell(spec.get("description", "")) + required
            out.append(f"| `{name}` | {spec.get('type', 'string')} | {_default(spec)} | {meaning} |")
        out.append("")

    secrets = call.get("secrets") or {}
    if secrets:
        out.append("**Secrets** a caller may pass, by name:\n")
        out.append("| Secret | Required | Meaning |")
        out.append("|---|---|---|")
        for name, spec in secrets.items():
            out.append(
                f"| `{name}` | {'yes' if spec.get('required') else 'no'} | {_cell(spec.get('description', ''))} |"
            )
        out.append("")

    outputs = call.get("outputs") or {}
    if outputs:
        out.append("**Outputs** a caller job can read:\n")
        out.append("| Output | Meaning |")
        out.append("|---|---|")
        for name, spec in outputs.items():
            out.append(f"| `{name}` | {_cell(spec.get('description', ''))} |")
        out.append("")

    if not inputs:
        out.append(f"`{stem}.yml` takes no inputs.\n")
    return "\n".join(out).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------


def _target(target: str, src: str, pages: set[str]) -> str:
    """The wiki or GitHub form of one relative link target."""
    if EXTERNAL.match(target):
        return target
    path, sep, anchor = target.partition("#")
    if not path:
        return target
    here = posixpath.dirname(f"docs/wiki/{src}")
    repo_path = posixpath.normpath(posixpath.join(here, path))
    if repo_path.startswith(".."):
        raise WikiError(f"{src}: the link {target} leaves the repository")
    if posixpath.dirname(repo_path) == "docs/wiki" and repo_path.endswith(".md"):
        name = posixpath.basename(repo_path).removesuffix(".md")
        if name not in pages:
            raise WikiError(f"{src}: the link {target} names a wiki page that does not exist")
        return name + (sep + anchor if sep else "")
    on_disk = REPO_ROOT / repo_path
    if not on_disk.exists():
        raise WikiError(f"{src}: the link {target} points at nothing in the repository")
    kind = "tree" if on_disk.is_dir() else "blob"
    return f"{REPO_URL}/{kind}/{REF}/{repo_path}" + (sep + anchor if sep else "")


def convert(markdown: str, src: str, pages: set[str]) -> str:
    out: list[str] = []
    in_fence = False
    for line in markdown.split("\n"):
        if FENCE.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        ref = REFDEF.match(line)
        if ref:
            out.append(ref.group(1) + _target(ref.group(2), src, pages) + ref.group(3))
            continue
        out.append(INLINE.sub(lambda m: m.group(1) + _target(m.group(2), src, pages) + m.group(3), line))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# The tree
# ---------------------------------------------------------------------------


def footer(commit: str) -> str:
    if re.fullmatch(r"[0-9a-f]{7,40}", commit):
        src = f"[`{commit[:12]}`]({REPO_URL}/commit/{commit})"
    else:
        src = f"`{commit}`"
    return (
        f"Generated from `docs/wiki/` at commit {src}. "
        "Do not edit this wiki: the next push to `main` replaces every page. "
        f"Corrections go to [`docs/wiki/`]({REPO_URL}/tree/{REF}/docs/wiki) by pull request.\n"
    )


def render(commit: str = "unknown") -> dict[str, str]:
    """Every wiki file, name -> content. Raises WikiError on a tree it cannot map."""
    sources = sorted(SOURCE.glob("*.md"))
    if not sources:
        raise WikiError("docs/wiki/ holds no pages")
    pages = {p.stem for p in sources}
    for required in ("Home", "_Sidebar"):
        if required not in pages:
            raise WikiError(f"docs/wiki/{required}.md is missing")
    bad = sorted(p for p in pages if p.lower() in RESERVED)
    if bad:
        raise WikiError(f"reserved wiki names written by hand: {', '.join(bad)}")
    lowered: dict[str, str] = {}
    for p in sorted(pages):
        if p.lower() in lowered:
            raise WikiError(f"{p} and {lowered[p.lower()]} differ only in case; GitHub treats them as one page")
        lowered[p.lower()] = p

    workflows = reusable_workflows()
    for stem in workflows:
        if f"{PAGE_PREFIX}{stem}" not in pages:
            raise WikiError(f"no page for {stem}.yml: write docs/wiki/{PAGE_PREFIX}{stem}.md")

    files: dict[str, str] = {}
    for path in sources:
        text = path.read_text()
        if text.count(MARKER) > 1:
            raise WikiError(f"{path.name} holds the {MARKER} marker more than once")
        stem = path.stem.removeprefix(PAGE_PREFIX)
        is_workflow_page = path.stem.startswith(PAGE_PREFIX)
        if is_workflow_page:
            if stem not in workflows:
                raise WikiError(f"{path.name} is named for {stem}.yml, which is not a reusable workflow")
            if MARKER not in text:
                raise WikiError(f"{path.name} has no {MARKER} marker; the inputs table would be missing")
            text = text.replace(MARKER, render_tables(stem).rstrip("\n"))
        elif MARKER in text:
            raise WikiError(f"{path.name} holds the {MARKER} marker but is not a workflow page")
        body = convert(text, path.name, pages)
        files[path.name] = body if body.endswith("\n") else body + "\n"
    files["_Footer.md"] = footer(commit)
    empty = sorted(f for f, c in files.items() if not c.strip())
    if empty:
        raise WikiError(f"empty wiki pages: {', '.join(empty)}")
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, help="directory to write the wiki into")
    parser.add_argument("--commit", default="unknown", help="source commit SHA for the footer")
    parser.add_argument("--check", action="store_true", help="write nothing: validate, and compare --out if it exists")
    args = parser.parse_args()
    if not args.check and args.out is None:
        parser.error("--out is required unless --check")

    try:
        files = render(args.commit)
    except WikiError as e:
        print(f"gen_wiki: {e}", file=sys.stderr)
        return 1

    if args.check:
        if args.out is not None and args.out.is_dir():
            have = {p.name: p.read_text() for p in args.out.glob("*.md")}
            if have != files:
                diff = sorted((set(have) ^ set(files)) | {f for f in files if have.get(f) != files[f]})
                print(f"{args.out} is out of date ({', '.join(diff[:8])}); run scripts/gen_wiki.py --out {args.out}")
                return 1
        print(f"wiki is up to date ({len(files)} pages generate cleanly)")
        return 0

    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (args.out / name).write_text(content)
    print(f"wrote {len(files)} wiki pages to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
