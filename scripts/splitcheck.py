#!/usr/bin/env python3
"""splitcheck: prove a document split dropped and duplicated nothing.

    python3 -I splitcheck.py --source FILE --out PAGE [PAGE ...]
    python3 -I splitcheck.py --copy [--lines L<a>-L<b>] --source FILE --out PAGE [PAGE ...]

Every non-blank line of the source must appear in the output pages exactly as often as it
appears in the source (so a line moved to the other page still passes, a deleted line or a
duplicated line fails). Before comparing, link destinations and wiki page names are masked
(a link edit is not a content change) and provenance comments (`<!-- from: ... -->`,
`<!-- docmove: ... -->`) are dropped from the pages. Lines only in the pages (new headings,
intro text) are allowed.

With --copy the source stays where it is, so only the copied lines (the whole file, or the
--lines range) must be present in the pages at least as often as in that range.

Pages that docmove wrote carry `<!-- docmove: split|merged|archived|copied from SRC Lx-Ly -->`
above each chunk. When such comments name the source, only those chunks are compared (each
against the source lines of its own range), so a page shared with other sources, and lines that
repeat across sources (code fences, table separators), give no false duplicates; lines of the
source that are in no chunk are missing, and lines in two chunks are duplicated. The source is
recognized by `--source-name SRC` (the path as docmove wrote it) or, by default, when SRC is the
tail of the --source path. Provenance is not trusted: a comment that names a source that is neither
--source nor listed by --known-source or in the `repo_path` column of --map is an "unknown
provenance source" and fails; a range outside the source fails; and a chunk must hold exactly as
many non-blank lines as its range does. With --copy the chunks must cover --lines (default: the
whole file) whatever their comments claim. A source that is its own destination page (a merge-into row onto its
own file) has no comment of its own: the lines above the page's first comment are its chunk, found
when the page's path ends with --source-name. With no such chunk the whole pages are compared.

Exit 0: ok. Exit 1: lines missing or duplicated (listed by number, never echoed). Exit 2:
usage or unreadable input. Python 3 standard library only.
"""

from __future__ import annotations

import argparse
import collections
import csv
import importlib.util
import os
import re
import sys

_PROVENANCE = re.compile(r"^\s*<!--\s*(?:docmove|from)\b.*-->\s*$", re.I)
_RANGE = re.compile(r"L(\d{1,9})-L(\d{1,9})")
_DOCMOVE = re.compile(r"^\s*<!--\s*docmove:")
_CHUNK = re.compile(
    r"^\s*<!--\s*docmove:\s*(split|merged|archived|copied) from (.+?)(?: L(\d{1,9})-L(\d{1,9}))?\s*-->\s*$"
)


def _load_scanner():
    """The link scanner lives in the sibling docmove.py (`-I` keeps the script dir off sys.path)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docmove.py")
    spec = importlib.util.spec_from_file_location("docmove_scanner", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mask(text, dm):
    """Text with every link destination and wiki page name replaced by a placeholder."""
    out = []
    last = 0
    for r in dm.scan(text):
        raw = text[r.start : r.end]
        if r.kind == "link" and not raw.startswith("#") and dm.parse_target(raw)[0] != "path":
            continue
        out.append(text[last : r.start])
        if r.kind == "wiki" and raw.count("|") == 1:
            out.append(raw.split("|")[0] + "|\x00")  # [[text|Page]]: the text is content, only the page is a target
        else:
            out.append("\x00")
        last = r.end
    out.append(text[last:])
    return "".join(out)


def numbered_lines(text, dm, drop_provenance):
    """[(line number, normalized line)] for the non-blank lines of `text`."""
    masked = _mask(text, dm).split("\n")
    result = []
    for i, ln in enumerate(masked, 1):
        ln = ln.rstrip("\r").lstrip("\ufeff")
        if not ln.strip() or (drop_provenance and _PROVENANCE.match(ln)):
            continue
        result.append((i, ln))
    return result


def _read(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "surrogateescape")


def check(source, pages, dm, copy=False, lines=None):
    """Returns (missing, duplicated): missing = [(source line, present, expected)];
    duplicated = [(page, line, present, expected)]."""
    src = numbered_lines(source, dm, drop_provenance=False)
    if lines:
        src = [(i, ln) for i, ln in src if lines[0] <= i <= lines[1]]
    want = collections.Counter(ln for _, ln in src)
    have = collections.Counter()
    where = collections.defaultdict(list)
    for name, text in pages:
        for i, ln in numbered_lines(text, dm, drop_provenance=True):
            have[ln] += 1
            where[ln].append((name, i))
    missing, duplicated = [], []
    for ln, n in want.items():
        if have[ln] < n:
            missing += [(i, have[ln], n) for i, x in src if x == ln]
        elif have[ln] > n and not copy:
            duplicated += [(name, i, have[ln], n) for name, i in where[ln]]
    return sorted(missing), sorted(duplicated)


def chunks_of(page, text, dm):
    """[(verb, src, (a, b) or None, [(page line number, normalized line)], comment line number)] for each
    docmove chunk. A docmove comment that is not a well-formed provenance comment is a chunk with verb
    "bogus", so that it can be reported."""
    out = []
    cur = ("inplace", None, None, [], 0)  # the lines above the first comment are the page's own text
    out.append(cur)
    for i, ln in enumerate(_mask(text, dm).split("\n"), 1):
        ln = ln.rstrip("\r").lstrip("\ufeff")
        if _DOCMOVE.match(ln):
            m = _CHUNK.match(ln)
            if m:
                cur = (m.group(1), m.group(2), (int(m.group(3)), int(m.group(4))) if m.group(3) else None, [], i)
            else:
                cur = ("bogus", ln.strip(), None, [], i)
            out.append(cur)
            continue
        if cur is not None and ln.strip() and not _PROVENANCE.match(ln):
            cur[3].append((i, ln))
    return [c for c in out if c[0] != "inplace" or c[3]]


def check_chunks(source, chunks, dm, copy, want_lines=None):
    """Compare each chunk with the source lines of its range. Returns (missing, duplicated) like check()."""
    src = numbered_lines(source, dm, drop_provenance=False)
    missing, duplicated = [], []
    owners = collections.defaultdict(list)  # source line number -> the chunks whose range holds it
    for k, (page, _, rng, lines, *_) in enumerate(chunks):
        mine = [(i, ln) for i, ln in src if rng is None or rng[0] <= i <= rng[1]]
        want = collections.Counter(ln for _, ln in mine)
        have = collections.Counter(ln for _, ln in lines)
        for ln, n in want.items():
            if have[ln] < n:
                missing += [(i, have[ln], n) for i, x in mine if x == ln]
            elif have[ln] > n and not copy:
                duplicated += [(page, i, have[ln], n) for i, x in lines if x == ln]
        for i, _ in mine:
            owners[i].append(k)
    if copy and want_lines:
        # a copy must hold every non-blank line of the requested range, whatever its comments claim
        have_all = collections.Counter(ln for _, _, _, lines, *_ in chunks for _, ln in lines)
        wanted = [(i, ln) for i, ln in src if want_lines[0] <= i <= want_lines[1]]
        need = collections.Counter(ln for _, ln in wanted)
        for ln, n in need.items():
            if have_all[ln] < n:
                missing += [(i, have_all[ln], n) for i, x in wanted if x == ln]
    if not copy:
        for i, _ in src:
            if not owners[i]:
                missing.append((i, 0, 1))
            elif len(owners[i]) > 1:
                duplicated.append((", ".join(sorted({chunks[k][0] for k in owners[i]})), i, len(owners[i]), 1))
    return sorted(set(missing)), sorted(set(duplicated))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="splitcheck", description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True)
    ap.add_argument("--out", required=True, nargs="+", metavar="PAGE")
    ap.add_argument(
        "--copy", action="store_true", help="the source stays in place; check only that the lines were copied"
    )
    ap.add_argument("--source-name", help="the source's path as docmove wrote it in its provenance comments")
    ap.add_argument(
        "--known-source",
        action="append",
        default=[],
        metavar="SRC",
        help="another source path whose provenance comments may appear on the pages (repeatable)",
    )
    ap.add_argument("--map", help="a docmove registry CSV: its repo_path column lists the known sources")
    ap.add_argument("--lines", help="only the source lines L<a>-L<b> (for a ranged copy)")
    a = ap.parse_args(argv)
    rng = None
    if a.lines:
        m = _RANGE.fullmatch(a.lines)
        if not m or int(m.group(1)) > int(m.group(2)) or int(m.group(1)) < 1:
            print("splitcheck: --lines must look like L4-L9", file=sys.stderr)
            return 2
        rng = (int(m.group(1)), int(m.group(2)))
    try:
        dm = _load_scanner()
        source = _read(a.source)
        pages = [(p, _read(p)) for p in a.out]
    except Exception as e:  # unreadable input is not a verdict
        print(f"splitcheck: cannot read input: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    known = set(a.known_source)
    if a.source_name:
        known.add(a.source_name)
    if a.map:
        try:
            with open(a.map, newline="", encoding="utf-8-sig") as f:
                known |= {r["repo_path"] for r in csv.DictReader(f) if r.get("repo_path")}
        except (OSError, UnicodeDecodeError, csv.Error, KeyError) as e:
            print(f"splitcheck: cannot read --map: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
    verbs = {"copied"} if a.copy else {"split", "merged", "archived"}
    tail = os.path.abspath(a.source).replace(os.sep, "/")
    total = len(source.split("\n")) - (1 if source.endswith("\n") else 0)
    src_lines = numbered_lines(source, dm, drop_provenance=False)
    chunks, problems = [], []
    for name, text in pages:
        page_abs = os.path.abspath(name).replace(os.sep, "/")
        own_page = (a.source_name and page_abs.endswith("/" + a.source_name)) or page_abs == tail
        for verb, src, crng, lines, cline in chunks_of(name, text, dm):
            if verb == "inplace":  # a source that is its own destination page: its text sits above the comments
                if own_page and not a.copy:
                    chunks.append((name, a.source_name or tail, None, lines, 0))
                continue
            ours = verb != "bogus" and (src == a.source_name if a.source_name else tail.endswith("/" + src))
            if not ours and (verb == "bogus" or src not in known):
                problems.append(f"unknown provenance source: {name} line {cline} ({src})")
                continue
            if not ours or verb not in verbs:
                continue
            if crng is not None and not 1 <= crng[0] <= crng[1] <= total:
                problems.append(
                    f"provenance range L{crng[0]}-L{crng[1]} at {name} line {cline} is outside the source "
                    f"({total} lines)"
                )
                continue
            want_n = sum(1 for i, _ in src_lines if crng is None or crng[0] <= i <= crng[1])
            if len(lines) != want_n:
                problems.append(
                    f"chunk at {name} line {cline} holds {len(lines)} non-blank lines, its range has {want_n}"
                )
            chunks.append((name, src, crng, lines, cline))
    if chunks:
        missing, duplicated = check_chunks(source, chunks, dm, a.copy, rng or (1, total) if a.copy else None)
    else:
        missing, duplicated = check(source, pages, dm, copy=a.copy, lines=rng)
    for msg in problems:
        print(msg)
    for i, have, want in missing:
        print(f"missing: source line {i} (pages hold it {have} time(s), source has it {want})")
    for name, i, have, want in duplicated:
        if chunks:
            print(f"duplicated: {name} line {i} ({have} time(s), expected {want})")
        else:
            print(f"duplicated: {name} line {i} (pages hold it {have} time(s), source has it {want})")
    if missing or duplicated or problems:
        print(f"splitcheck: FAIL ({len(missing)} missing, {len(duplicated)} duplicated, {len(problems)} other)")
        return 1
    print("splitcheck: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
