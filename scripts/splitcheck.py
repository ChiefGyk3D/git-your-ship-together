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

Exit 0: ok. Exit 1: lines missing or duplicated (listed by number, never echoed). Exit 2:
usage or unreadable input. Python 3 standard library only.
"""

from __future__ import annotations

import argparse
import collections
import importlib.util
import os
import re
import sys

_PROVENANCE = re.compile(r"^\s*<!--\s*(?:docmove|from)\b.*-->\s*$", re.I)
_RANGE = re.compile(r"L(\d{1,9})-L(\d{1,9})")


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
        if r.kind == "link" and dm.parse_target(raw)[0] != "path":
            continue
        out.append(text[last : r.start])
        out.append("\x00")
        last = r.end
    out.append(text[last:])
    return "".join(out)


def numbered_lines(text, dm, drop_provenance):
    """[(line number, normalized line)] for the non-blank lines of `text`."""
    masked = _mask(text, dm).split("\n")
    result = []
    for i, ln in enumerate(masked, 1):
        ln = ln.rstrip("\r")
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


def main(argv=None):
    ap = argparse.ArgumentParser(prog="splitcheck", description=__doc__.splitlines()[0])
    ap.add_argument("--source", required=True)
    ap.add_argument("--out", required=True, nargs="+", metavar="PAGE")
    ap.add_argument(
        "--copy", action="store_true", help="the source stays in place; check only that the lines were copied"
    )
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
    missing, duplicated = check(source, pages, dm, copy=a.copy, lines=rng)
    for i, have, want in missing:
        print(f"missing: source line {i} (pages hold it {have} time(s), source has it {want})")
    for name, i, have, want in duplicated:
        print(f"duplicated: {name} line {i} (pages hold it {have} time(s), source has it {want})")
    if missing or duplicated:
        print(f"splitcheck: FAIL ({len(missing)} missing, {len(duplicated)} duplicated)")
        return 1
    print("splitcheck: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
