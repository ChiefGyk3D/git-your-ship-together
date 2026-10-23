#!/usr/bin/env python3
"""docmove: deterministic documentation move for a git repo.

Run:  python3 -I docmove.py --repo DIR --map registry.csv [--dry-run] [--subfolder wiki]
                            [--report where-did-it-go.md] [--strict]

The map is a CSV with the header `repo_path,section,page,action,order` and an optional
trailing `notes` column (its content is ignored; any other extra column is refused).
Actions: move, merge-into, split-into, archive-into, copy-into, keep, stub. `section` is empty
except for split-into (required) and copy-into (optional; empty copies the whole file), where it
is `L<start>-L<end>` (1-indexed, inclusive source lines). copy-into leaves the source file in
place (it may share a source with a `keep` row) and copies the text to the page.
`page` is a flat file name; with --subfolder it is placed in that folder (an explicit
`<subfolder>/Name` is accepted too). A `stub` row creates a page named `page` that points
at where the `repo_path` source went (that source needs its own non-stub row).

Everything (validation, link rewrite, post-check) is computed in memory first; the
working tree is only touched when all of it passes. Changes are staged, never committed.
Exit codes: 0 ok, 2 any validation error / ambiguity / failed post-check, 64 malformed
map file. Python 3 standard library only.
"""

import argparse
import collections
import csv
import fnmatch
import hashlib
import io
import os
import posixpath
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote


class DocmoveError(Exception):
    pass


class MapFormatError(DocmoveError):
    """The map file itself is malformed (exit 64), as opposed to a row that cannot be honored (exit 2)."""


# --------------------------------------------------------------------------- scanner
# Hand-written, single forward pass per paragraph; every bounded lookahead has a cap,
# so total work is linear in the input size.
Ref = collections.namedtuple("Ref", "start end angle kind", defaults=(False, "link"))
CAP = 2000
_PREFIX = re.compile(r"[ \t>]*(?:(?:[-*+]|\d{1,9}[.)])[ \t]+)?")
_SPECIAL_TICK = re.compile(r"\\|`+")
_SPECIAL_BRACKET = re.compile(r"[\\\[\]<]")
_ATTR = re.compile(r"\b(?:src|href)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", re.I)


def _fence_info(line):
    s = line[_PREFIX.match(line).end() :]
    if s[:3] in ("```", "~~~"):
        ch = s[0]
        k = 3
        while k < len(s) and s[k] == ch:
            k += 1
        rest = s[k:]
        if ch == "`" and "`" in rest:
            return None
        return ch, k, rest
    return None


def _is_title(r):
    return len(r) >= 2 and (
        (r[0] == '"' and r[-1] == '"') or (r[0] == "'" and r[-1] == "'") or (r[0] == "(" and r[-1] == ")")
    )


def _next_line(text, end, n):
    """Offsets (start, end) of the line after the one ending at `end`, or None."""
    if end >= n:
        return None
    s = end + 1
    nl = text.find("\n", s)
    return s, (n if nl < 0 else nl)


def _title_end(st, text, cur_end, n):
    """`st` is stripped text that should be a link title starting on the current line (which ends at
    `cur_end`). Return the end offset of the line the title ends on (it may close on the next line), or None."""
    if _is_title(st):
        return cur_end
    if st[:1] not in ('"', "'", "("):
        return None
    closer = ")" if st[0] == "(" else st[0]
    if closer in st[1:]:
        return None
    nx = _next_line(text, cur_end, n)
    if not nx:
        return None
    st2 = text[nx[0] : nx[1]].strip()
    if st2 and st2[-1] == closer and closer not in st2[:-1]:
        return nx[1]
    return None


def _refdest(line, j, base):
    """Destination starting at line[j]; returns (Ref, index after it) or None."""
    n = len(line)
    if line[j] == "<":
        k = line.find(">", j + 1)
        if k < 0 or "<" in line[j + 1 : k]:
            return None
        ds, de, after, angle = j + 1, k, k + 1, True
    else:
        k = j
        while k < n and line[k] not in " \t":
            k += 1
        ds, de, after, angle = j, k, k, False
    if ds == de:
        return None
    return Ref(base + ds, base + de, angle), after


def _refdef(text, pos, end, n):
    """A reference definition starting on the line [pos, end): `[label]: dest "title"`, where the
    destination may sit on the next line and the title may sit on the next line (or span two).
    Returns (Ref, end offset of the last line used) or None."""
    line = text[pos:end].rstrip("\r")
    ln = len(line)
    pm = _PREFIX.match(line)  # a definition may sit in a blockquote or a list item
    i = pm.end()
    if (
        i >= ln
        or line[i] != "["
        or line[i + 1 : i + 2] == "^"
        or (i > 3 and not any(c in pm.group(0) for c in ">-*+0123456789"))
    ):
        return None
    j = i + 1
    lim = min(ln, i + 1001)
    while j < lim and line[j] not in "[]":
        j += 2 if line[j] == "\\" else 1
    if j >= ln or line[j] != "]" or line[j + 1 : j + 2] != ":":
        return None
    j += 2
    while j < ln and line[j] in " \t":
        j += 1
    cur_end = end
    if j >= ln:  # destination on the next line
        nx = _next_line(text, end, n)
        if not nx:
            return None
        line = text[nx[0] : nx[1]].rstrip("\r")
        ln = len(line)
        j = _PREFIX.match(line).end()
        if j >= ln:
            return None
        pos, cur_end = nx[0], nx[1]
    r = _refdest(line, j, pos)
    if r is None:
        return None
    ref, after = r
    rest = line[after:].strip()
    if rest:
        te = _title_end(rest, text, cur_end, n)
        if te is None:
            return None
        return ref, te
    nx = _next_line(text, cur_end, n)  # a title alone on the following line belongs to the definition
    if nx:
        st = text[nx[0] : nx[1]].strip()
        if st:
            te = _title_end(st, text, nx[1], n)
            if te is not None:
                return ref, te
    return ref, cur_end


def _skip_ws(t, p, b):
    n = 0
    while p < b and t[p] in " \t\r\n" and n < 200:
        p += 1
        n += 1
    return p


def _find(t, ch, s, b, memo):
    """str.find with a memo so repeated failed/identical searches stay amortized linear."""
    c = memo.get(ch)
    if c is not None and c[0] <= s and (c[1] < 0 or s <= c[1]):
        return c[1]
    q = t.find(ch, s, b)
    memo[ch] = (s, q)
    return q


def _parse_dest(t, p, b, memo):
    bt = b
    b = min(b, p + CAP)
    p = _skip_ws(t, p, b)
    if p >= b:
        return None
    if t[p] == "<":
        q = p + 1
        while q < b and t[q] not in "<>\n":
            q += 1
        if q >= b or t[q] != ">":
            return None
        ds, de, r, angle = p + 1, q, q + 1, True
    else:
        q = p
        depth = 0
        while q < b:
            ch = t[q]
            if ch in " \t\r\n" or ch < " ":
                break
            if ch == "\\":
                q += 2
                continue
            if ch == "(":
                depth += 1
                if depth > 32:
                    return None
            elif ch == ")":
                if depth == 0:
                    break
                depth -= 1
            q += 1
        if depth or q > b:
            return None
        ds, de, r, angle = p, q, q, False
    s = _skip_ws(t, r, b)
    if s > r and s < b and t[s] in "\"'(":
        close = ")" if t[s] == "(" else t[s]
        q = _find(t, close, s + 1, bt, memo)
        if q < 0 or q - s > 1500:
            return None
        s = _skip_ws(t, q + 1, b)
    if s < b and t[s] == ")" and de > ds:
        return Ref(ds, de, angle), s + 1
    return None


def _scan_inline(t, a, b, refs):
    runs = []
    i = a
    while True:
        m = _SPECIAL_TICK.search(t, i, b)
        if not m:
            break
        if t[m.start()] == "\\":
            i = m.start() + 2
        else:
            runs.append((m.start(), m.end()))
            i = m.end()
    nxt = [-1] * len(runs)
    last = {}
    for k in range(len(runs) - 1, -1, -1):
        ln = runs[k][1] - runs[k][0]
        nxt[k] = last.get(ln, -1)
        last[ln] = k
    code = []
    k = 0
    while k < len(runs):
        if nxt[k] >= 0:
            code.append((runs[k][0], runs[nxt[k]][1]))
            k = nxt[k] + 1
        else:
            k += 1
    ci = 0
    depth = 0
    memo = {}
    i = a
    while True:
        m = _SPECIAL_BRACKET.search(t, i, b)
        if not m:
            break
        i = m.start()
        while ci < len(code) and code[ci][1] <= i:
            ci += 1
        if ci < len(code) and code[ci][0] <= i:
            i = code[ci][1]
            continue
        c = t[i]
        if c == "\\":
            i += 2
        elif c == "[":
            if t.startswith("[[", i):
                k = t.find("]]", i + 2, min(b, i + 302))
                if k > i + 2:
                    inner = t[i + 2 : k]
                    if inner.strip() and not any(ch in inner for ch in "[]\n"):
                        refs.append(Ref(i + 2, k, False, "wiki"))
                        i = k + 2
                        continue
            depth += 1
            i += 1
        elif c == "]":
            if depth > 0:
                depth -= 1
                if i + 1 < b and t[i + 1] == "(":
                    r = _parse_dest(t, i + 2, b, memo)
                    if r:
                        refs.append(r[0])
                        i = r[1]
                        continue
            i += 1
        else:  # "<"
            if i + 1 < b and (t[i + 1].isalpha() or t[i + 1] == "/"):
                e = t.find(">", i, min(b, i + 2000))
                if e >= 0:
                    for am in _ATTR.finditer(t, i, e):
                        g = 1 if am.group(1) is not None else 2
                        if am.end(g) > am.start(g):
                            refs.append(Ref(am.start(g), am.end(g), False))
                    i = e + 1
                    continue
            i += 1


_QUOTE = re.compile(r" {0,3}> ?")
_ATX = re.compile(r" {0,3}#{1,6}(?:[ \t]|$)")
_LISTMARK = re.compile(r"([-*+]|\d{1,9}[.)])([ \t]+|$)")


def _columns(rest):
    """(indent in columns with tabs to multiples of 4, text after the indent)."""
    col = 0
    i = 0
    while i < len(rest) and rest[i] in " \t":
        col += 4 - col % 4 if rest[i] == "\t" else 1
        i += 1
    return col, rest[i:]


def scan(text):
    """Return Refs (spans of link destinations and wiki page names) outside code, in document order.

    Code is: fenced blocks, inline code spans, and indented code blocks (4+ columns relative to the
    enclosing list item, not continuing a paragraph)."""
    refs = []
    n = len(text)
    pos = 0
    fence = None
    cs = ce = None
    lists = []  # content columns of the enclosing list items
    while pos < n:
        nl = text.find("\n", pos)
        end = n if nl < 0 else nl
        line = text[pos:end]
        nxt = n if nl < 0 else nl + 1
        if fence:
            fi = _fence_info(line)
            if fi and fi[0] == fence[0] and fi[1] >= fence[1] and not fi[2].strip():
                fence = None
            pos = nxt
            continue
        rest = line
        while True:
            m = _QUOTE.match(rest)
            if not m:
                break
            rest = rest[m.end() :]
        blank = not rest.strip()
        col, body = _columns(rest)
        if blank:
            if cs is not None:
                _scan_inline(text, cs, ce, refs)
                cs = None
            pos = nxt
            continue
        if cs is None:
            while lists and col < lists[-1]:
                lists.pop()
            if col - (lists[-1] if lists else 0) >= 4:  # indented code block
                pos = nxt
                continue
        mark = _LISTMARK.match(body) if col - (lists[-1] if lists else 0) < 4 else None
        if mark:  # a list item starts a new block; its content column is where the text begins
            if cs is not None:
                _scan_inline(text, cs, ce, refs)
                cs = None
            while lists and col < lists[-1]:
                lists.pop()
            sp = len(mark.group(2))
            lists.append(col + len(mark.group(1)) + (sp if 1 <= sp <= 4 else 1))
        fi = _fence_info(line)
        d = None if fi else _refdef(text, pos, end, n)
        if fi or d or _ATX.match(rest):
            if cs is not None:
                _scan_inline(text, cs, ce, refs)
                cs = None
            if fi:
                fence = (fi[0], fi[1])
            elif d:
                refs.append(d[0])
                nxt = d[1] + 1 if d[1] < n else n
            else:
                _scan_inline(text, pos, end, refs)
        else:
            if cs is None:
                cs = pos
            ce = end
        pos = nxt
    if cs is not None:
        _scan_inline(text, cs, ce, refs)
    return refs


# --------------------------------------------------------------------------- link math
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def parse_target(raw):
    """-> ('skip', None) | ('bad', None) | ('path', (path, suffix))"""
    if not raw or raw[0] == "#" or raw.startswith("//") or _SCHEME.match(raw):
        return "skip", None
    if "\\" in raw:
        return "bad", None
    cut = len(raw)
    for ch in "#?":
        i = raw.find(ch)
        if 0 <= i < cut:
            cut = i
    p, suffix = raw[:cut], raw[cut:]
    if "%" in p:
        p = unquote(p, errors="surrogateescape")
    if not p:
        return "skip", None
    return "path", (p, suffix)


def resolve(p, fpath):
    full = p[1:] if p.startswith("/") else posixpath.join(posixpath.dirname(fpath), p)
    full = posixpath.normpath(full)
    if full == ".":
        return ""
    if full == ".." or full.startswith("../") or full.startswith("/"):
        return None
    return full


def _parents(files):
    dirs = set()
    for f in files:
        d = posixpath.dirname(f)
        while d and d not in dirs:
            dirs.add(d)
            d = posixpath.dirname(d)
    return dirs


def _exists(full, files, dirs):
    return full == "" or full in files or full in dirs


def _rel(target, start):
    t = [x for x in target.split("/") if x]
    s = [x for x in start.split("/") if x]
    k = 0
    while k < len(t) and k < len(s) and t[k] == s[k]:
        k += 1
    parts = [".."] * (len(s) - k) + t[k:]
    return "/".join(parts) or "."


def _enc(path, angle):
    if angle:
        return path
    for ch, rep in ((" ", "%20"), ("(", "%28"), (")", "%29"), ("<", "%3C"), (">", "%3E"), ('"', "%22")):
        path = path.replace(ch, rep)
    return path


# --------------------------------------------------------------------------- heading anchors
# GitHub's slug for a heading: the rendered text (links reduced to their text, images to their alt text,
# HTML tags and code marks dropped), lowercased, every character that is not a letter, digit, underscore,
# hyphen or space removed, spaces turned into hyphens. The text is stripped before the removal, so an emoji
# at the start leaves a leading hyphen. A repeated slug in one document gets -1, -2, ... in order.
# Headings inside fenced or indented code do not count; `<a name="x">` and `id="x"` are anchors as well.
_ATX_H = re.compile(r" {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$")
_SETEXT_H = re.compile(r" {0,3}(=+|-+)[ \t]*$")
_ID_ATTR = re.compile(r'<a\s[^>]*?\b(?:name|id)\s*=\s*"([^"]+)"', re.I)


def slug_of(title):
    t = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", title)
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"\[([^\]]*)\]\[[^\]]*\]", r"\1", t)
    t = re.sub(r"<[^>]+>", "", t)
    return re.sub(r"[^\w\- ]", "", t.strip().lower()).replace(" ", "-")


def headings(text):
    """[{line, level, base, slug, kind}] in document order; `base` is the slug before the duplicate suffix."""
    lines = text.split("\n")
    out = []
    counts = {}
    fence = None
    prev_blank = True
    in_icode = False
    for i, raw in enumerate(lines, 1):
        ln = raw.rstrip("\r")
        fi = _fence_info(ln)
        if fence:
            closed = bool(fi and fi[0] == fence[0] and fi[1] >= fence[1] and not fi[2].strip())
            if closed:
                fence = None
            prev_blank = closed  # a block ends where the fence closes
            continue
        if fi:
            fence = (fi[0], fi[1])
            prev_blank = False
            continue
        if not ln.strip():
            prev_blank = True
            continue
        if (ln.startswith("    ") or ln.startswith("\t")) and (prev_blank or in_icode):
            in_icode = True
            prev_blank = False
            continue
        if in_icode:
            prev_blank = True  # a block that is not code starts here
        in_icode = False
        title = level = None
        m = _ATX_H.fullmatch(ln)
        if m:
            level, title = len(m.group(1)), m.group(2) or ""
        elif prev_blank and i < len(lines) and not ln.lstrip().startswith((">", "|", "-", "*", "+", "<")):
            u = _SETEXT_H.fullmatch(lines[i].rstrip("\r"))
            if u:
                level, title = (1 if u.group(1)[0] == "=" else 2), ln.strip()
        if title is not None:
            base = slug_of(title)
            n = counts.get(base, 0)
            counts[base] = n + 1
            out.append(
                {"line": i, "level": level, "base": base, "slug": base if n == 0 else f"{base}-{n}", "kind": "h"}
            )
        for idm in _ID_ATTR.finditer(ln):
            out.append({"line": i, "level": 0, "base": idm.group(1), "slug": idm.group(1), "kind": "id"})
        prev_blank = False
    return out


def _wiki_fold(name):
    return unicodedata.normalize("NFC", name).strip().replace(" ", "-").casefold()


class LinkCtx:
    def __init__(self, files, loc, approx=frozenset(), amap=None, orig=None):
        self.files = files
        self.dirs = _parents(files)
        # old path -> new path. For a source whose lines go to several pages this is the page that
        # holds its first section (or the --link-map page): a link to it is only approximately right.
        self.loc = loc
        self.approx = frozenset(approx)
        # heading anchors: amap[src][slug] = (page, slug on that page) for a source whose text is spread
        # over pages; orig[file][slug] = line of that heading in the file as it was before the move
        self.amap = amap or {}
        self.orig = orig or {}
        self.wiki = {}  # folded page name -> tracked markdown files with that name
        for f in files:
            if _is_md(f):
                self.wiki.setdefault(_wiki_fold(posixpath.splitext(posixpath.basename(f))[0]), []).append(f)


def _frag_of(suffix):
    """(query part, fragment or None) of a link suffix such as `?x=1#frag`."""
    q, sep, f = suffix.partition("#")
    return q, (unquote(f, errors="surrogateescape") if sep else None)


def _rewrite_wiki(inner, ctx, st, where, lineno):
    """New text for the inside of a [[...]] link, or None to leave it alone. In GitHub's form
    `[[text|Page]]` the left side is display text and the right side is the page: only the page side
    is ever rewritten. A one-part link is the page name itself. A `#fragment` follows its heading."""
    parts = inner.split("|")
    if len(parts) > 2:
        return None
    name, sep, frag = parts[-1].partition("#")
    cands = ctx.wiki.get(_wiki_fold(name), [])
    involved = [c for c in cands if c in ctx.loc]
    if not involved:
        return None
    if len(cands) > 1:
        st["amb"].append(f"{where}: ambiguous wiki link [[{inner}]]: several pages share that name")
        return None
    tgt = involved[0]
    hit = None
    fl = unquote(frag).lower() if sep else ""
    if fl:
        if fl not in ctx.orig.get(tgt, {}):
            st["pre"].append((lineno, f"[[{inner}]]", False))
        else:
            hit = ctx.amap.get(tgt, {}).get(fl)
    if hit:
        new_name = posixpath.splitext(posixpath.basename(hit[0]))[0]
        parts[-1] = new_name + "#" + hit[1]
        st["anch"].append(lineno)
        return "|".join(parts)
    if tgt in ctx.approx:
        st["approx"].append((where, lineno, f"[[{inner}]]", ctx.loc[tgt]))
    new_name = posixpath.splitext(posixpath.basename(ctx.loc[tgt]))[0]
    if name.strip().replace(" ", "-") == new_name:
        return None
    parts[-1] = new_name + sep + frag
    return "|".join(parts)


def _same_page_anchor(raw, old_path, new_path, ctx, st, lineno, span):
    """New destination for `#fragment` (a link inside the file `old_path`, which now reads as
    `new_path`), or None to leave it. A heading that moved to another page gets a link to that page."""
    frag = unquote(raw[1:], errors="surrogateescape")
    fl = frag.lower()
    if not fl:
        return None
    heads = ctx.orig.get(old_path)
    if heads is None:
        return None
    if fl not in heads:
        st["pre"].append((lineno, raw, True))
        return None
    am = ctx.amap.get(old_path)
    if am is not None:
        dest, slug = am.get(fl, (None, None))
        if dest is None:
            return None
        if dest == new_path:
            return None if slug == fl else "#" + slug
        st["anch"].append(lineno)
        return _rel(dest, posixpath.dirname(new_path)) + "#" + slug
    if new_path != old_path and span is not None and not span[0] <= heads[fl] <= span[1]:
        st["anch"].append(lineno)  # copied text whose heading was not copied: point at the file that stays
        return _rel(old_path, posixpath.dirname(new_path)) + "#" + frag
    return None


def rewrite_md(text, old_path, new_path, ctx, span=None):
    """Return (new_text, stats). Only destinations that resolve and whose target or
    containing file moved are touched; everything else stays byte-identical. `span` is the (first, last)
    line of `old_path` that `new_path` holds, when it holds only a part."""
    refs = scan(text)
    out = []
    last = 0
    st = {"edits": 0, "broken": [], "bad": [], "amb": [], "approx": [], "anch": [], "pre": []}
    for r in refs:
        raw = text[r.start : r.end]
        lineno = text.count("\n", 0, r.start) + 1
        if r.kind == "wiki":
            new = _rewrite_wiki(raw, ctx, st, old_path, lineno)
            if new is not None and new != raw:
                out.append(text[last : r.start])
                out.append(new)
                last = r.end
                st["edits"] += 1
            continue
        if raw.startswith("#"):
            new = _same_page_anchor(raw, old_path, new_path, ctx, st, lineno, span)
            if new is not None and new != raw:
                out.append(text[last : r.start])
                out.append(_enc(new, r.angle))
                last = r.end
                st["edits"] += 1
            continue
        kind, info = parse_target(raw)
        if kind == "skip":
            continue
        if kind == "bad":
            st["bad"].append(raw)
            continue
        p, suffix = info
        tgt = resolve(p, old_path)
        if tgt is None or not _exists(tgt, ctx.files, ctx.dirs):
            st["broken"].append(raw)
            continue
        tgt2 = ctx.loc.get(tgt, tgt)
        query, frag = _frag_of(suffix)
        hit = None
        if frag and tgt in ctx.orig:
            fl = frag.lower()
            if fl not in ctx.orig[tgt]:
                pass  # recorded below once the destination is known
            else:
                hit = ctx.amap.get(tgt, {}).get(fl)
        if hit:
            tgt2 = hit[0]
            suffix = query + "#" + hit[1]
        elif tgt in ctx.approx:
            st["approx"].append((old_path, lineno, raw, tgt2))
        if tgt2 == tgt and posixpath.dirname(old_path) == posixpath.dirname(new_path) and not hit:
            if frag and tgt in ctx.orig and frag.lower() not in ctx.orig[tgt]:
                st["pre"].append((lineno, raw, True))
            continue
        if p.startswith("/"):
            newp = "/" + tgt2
        else:
            newp = _rel(tgt2, posixpath.dirname(new_path))
            if p.endswith("/") and not newp.endswith("/"):
                newp += "/"
        new_raw = _enc(newp, r.angle) + suffix
        if frag and tgt in ctx.orig and frag.lower() not in ctx.orig[tgt]:
            st["pre"].append((lineno, new_raw, True))
        if hit and new_raw != raw:
            st["anch"].append(lineno)
        if newp == p and suffix == info[1]:
            continue
        if r.angle and ("<" in newp or ">" in newp):
            raise DocmoveError(f"{new_path}: cannot encode new link target for {raw!r}")
        out.append(text[last : r.start])
        out.append(new_raw)
        last = r.end
        st["edits"] += 1
    out.append(text[last:])
    return "".join(out), st


def unresolved_anchors(pages, tree, pre):
    """Links in the final markdown `pages` whose `#fragment` names no heading of the page they point at.
    `pre` counts [(file, destination)] that were already broken before the move; those are not reported.
    Returns [(file, line, destination)]."""
    slugs = {}
    for f, t in pages.items():
        slugs[f] = {h["slug"].lower() for h in headings(t)}
    left = collections.Counter(pre)
    bad = []
    for f in sorted(pages):
        t = pages[f]
        for r in scan(t):
            if r.kind != "link":
                continue
            raw = t[r.start : r.end]
            if raw.startswith("#"):
                tgt, frag = f, raw[1:]
            else:
                kind, info = parse_target(raw)
                if kind != "path":
                    continue
                tgt = resolve(info[0], f)
                frag = _frag_of(info[1])[1]
            if not frag or tgt not in slugs:
                continue
            if unquote(frag, errors="surrogateescape").lower() in slugs[tgt]:
                continue
            if left[(f, raw)] > 0:
                left[(f, raw)] -= 1
                continue
            bad.append((f, t.count("\n", 0, r.start) + 1, raw))
    return bad


def rewrite_nonmd(text, moved):
    """Literal old-path -> new-path rewrite with boundary checks. A path mapped to None (a split
    source: no single new home) is reported as ambiguous, never rewritten.
    Returns (new_text, [(lineno, old, new)], [(lineno, old)] ambiguous)."""
    if not moved:
        return text, [], []
    pat = re.compile("|".join(re.escape(p) for p in sorted(moved, key=len, reverse=True)))
    out = []
    last = 0
    done = []
    amb = []
    n = len(text)
    for m in pat.finditer(text):
        s, e = m.span()
        if s > 0:
            c = text[s - 1]
            if c.isalnum() or c in "_-.":
                continue
            if c == "/":
                ok = (
                    text[s - 2 : s] == "./" and (s < 3 or not (text[s - 3].isalnum() or text[s - 3] in "_-."))
                ) or text[s - 2 : s - 1] == "}"
                if not ok:
                    amb.append((text.count("\n", 0, s) + 1, m.group()))
                    continue
        if e < n:
            c = text[e]
            if c.isalnum() or c in "_-" or (c == "." and e + 1 < n and text[e + 1].isalnum()):
                continue
        new = moved[m.group()]
        if new is None:
            amb.append((text.count("\n", 0, s) + 1, m.group()))
            continue
        out.append(text[last:s])
        out.append(new)
        last = e
        done.append((text.count("\n", 0, s) + 1, m.group(), new))
    out.append(text[last:])
    return "".join(out), done, amb


# --------------------------------------------------------------------------- post-check
def _wiki_mask(inner, stems):
    parts = inner.split("|")
    if len(parts) > 2:
        return inner
    for k, part in enumerate(parts):
        name, sep, frag = part.partition("#")
        if _wiki_fold(name) in stems:
            parts[k] = "\x00"  # the page name and its fragment may both change
    return "|".join(parts)


def _neutralize(text, stems=frozenset()):
    """Mask link destinations (and wiki page names that are moved pages) so that a line's wording,
    not its link target, is what the loss check compares."""
    out = []
    last = 0
    for r in scan(text):
        raw = text[r.start : r.end]
        if r.kind == "wiki":
            masked = _wiki_mask(raw, stems)
            if masked != raw:
                out.append(text[last : r.start])
                out.append(masked)
                last = r.end
        elif raw.startswith("#") or parse_target(raw)[0] == "path":
            out.append(text[last : r.start])
            out.append("\x00")
            last = r.end
    out.append(text[last:])
    return "".join(out)


def _lines(text, stems=frozenset()):
    for ln in _neutralize(text, stems).split("\n"):
        ln = ln.rstrip("\r").lstrip("\ufeff")
        if ln.strip():
            yield ln


def _h(line):
    return hashlib.sha1(line.encode("utf-8", "surrogateescape")).hexdigest()[:10]


def line_multiset_diff(before, after, comments, stems=frozenset()):
    """Multiset of non-blank lines (link destinations masked) before vs after.
    `comments` (provenance comments and stub text) are the only allowed extra lines. Returns
    (lost, extra) as lists of (hash, count); lines are never returned verbatim."""
    b = collections.Counter(ln for t in before.values() for ln in _lines(t, stems))
    a = collections.Counter(ln for t in after.values() for ln in _lines(t, stems))
    cm = collections.Counter(ln for c in comments for ln in _lines(c, stems))
    missing = cm - a
    a = a - cm
    lost = collections.Counter(b - a) + missing
    extra = a - b
    return ([(_h(k), v) for k, v in lost.items()], [(_h(k), v) for k, v in extra.items()])


def unresolved_links(md_texts, files, detail=False):
    """Links whose target is not in `files`. [(file, raw)], or with detail [(file, raw, target, line)]."""
    dirs = _parents(files)
    bad = []
    for f in sorted(md_texts):
        t = md_texts[f]
        for r in scan(t):
            if r.kind != "link":
                continue
            raw = t[r.start : r.end]
            kind, info = parse_target(raw)
            if kind != "path":
                continue
            tgt = resolve(info[0], f)
            if tgt is None or not _exists(tgt, files, dirs):
                bad.append((f, raw, tgt, t.count("\n", 0, r.start) + 1) if detail else (f, raw))
    return bad


def verify(v, tree_files, md_texts, nonmd_texts):
    """v: dict with entries, before_md, before_broken, comments, report, nonmd_before,
    nonmd_lines (and optionally stems, dangling). Returns (errors, warnings, accounted)."""
    errs, warns = [], []
    bad_src = set()
    sources = []
    for e in v["entries"]:
        if e["action"] == "stub":
            if e["dest"] not in tree_files:
                errs.append(f"stub page missing: {e['dest']}")
            continue
        if e["src"] not in sources:
            sources.append(e["src"])
        gone = e.get("expect_gone", e["action"] not in ("keep", "copy-into"))
        comment = e.get("comment", f"<!-- docmove: merged from {e['src']} -->" if e["action"] != "move" else None)
        ok = ((e["src"] not in tree_files) == gone or e.get("reused", False)) and e["dest"] in tree_files
        if ok and comment and e["action"] not in ("keep", "move"):
            ok = comment in md_texts.get(e["dest"], "")
        if not ok:
            bad_src.add(e["src"])
            errs.append(f"source not accounted for: {e['src']} ({e['action']})")
    accounted = len([s for s in sources if s not in bad_src])
    bad = unresolved_links(md_texts, tree_files)
    budget = collections.Counter(v["before_broken"])
    dangling = v.get("dangling", set())
    pre = dang = 0
    for f, raw in bad:
        if budget[raw] > 0:
            budget[raw] -= 1
            pre += 1
        elif (f, raw) in dangling:
            dang += 1  # a directory the move emptied; reported, and failed only by --strict
        else:
            errs.append(f"link broken by the move: {f} -> {raw}")
    if pre:
        warns.append(f"pre-existing unresolved links: {pre}")
    if dang:
        warns.append(f"dangling directory links: {dang}")
    after = {p: t for p, t in md_texts.items() if p != v["report"]}
    lost, extra = line_multiset_diff(v["before_md"], after, v["comments"], v.get("stems", frozenset()))
    for h, c in lost:
        errs.append(f"content lost: line hash {h} x{c}")
    for h, c in extra:
        errs.append(f"unexpected extra content: line hash {h} x{c}")
    for p, aft in nonmd_texts.items():
        bl = v["nonmd_before"][p].split("\n")
        al = aft.split("\n")
        if len(bl) != len(al):
            errs.append(f"{p}: line count changed")
            continue
        for i, (x, y) in enumerate(zip(bl, al, strict=True)):
            if x != y and i not in v["nonmd_lines"].get(p, ()):
                errs.append(f"{p}: unexpected change on line {i + 1}")
    return errs, warns, accounted


# --------------------------------------------------------------------------- git + mapping
def _env():
    env = {k: val for k, val in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_LITERAL_PATHSPECS"] = "1"
    return env


def git(root, *args, inp=None):
    cmd = ["git", "-C", root, "-c", "core.quotepath=off", "-c", "core.fsmonitor=false", *args]
    r = subprocess.run(cmd, capture_output=True, env=_env(), input=inp)
    if r.returncode:
        raise DocmoveError(f"git {args[0]} failed: {r.stderr.decode(errors='replace').strip()[:300]}")
    return r.stdout


def _fold(s):
    return unicodedata.normalize("NFC", s).casefold()


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]*$")
_BADCH = re.compile(r"[\x00-\x1f\x7f\\\[\]<>|`\"]")
_SECTION = re.compile(r"L(\d{1,9})-L(\d{1,9})")
ACTIONS = ("move", "merge-into", "split-into", "archive-into", "copy-into", "keep", "stub")
ASSEMBLE = ("merge-into", "split-into", "archive-into", "copy-into")
REQUIRED = ("repo_path", "section", "page", "action", "order")
MAXMAP = 5 * 1024 * 1024


def load_mapping(path):
    try:
        with open(path, "rb") as f:
            data = f.read(MAXMAP + 1)
    except OSError as e:
        raise MapFormatError(f"cannot read the map: {e.strerror}") from None
    if len(data) > MAXMAP:
        raise MapFormatError("mapping file too large")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise MapFormatError("mapping file is not valid UTF-8") from None
    if "\x00" in text:
        raise MapFormatError("mapping file contains NUL")
    try:
        rd = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error as e:
        raise MapFormatError(f"mapping CSV error: {e}") from None
    rows = [(i + 1, r) for i, r in enumerate(rd) if any(c.strip() for c in r)]
    if not rows:
        raise MapFormatError("mapping is empty")
    header = rows[0][1]
    if len(set(header)) != len(header) or not set(REQUIRED) <= set(header) or not set(header) <= {*REQUIRED, "notes"}:
        raise MapFormatError("mapping header must be repo_path,section,page,action,order[,notes]")
    out = []
    for ln, r in rows[1:]:
        if len(r) > len(header):
            raise MapFormatError(f"mapping line {ln}: too many fields")
        r = r + [""] * (len(header) - len(r))
        d = dict(zip(header, r, strict=True))
        for k, val in d.items():
            if k != "notes" and val != val.strip():
                raise MapFormatError(f"mapping line {ln}: surrounding whitespace in {k}")
        d["line"] = ln
        d.setdefault("notes", "")
        out.append(d)
    if not out:
        raise MapFormatError("mapping has a header but no rows")
    return out


def _check_relpath(p, what, errs):
    if (
        not p
        or len(p) > 1024
        or p.startswith("/")
        or _BADCH.search(p)
        or posixpath.normpath(p) != p
        or p == ".."
        or p.startswith("../")
    ):
        errs.append(f"{what}: unsafe or non-canonical path {p!r}")
        return False
    return True


def read_text(path):
    return path.decode("utf-8", "surrogateescape")


def _is_md(p):
    return p.lower().endswith((".md", ".markdown"))


def _read(full):
    fd = os.open(full, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        return f.read()


def _real_dirs_only(root, d):
    """No existing ancestor directory of `d` under `root` is a symlink or a non-directory."""
    cur = root
    for part in d.split("/")[:-1]:
        cur = os.path.join(cur, part)
        if os.path.islink(cur) or (os.path.lexists(cur) and not os.path.isdir(cur)):
            return False
    return True


class Plan:
    pass


def _title(stem):
    return stem.replace("-", " ").replace("_", " ")


_POINTS = re.compile(r"points to (.+?)\s*$")
_URL = re.compile(r"https://[A-Za-z0-9.\-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~%/\-]*)?")
_ORDER = re.compile(r"-?\d{1,9}")
_LANDING = ("_Sidebar", "_Footer")
CONSUME = ("merge-into", "split-into", "archive-into")
DEFAULT_EXCLUDES = (".gitleaksignore", "docs-migration/**")


def stub_targets(notes):
    """Targets named by a stub row's notes ("points to PageA and PageB", "points to repo file PATH"),
    or None when the notes name none."""
    m = _POINTS.search(notes or "")
    if not m:
        return None
    out = [t.strip() for t in re.split(r"\s+and\s+|\s*,\s*", m.group(1)) if t.strip()]
    return out or None


def load_link_map(path):
    """source,page rows that pick the page a link to a multi-page source is rewritten to."""
    try:
        with open(path, "rb") as f:
            data = f.read(MAXMAP + 1)
        text = data.decode("utf-8-sig")
        rd = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (OSError, UnicodeDecodeError, csv.Error) as e:
        raise MapFormatError(f"cannot read the link map: {e}") from None
    rows = [(i + 1, r) for i, r in enumerate(rd) if any(c.strip() for c in r)]
    if not rows or rows[0][1] != ["source", "page"]:
        raise MapFormatError("link map header must be source,page")
    out = {}
    for ln, r in rows[1:]:
        if len(r) != 2 or not r[0] or not r[1] or r[0] != r[0].strip() or r[1] != r[1].strip():
            raise MapFormatError(f"link map line {ln}: expected source,page")
        if r[0] in out:
            raise MapFormatError(f"link map line {ln}: duplicate source {r[0]!r}")
        out[r[0]] = r[1]
    return out


def _excluded(path, patterns):
    return any(
        fnmatch.fnmatchcase(path, pat) if "/" in pat else fnmatch.fnmatchcase(posixpath.basename(path), pat)
        for pat in patterns
    )


def _rel_in_repo(root, p):
    """Repo-relative path of `p` when it lies inside the repository, else None."""
    try:
        rel = os.path.relpath(os.path.realpath(p), root)
    except ValueError:
        return None
    return None if rel.startswith("..") else rel.replace(os.sep, "/")


def _norm_chunk(t, eol, first):
    """Give a chunk the first chunk's line ending and drop a BOM that is not at the start of the page."""
    if not first:
        t = t.lstrip("﻿")
    t = t.replace("\r\n", "\n")
    return t.replace("\n", "\r\n") if eol == "\r\n" else t


def build(root, rows, opts):
    errs = []
    top = git(root, "rev-parse", "--show-toplevel").decode().strip()
    if os.path.realpath(top) != os.path.realpath(root):
        raise DocmoveError("--repo must be the repository top level")
    if git(root, "status", "--porcelain", "-z", "--untracked-files=all"):
        raise DocmoveError("working tree is not clean (commit or stash first)")
    tracked = {}
    for ent in git(root, "ls-files", "-s", "-z").split(b"\0"):
        if not ent:
            continue
        meta, _, path = ent.partition(b"\t")
        mode, _, stage = meta.decode().split(" ")
        if stage != "0":
            raise DocmoveError("unmerged paths present")
        tracked[path.decode("utf-8", "surrogateescape")] = mode
    sub = opts["subfolder"]

    def place(page, src, what, md_only):
        """Final repo path for a page name, or None (error recorded)."""
        parts = page.split("/")
        if len(parts) > 2 or (len(parts) == 2 and (not sub or parts[0] != sub)):
            errs.append(f"{what}: {page!r} is outside the configured subfolder {sub!r}")
            return None
        name = parts[-1]
        if not (_NAME.match(name) or name.split(".")[0] in _LANDING):
            errs.append(f"{what}: {page!r} is not a flat wiki name (Topic-Words.ext)")
            return None
        if "." not in name:
            name += ".md" if md_only or not src else posixpath.splitext(src)[1]
        if md_only and not _is_md(name):
            errs.append(f"{what}: {page!r} must be a markdown page")
            return None
        dest = f"{sub}/{name}" if sub else name
        return dest if _check_relpath(dest, what, errs) and posixpath.splitext(name)[1] else None

    entries = []
    for r in rows:
        src, page, act, ln, order, section = r["repo_path"], r["page"], r["action"], r["line"], r["order"], r["section"]
        w = f"line {ln}"
        if act not in ACTIONS:
            errs.append(f"{w}: unknown action {act!r}")
            continue
        if not _check_relpath(src, w + " repo_path", errs):
            continue
        mode = tracked.get(src)
        if mode is None:
            errs.append(f"{w}: {src!r} is not a tracked file")
            continue
        if mode == "120000":
            errs.append(f"{w}: {src!r} is a symlink")
            continue
        if mode == "160000":
            errs.append(f"{w}: {src!r} is a submodule")
            continue
        if order and not _ORDER.fullmatch(order):
            errs.append(f"{w}: order must be an integer, got {order!r}")
            continue
        if act == "split-into" and not section:
            errs.append(f"{w}: split-into needs a section like L1-L20")
            continue
        if section and act not in ASSEMBLE:
            errs.append(f"{w}: section is only for split-into, merge-into, archive-into and copy-into")
            continue
        if section and not _SECTION.fullmatch(section):
            errs.append(f"{w}: {act} needs a section like L1-L20, got {section!r}")
            continue
        if act in ASSEMBLE and not _is_md(src):
            errs.append(f"{w}: only markdown can be merged, split, copied or archived ({src!r})")
            continue
        if act == "keep":
            if page not in ("", src):
                errs.append(f"{w}: keep must not rename")
            dest = src
        elif not page:
            errs.append(f"{w}: page required for {act}")
            continue
        else:
            dest = place(page, src, w + " page", act != "move")
            if dest is None:
                continue
            if act == "move" and posixpath.splitext(dest)[1].lower() != posixpath.splitext(src)[1].lower():
                errs.append(f"{w}: extension change {src!r} -> {dest!r}")
        entries.append(
            {
                "src": src,
                "dest": dest,
                "action": act,
                "order": order,
                "line": ln,
                "section": section,
                "span": None,
                "notes": r.get("notes", ""),
            }
        )

    # which combinations of rows one source may have
    real = [e for e in entries if e["action"] != "stub"]
    by_src = collections.OrderedDict()
    for e in real:
        by_src.setdefault(e["src"], []).append(e)
    for src, es in by_src.items():
        acts = [e["action"] for e in es]
        consuming = [e for e in es if e["action"] in CONSUME]
        bad = (
            ("move" in acts and len(es) > 1)
            or acts.count("keep") > 1
            or ("keep" in acts and consuming)
            or len([e for e in consuming if not e["section"]]) > 1
        )
        if bad:
            errs.append(f"line {es[1]['line']}: duplicate source {src!r} (first on line {es[0]['line']})")
        seen = set()
        for e in es:
            if e["action"] == "copy-into":
                key = (e["dest"], e["section"])
                if key in seen:
                    errs.append(f"line {e['line']}: {src!r} is copied to {e['dest']!r} twice")
                seen.add(key)

    # section ranges: read the sources now, so every error is reported before anything is written
    texts = {}
    for src, es in by_src.items():
        if not any(e["action"] in CONSUME + ("copy-into",) for e in es):
            continue
        try:
            texts[src] = read_text(_read(os.path.join(root, src)))
        except OSError as exc:
            errs.append(f"{src!r}: cannot read ({exc.strerror})")
            continue
        lines = texts[src].split("\n")
        total = len(lines) - (1 if texts[src].endswith("\n") else 0)
        spans = []  # rows that must not overlap: consuming rows and ranged copies
        covered = set()
        for e in es:
            if e["action"] not in CONSUME + ("copy-into",):
                continue
            if not e["section"]:
                e["span"] = (1, total)
                covered.update(range(1, total + 1))
                if e["action"] != "copy-into":
                    spans.append((1, total, e["line"]))
                continue
            a, b = (int(x) for x in _SECTION.fullmatch(e["section"]).groups())
            if not 1 <= a <= b <= total:
                errs.append(f"line {e['line']}: section {e['section']} is outside {src!r} (1-{total})")
                continue
            e["span"] = (a, b)
            spans.append((a, b, e["line"]))
            covered.update(range(a, b + 1))
        spans.sort()
        for (_, b1, l1), (a2, _, l2) in zip(spans, spans[1:], strict=False):
            if a2 <= b1:
                errs.append(f"lines {l1} and {l2}: sections of {src!r} overlap")
        gaps = [i for i in range(1, total + 1) if i not in covered and lines[i - 1].strip()]
        if gaps and any(e["action"] in CONSUME for e in es) and all(e["span"] for e in es if e["action"] in CONSUME):
            errs.append(f"{src!r}: non-blank lines not in any section: " + ", ".join(f"L{i}" for i in gaps[:10]))

    # tracked symlinks pointing at a source
    srcs = {e["src"] for e in real if e["action"] != "keep"}
    for p, mode in tracked.items():
        if mode == "120000":
            try:
                tgt = os.readlink(os.path.join(root, p))
            except OSError:
                continue
            full = posixpath.normpath(posixpath.join(posixpath.dirname(p), tgt)) if not tgt.startswith("/") else None
            if full and any(s == full or s.startswith(full + "/") for s in srcs):
                errs.append(f"tracked symlink {p!r} points at a moved source")

    # destinations: groups, collisions
    groups = collections.OrderedDict()
    owner = {}
    for e in entries:
        if e["action"] == "keep":
            continue
        d = e["dest"]
        kind = "assemble" if e["action"] in ASSEMBLE else e["action"]
        if kind in ("move", "stub"):
            if d in owner:
                errs.append(
                    f"line {e['line']}: destination {d!r} already used "
                    "(only merge, split, copy and archive rows may share one)"
                )
            owner[d] = kind
        else:
            if owner.get(d, kind) != kind:
                errs.append(f"line {e['line']}: destination {d!r} mixes actions")
            owner[d] = kind
            groups.setdefault(d, []).append(e)
    for d, g in groups.items():
        orders = [e["order"] for e in g]
        need = any(orders) or (len(g) > 1 and any(e["action"] != "archive-into" for e in g))
        if need:
            if not all(_ORDER.fullmatch(o) for o in orders) or len({int(o) for o in orders}) != len(orders):
                errs.append(f"merge group {d!r}: every row needs a unique integer order")
                continue
            g.sort(key=lambda e: (int(e["order"]), e["line"]))
        else:
            g.sort(key=lambda e: e["line"])

    noop = {e["src"] for e in real if e["action"] == "move" and e["dest"] == e["src"]}
    inplace_dests = {e["src"] for e in real if e["action"] == "move" and e["dest"] == e["src"]}
    inplace_srcs = set()
    for d, g in groups.items():
        for e in g:
            if e["src"] == d and e["action"] in CONSUME:
                inplace_dests.add(d)
                inplace_srcs.add(d)
    vanish = {s for s, es in by_src.items() if any(e["action"] in CONSUME for e in es)} | {
        e["src"] for e in real if e["action"] == "move" and e["dest"] != e["src"]
    }
    vanish_eff = vanish - inplace_srcs

    # stub targets (the page names that exist in this run)
    page_dest = {posixpath.splitext(posixpath.basename(d))[0]: d for d, k in owner.items() if k != "stub"}
    page_dest.update(
        {posixpath.splitext(posixpath.basename(e["dest"]))[0]: e["dest"] for e in real if e["action"] == "keep"}
    )
    stub_links = {}
    fallbacks = []
    for e in entries:
        if e["action"] != "stub":
            continue
        tg = stub_targets(e["notes"])
        items = []
        if tg is None:
            fallbacks.append(e["dest"])
            es = [x for x in by_src.get(e["src"], []) if x["action"] != "copy-into"]
            if not by_src.get(e["src"]):
                errs.append(f"line {e['line']}: stub {e['dest']!r} has no 'points to' note and {e['src']!r} has no row")
                continue
            es.sort(key=lambda x: (x["span"] or (0, 0), x["line"]))
            items = [("page", es[0]["dest"] if es else e["src"])]
        else:
            for t in tg:
                if t.startswith("repo file "):
                    path = t[len("repo file ") :]
                    if path not in tracked:
                        errs.append(f"line {e['line']}: stub points to repo file {path!r}, which is not tracked")
                    else:
                        items.append(("file", path))
                elif t in page_dest:
                    items.append(("page", page_dest[t]))
                else:
                    errs.append(
                        f"line {e['line']}: stub {e['dest']!r} points to {t!r}, which is not a page in this run"
                    )
        stub_links[id(e)] = items

    report = place(opts["report"], None, "--report", True)
    dests = list(owner) + ([report] if report else [])
    fold_tracked = collections.defaultdict(list)
    for t in tracked:
        fold_tracked[_fold(t)].append(t)
    dirs_fold = {_fold(p) for p in _parents(tracked)}
    file_fold = {_fold(p) for p in tracked}
    byfold = {}
    for d in dests:
        byfold.setdefault(_fold(d), []).append(d)
        conflicts = fold_tracked.get(_fold(d), [])
        for t in conflicts:
            if (t == d and d in inplace_dests) or t in vanish_eff:
                continue  # the file is itself a source: it stays in place, or it is gone by then
            errs.append(f"destination {d!r} collides with an existing path (case-insensitive)")
        if not conflicts and (_fold(d) in dirs_fold or os.path.lexists(os.path.join(root, d))):
            errs.append(f"destination {d!r} collides with an existing path (case-insensitive)")
        par = posixpath.dirname(d)
        if par and _fold(par) in file_fold:
            errs.append(f"destination folder {par!r} is a file")
        if not _real_dirs_only(root, d):
            errs.append(f"destination {d!r} is under a symlink or a non-directory")
    for v in byfold.values():
        if len(v) > 1:
            errs.append(f"destinations collide case-insensitively: {sorted(v)}")

    # where a link to a source that goes to several pages is rewritten to
    first_dest = {}
    multi_dest = set()
    for src, es in by_src.items():
        cs = [e for e in es if e["action"] in CONSUME and e["span"]]
        if len({e["dest"] for e in cs}) > 1:
            multi_dest.add(src)
            first_dest[src] = sorted(cs, key=lambda e: (e["span"][0], e["line"]))[0]["dest"]
    override = {}
    for src, page in (opts.get("link_map") or {}).items():
        if src not in multi_dest:
            errs.append(f"link map: {src!r} is not a source that goes to several pages")
            continue
        want = place(page, None, f"link map {src!r}", True)
        if want not in {e["dest"] for e in by_src[src] if e["action"] in CONSUME}:
            errs.append(f"link map: {page!r} is not one of the pages {src!r} goes to")
            continue
        override[src] = want
    if errs:
        raise DocmoveError("\n  ".join(["validation failed:"] + sorted(set(errs))))

    # ---------------- compute the new tree in memory
    moved = {}
    for src, es in by_src.items():
        ds = {e["dest"] for e in es if e["action"] == "move" or e["action"] in CONSUME}
        if len(ds) == 1:
            d = next(iter(ds))
            if d != src:
                moved[src] = d
    loc = dict(moved)
    for src in multi_dest:
        loc[src] = override.get(src, first_dest[src])
    approx = multi_dest - set(override)
    md_old, nonmd_old = {}, {}
    excl = tuple(DEFAULT_EXCLUDES) + tuple(opts.get("excludes", ())) + tuple(opts.get("exclude_paths", ()))
    if report:
        excl += (report,)
    for p, mode in tracked.items():
        if mode not in ("100644", "100755"):
            continue
        full = os.path.join(root, p)
        st = os.lstat(full)
        if _is_md(p):
            md_old[p] = texts[p] if p in texts else read_text(_read(full))
        elif p not in moved and not _excluded(p, excl) and st.st_size <= 2 * 1024 * 1024:
            data = _read(full)
            if b"\0" not in data:
                nonmd_old[p] = read_text(data)
    # heading anchors: where each heading of a source lands, and the slug it has on that page
    heads = {f: headings(t) for f, t in md_old.items()}
    orig = {f: {h["slug"].lower(): h["line"] for h in reversed(hs)} for f, hs in heads.items()}
    regs = []
    for d, g in groups.items():
        counts = {}
        for e in g:
            if e["action"] == "copy-into" and e["src"] not in vanish:
                continue  # the source stays: its headings stay where they are
            a, b = e["span"]
            for h in heads[e["src"]]:
                if not a <= h["line"] <= b:
                    continue
                if h["kind"] == "id":
                    final = h["slug"]
                else:
                    n = counts.get(h["base"], 0)
                    counts[h["base"]] = n + 1
                    final = h["base"] if n == 0 else f"{h['base']}-{n}"
                regs.append((e["action"] == "copy-into", e["src"], h["slug"].lower(), d, final))
    amap = {}
    for _, src, slug, d, final in sorted(regs, key=lambda x: x[0]):
        amap.setdefault(src, {}).setdefault(slug, (d, final))
    ctx = LinkCtx(set(tracked), loc, approx, amap, orig)
    pieces = {}
    stats = {}
    for p, t in md_old.items():
        pieces[p], stats[p] = rewrite_md(t, p, moved.get(p, p), ctx)
    # a source that feeds a page with a part of itself, or several pages, or a copy, is rewritten once
    # per page it feeds and cut by line
    multi = {
        s
        for s, es in by_src.items()
        if any(e["action"] == "copy-into" or e["span"] and (len(es) > 1 or e["section"]) for e in es)
        or (len(es) > 1 and any(e["action"] in CONSUME for e in es))
    }
    chunk_text = {}
    via_rows = {s for s in multi if any(e["action"] in CONSUME for e in by_src[s])}
    row_stats = []  # (final page, stats of the lines that page holds)
    for src in multi:
        for e in by_src[src]:
            if e["action"] not in CONSUME + ("copy-into",):
                continue
            rw, rst = rewrite_md(md_old[src], src, e["dest"], ctx, span=e["span"] if e["section"] else None)
            a, b = e["span"]
            row_stats.append(
                (
                    e["dest"],
                    {
                        "anch": [ln for ln in rst["anch"] if a <= ln <= b],
                        "pre": [x for x in rst["pre"] if a <= x[0] <= b],
                        "src": src,
                    },
                )
            )
            if not e["section"]:
                chunk_text[id(e)] = rw
                continue
            chunk_text[id(e)] = "\n".join(rw.split("\n")[a - 1 : b]) + "\n"
    final_md = {}
    allowed = []  # lines the loss check may see beyond the sources: provenance comments, copies, stub text
    for p, t in pieces.items():
        if p not in vanish_eff:
            final_md[p] = t
    for e in real:
        if e["action"] == "move" and _is_md(e["src"]) and e["dest"] != e["src"]:
            final_md[e["dest"]] = pieces[e["src"]]
    for d, g in groups.items():
        parts = []
        first_t = chunk_text.get(id(g[0]), pieces.get(g[0]["src"]))
        eol = "\r\n" if "\r\n" in first_t else "\n"
        for k, e in enumerate(g):
            t = chunk_text[id(e)] if id(e) in chunk_text else pieces[e["src"]]
            if len(g) > 1:
                t = _norm_chunk(t, eol, k == 0)
            elif t and not t.endswith("\n"):
                t += "\r\n" if "\r\n" in t else "\n"
            if t and not t.endswith("\n"):
                t += eol
            if e["src"] == d and not e["section"]:
                e["comment"] = None  # the page's own text: it carries no provenance
                parts.append(t)
                continue
            verb = {
                "merge-into": "merged from",
                "archive-into": "archived from",
                "split-into": "split from",
                "copy-into": "copied from",
            }[e["action"]]
            where = f"{e['src']} {e['section']}" if e["section"] else e["src"]
            c = f"<!-- docmove: {verb} {where} -->"
            e["comment"] = c
            allowed.append(c)
            if e["action"] == "copy-into" and e["src"] not in vanish_eff:
                allowed.extend(ln for ln in t.split("\n") if ln.strip())  # the source keeps these lines
            parts.append(c + eol + t)
        final_md[d] = eol.join(parts) if len(parts) > 1 else parts[0]
    for e in entries:
        if e["action"] != "stub":
            continue
        links = []
        for kind, target in stub_links[id(e)]:
            if kind == "page":
                rel = _rel(target, posixpath.dirname(e["dest"]))
                links.append(f"[{posixpath.splitext(posixpath.basename(target))[0]}]({_enc(rel, False)})")
            elif opts.get("repo_url"):
                links.append(f"[{target}]({opts['repo_url'].rstrip('/')}/blob/main/{_enc(target, False)})")
            else:
                links.append(f"`{target}`")
        said = links[0] if len(links) == 1 else ", ".join(links[:-1]) + " and " + links[-1]
        stem = posixpath.splitext(posixpath.basename(e["dest"]))[0]
        body = f"# {_title(stem)}\n\nThis page moved. See {said}.\n"
        final_md[e["dest"]] = body
        allowed.extend(ln for ln in body.split("\n") if ln.strip())
    nonmd_new, nonmd_edits, nonmd_lines, ambiguous = {}, {}, {}, []
    lit = dict(moved)
    for src in multi_dest:
        lit[src] = override.get(src)
    for p, t in nonmd_old.items():
        nt, done, amb = rewrite_nonmd(t, lit)
        ambiguous += [(p, ln, o) for ln, o in amb]
        if done:
            nonmd_new[p] = nt
            nonmd_edits[p] = done
            nonmd_lines[p] = {ln - 1 for ln, _, _ in done}
    tree = (set(tracked) - vanish_eff) | set(final_md) | set(moved.values()) | {report}
    old_dirs = _parents(set(tracked))
    approx_links = sorted(
        {(f, ln, raw, dest) for st in stats.values() for f, ln, raw, dest in st["approx"]},
        key=lambda x: (x[0], x[1], x[2]),
    )
    dangling = []
    for f, t in final_md.items():
        for _, raw, tgt, ln in unresolved_links({f: t}, tree, detail=True):
            if tgt in old_dirs:
                dangling.append((f, ln, raw))
    # anchors: rewritten, already broken before the move, broken by it
    n_anch = 0
    pre_anchors = []
    pre_keys = collections.Counter()
    for p, st in stats.items():
        if p in via_rows:
            continue  # its lines are counted per page below
        n_anch += len(st["anch"])
        for ln, raw_out, is_path in st["pre"]:
            pre_anchors.append((p, ln, raw_out))
            if is_path:
                pre_keys[(moved.get(p, p), raw_out)] += 1
    for dest, rs in row_stats:
        n_anch += len(rs["anch"])
        for ln, raw_out, is_path in rs["pre"]:
            pre_anchors.append((rs["src"], ln, raw_out))
            if is_path:
                pre_keys[(dest, raw_out)] += 1
    unresolved = unresolved_anchors(final_md, tree, pre_keys)
    # report page
    cnt = collections.Counter(e["action"] for e in real)
    cnt["split-into"] = len({e["src"] for e in real if e["action"] == "split-into"})
    rows_md = ["| Old path | New page | Action |", "|---|---|---|"]
    for e in entries:
        act = e["action"]
        if act in ("merge-into", "split-into", "copy-into") and e["order"]:
            act += f" ({e['order']})"
        if e["section"]:
            act += f" {e['section']}"
        rel = _rel(e["dest"], posixpath.dirname(report))
        rows_md.append(f"| `{e['src']}` | [{e['dest']}]({_enc(rel, False)}) | {act} |")
    total_src = len(by_src)
    n_stubs = sum(1 for e in entries if e["action"] == "stub")
    review = [
        f"- approximate link: {f}:{ln} -> {raw} now points at {dest} (line as before the move)"
        for f, ln, raw, dest in approx_links
    ]
    review += [
        f"- dangling directory link: {f}:{ln} -> {raw} (directory gone: link `Home` or a page)"
        for f, ln, raw in sorted(dangling)
    ]
    review += [f"- anchor unresolved: {f}:{ln} -> {raw}" for f, ln, raw in unresolved]
    review += [f"- pre-existing broken anchor: {f}:{ln} -> {raw}" for f, ln, raw in sorted(pre_anchors)]
    review += [
        f"- stub fallback: {d} (no 'points to' in its notes; pointed at where its source went)" for d in fallbacks
    ]
    final_md[report] = (
        "# Where did it go\n\nOld documentation paths and where each one lives now.\n\n"
        + "\n".join(rows_md)
        + "\n\n"
        + f"Files in: {total_src}. Accounted for: {total_src} "
        f"(moved {cnt['move']}, merged {cnt['merge-into']}, split {cnt['split-into']}, "
        f"archived {cnt['archive-into']}, kept {cnt['keep']}, copied {cnt['copy-into']}). Stubs: {n_stubs}.\n"
        + ("\n## Links to review\n\n" + "\n".join(review) + "\n" if review else "")
    )
    plan = Plan()
    plan.entries, plan.groups, plan.moved = entries, groups, moved
    plan.final_md, plan.nonmd_new, plan.nonmd_edits = final_md, nonmd_new, nonmd_edits
    plan.stats, plan.ambiguous, plan.report = stats, ambiguous, report
    plan.tracked = tracked
    plan.vanish = vanish_eff
    plan.noop = noop
    plan.tree = tree
    plan.approx = approx_links
    plan.dangling = sorted(dangling)
    plan.anchors = {"rewritten": n_anch, "unresolved": unresolved, "pre": sorted(pre_anchors)}
    plan.fallbacks = fallbacks
    stub_dests = {e["dest"] for e in entries if e["action"] == "stub"}
    stems = {
        _wiki_fold(posixpath.splitext(posixpath.basename(p))[0])
        for p in list(loc) + [e["dest"] for e in entries if e["action"] != "stub"]
    }
    for e in entries:
        e["expect_gone"] = e["src"] in vanish_eff
        e["reused"] = e["src"] in stub_dests  # a stub may reuse the path a move vacated
    plan.verify_ctx = {
        "entries": entries,
        "before_md": md_old,
        "comments": allowed,
        "report": report,
        "stems": stems,
        "dangling": {(f, raw) for f, _, raw in dangling},
        "before_broken": [r for s in stats.values() for r in s["broken"]],
        "nonmd_before": {p: nonmd_old[p] for p in nonmd_new},
        "nonmd_lines": nonmd_lines,
    }
    plan.bad = [(p, r) for p, s in stats.items() for r in s["bad"]]
    plan.wiki_amb = [m for s in stats.values() for m in s["amb"]]
    new_pages = set(groups) | {e["dest"] for e in entries if e["action"] == "stub"}
    plan.write_md = {
        p for p, t in final_md.items() if p == report or p in new_pages or p in moved.values() or md_old.get(p) != t
    }
    plan.by_src = by_src
    return plan


def apply(root, plan):
    done = set()
    for e in plan.entries:
        if e["action"] == "move" and e["dest"] != e["src"]:
            os.makedirs(os.path.dirname(os.path.join(root, e["dest"])), exist_ok=True)
            git(root, "mv", "--", e["src"], e["dest"])
            done.add(e["src"])
    for d, g in plan.groups.items():
        os.makedirs(os.path.dirname(os.path.join(root, d)), exist_ok=True)
        first = g[0]
        # a whole file that becomes the first part of a page keeps its history through the rename
        if (
            first["action"] in ("merge-into", "archive-into")
            and not first["section"]
            and first["src"] != d
            and len(plan.by_src[first["src"]]) == 1
        ):
            git(root, "mv", "--", first["src"], d)
            done.add(first["src"])
    gone = sorted(plan.vanish - done)
    if gone:
        git(root, "rm", "-q", "--", *gone)
    paths = []
    for p in sorted(plan.write_md):
        os.makedirs(os.path.dirname(os.path.join(root, p)), exist_ok=True)
        with open(os.path.join(root, p), "wb") as f:
            f.write(plan.final_md[p].encode("utf-8", "surrogateescape"))
        paths.append(p)
    for p, t in plan.nonmd_new.items():
        with open(os.path.join(root, p), "wb") as f:
            f.write(t.encode("utf-8", "surrogateescape"))
        paths.append(p)
    git(
        root,
        "add",
        "--pathspec-from-file=-",
        "--pathspec-file-nul",
        inp="\0".join(paths).encode("utf-8", "surrogateescape") + b"\0",
    )


def verify_disk(root, plan):
    files = {p.decode("utf-8", "surrogateescape") for p in git(root, "ls-files", "-z").split(b"\0") if p}
    md = {
        p: read_text(_read(os.path.join(root, p)))
        for p in files
        if _is_md(p) and os.path.isfile(os.path.join(root, p)) and not os.path.islink(os.path.join(root, p))
    }
    nm = {p: read_text(_read(os.path.join(root, p))) for p in plan.nonmd_new}
    errs, warns, acc = verify(plan.verify_ctx, files, md, nm)
    expected = plan.vanish | plan.write_md | set(plan.nonmd_new) | set(plan.moved.values())
    for ent in git(root, "status", "--porcelain", "-z", "--no-renames", "--untracked-files=all").split(b"\0"):
        if not ent:
            continue
        e = ent.decode("utf-8", "surrogateescape")
        if e[1] != " " or e[3:] not in expected:
            errs.append(f"unexpected tree state: {e[:2].strip() or '?'} {e[3:]}")
    return errs, warns, acc


def run(
    repo,
    map_path,
    dry_run=False,
    subfolder="",
    report="where-did-it-go.md",
    strict=False,
    out=None,
    excludes=(),
    link_map=None,
    repo_url="",
):
    out = out or sys.stdout
    root = os.path.realpath(repo)
    rows = load_mapping(map_path)
    lm = load_link_map(link_map) if link_map else None
    exclude_paths = [p for p in (_rel_in_repo(root, x) for x in (map_path, link_map) if x) if p]
    plan = build(
        root,
        rows,
        {
            "subfolder": subfolder,
            "report": report,
            "excludes": excludes,
            "exclude_paths": exclude_paths,
            "link_map": lm,
            "repo_url": repo_url,
        },
    )
    errs, warns, acc = verify(plan.verify_ctx, plan.tree, plan.final_md, {p: plan.nonmd_new[p] for p in plan.nonmd_new})

    def pr(*a):
        print(*a, file=out)

    pr(f"docmove plan{' (dry run, nothing written)' if dry_run else ''}: {len(plan.entries)} mapping rows")
    for e in plan.entries:
        extra = f" [order {e['order']}]" if e["order"] else ""
        extra += f" {e['section']}" if e["section"] else ""
        pr(f"  {e['action']:<12} {e['src']} -> {e['dest']}{extra}")
    tot = sum(s["edits"] for s in plan.stats.values())
    pr(
        f"markdown link rewrites: {tot} in {sum(1 for s in plan.stats.values() if s['edits'])} "
        f"of {len(plan.stats)} files"
    )
    for p, s in sorted(plan.stats.items()):
        if s["edits"]:
            pr(f"  {plan.moved.get(p, p)}: {s['edits']}")
    pr(f"non-markdown rewrites: {sum(len(v) for v in plan.nonmd_edits.values())} in {len(plan.nonmd_edits)} files")
    for p, v in sorted(plan.nonmd_edits.items()):
        for ln, o, n in v:
            pr(f"  {p}:{ln}: {o} -> {n}")
    if plan.ambiguous:
        pr(f"ambiguous literal references NOT rewritten: {len(plan.ambiguous)}")
        for p, ln, o in plan.ambiguous[:30]:
            pr(f"  {p}:{ln}: {o}")
    if plan.bad:
        pr(f"links with backslash escapes NOT rewritten: {len(plan.bad)}")
    for m in plan.wiki_amb:
        pr(f"ambiguous wiki link: {m}")
    for f, ln, raw, dest in plan.approx:
        pr(f"approximate link: {f}:{ln} -> {raw} now points at {dest}")
    for f, ln, raw in plan.dangling:
        pr(f"dangling directory link: {f}:{ln} -> {raw}")
    for f, ln, raw in plan.anchors["unresolved"]:
        pr(f"anchor unresolved: {f}:{ln} -> {raw}")
    for f, ln, raw in plan.anchors["pre"]:
        pr(f"pre-existing broken anchor: {f}:{ln} -> {raw}")
    pr(
        f"anchors: {plan.anchors['rewritten']} rewritten, {len(plan.anchors['unresolved'])} unresolved, "
        f"{len(plan.anchors['pre'])} pre-existing broken"
    )
    for d in plan.fallbacks:
        pr(f"stub fallback: {d}")
    for w in warns:
        pr(w)
    pr(f"files in: {len({e['src'] for e in plan.entries if e['action'] != 'stub'})}, accounted for: {acc}")
    fail = list(errs) + [f"ambiguous: {m}" for m in plan.wiki_amb]
    if strict:
        if plan.ambiguous:
            fail.append("strict: ambiguous literal references present")
        if plan.bad:
            fail.append("strict: un-rewritable links present")
        if plan.approx:
            fail.append("strict: approximate links to a split source present")
        if plan.dangling:
            fail.append("strict: dangling directory links present")
        if plan.anchors["unresolved"]:
            fail.append("strict: anchors that no longer resolve")
        if any(w.startswith("pre-existing") for w in warns):
            fail.append("strict: pre-existing unresolved links present")
    if fail:
        raise DocmoveError("post-check failed (nothing written):\n  " + "\n  ".join(fail[:50]))
    pr("post-check: ok")
    if dry_run:
        return 0
    hint = (
        "the tree in --repo is partly modified. To undo it, run this in that repository (it discards ALL "
        "uncommitted work there): git reset --hard HEAD && git clean -fd"
    )
    try:
        apply(root, plan)
        errs, _, acc = verify_disk(root, plan)
    except Exception as exc:  # anything that stops the apply leaves a half-moved tree
        raise DocmoveError(f"APPLY FAILED ({type(exc).__name__}): {exc}\n  {hint}") from None
    if errs:
        raise DocmoveError("POST-APPLY CHECK FAILED: " + hint + "\n  " + "\n  ".join(errs[:50]))
    pr(f"applied and staged (not committed); post-apply check ok, accounted for: {acc}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="docmove", description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--map", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--subfolder", default="")
    ap.add_argument("--report", default="where-did-it-go.md")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--link-map", help="CSV source,page: the page a link to a multi-page source is rewritten to")
    ap.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="non-markdown files whose literal doc paths are left alone (repeatable); defaults: "
        + ", ".join(DEFAULT_EXCLUDES)
        + ", the map, the link map and the report",
    )
    ap.add_argument("--repo-url", default="", help="https URL of the repository, for stubs that point at a repo file")
    a = ap.parse_args(argv)
    try:
        if a.subfolder and (not _NAME.match(a.subfolder) or "." in a.subfolder):
            raise DocmoveError(f"bad --subfolder {a.subfolder!r}")
        if a.repo_url and not _URL.fullmatch(a.repo_url):
            raise MapFormatError("--repo-url must be an https URL")
        return run(
            a.repo,
            a.map,
            a.dry_run,
            a.subfolder,
            a.report,
            a.strict,
            excludes=tuple(a.exclude),
            link_map=a.link_map,
            repo_url=a.repo_url,
        )
    except MapFormatError as e:
        print(f"docmove: error: {e}", file=sys.stderr)
        return 64
    except DocmoveError as e:
        print(f"docmove: error: {e}", file=sys.stderr)
    except Exception as e:  # fail closed on anything unexpected
        print(f"docmove: internal error: {type(e).__name__}: {e}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
