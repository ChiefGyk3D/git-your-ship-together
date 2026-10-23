#!/usr/bin/env python3
"""identscan: fail a docs build on identifier-class leaks that secret scanners miss.

Usage: python3 -I scripts/identscan.py <dir-or-files...> [--allow FILE] [--deny-file FILE] [--strict-deny]
                               [--deny-budget SECONDS] [--format text|json]
                               [--all] [--max-bytes N]

Placeholder-looking emails such as you@your-domain.com are findings unless the allow file
waives them with a reason.

Residual risk (not caught):
  * an address split by HTML tags or comments between the octets, text encoded more than three
    levels deep, and a public IPv4 split across a line break;
  * a public IPv6 address with only two explicit groups (2001::1, 2a00::5, 2620::1);
  * spelled-out or defanged forms other than [.] (.) {.} between digits: "10 dot 23", "[dot]";
  * file names print only when plainly safe: a name with a callsign- or grid-shaped token, an address
    spelling, a non-ASCII or @ character is shown as <redacted> (over-redaction is intended);
  * the deny file is trusted input.  A deny entry is a regex only if it passes a nested-quantifier
    check, and the regex pass is killed after a per-file budget; a killed pass is a degraded run
    and exits 2 (cannot tell), never 0.

Exit 0 clean, 1 findings, 2 cannot tell (unreadable, bad encoding, symlink, oversize,
bad allow file).  Exit 2 wins over 1 when both occur.

The report NEVER contains a matched value: only file, line, class and a constant
redacted shape.  Python 3 standard library only; all patterns are linear-time by
construction (bounded quantifiers; hostnames are walked in code, not matched with a nested quantifier).
"""

import argparse
import fnmatch
import html
import ipaddress
import json
import math
import multiprocessing
import os
import posixpath
import re
import stat
import sys
import unicodedata
import urllib.parse

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
CONFIG_MAX_BYTES = 1024 * 1024  # --allow and --deny-file: over this is exit 2, never truncated
MAX_DENY_PATTERNS = 500
MAX_CONFIG_LINE = 4096
DENY_WINDOW = 1024  # minimum window; a pattern's own maximum width raises it (see _window_params)
DENY_MAX_WIDTH = 4096  # a pattern wider than this (or unbounded) is matched against the whole line
DENY_WHOLE_LINE_MAX = 1024 * 1024  # a line longer than this cannot be matched whole: degraded run
DENY_BUDGET_SECONDS = 5.0  # per file; the regex pass runs in a worker that is killed at this point
MAX_DENY_LEN = 256
MD_EXT = (".md", ".markdown", ".mdx")


class AllowError(Exception):
    pass


class Finding:
    __slots__ = ("line", "cls", "shape")

    def __init__(self, line, cls, shape):
        self.line, self.cls, self.shape = line, cls, shape

    def __repr__(self):
        return f"Finding(line={self.line}, cls={self.cls}, shape={self.shape})"


# --------------------------------------------------------------------- allow-list
_BUILTIN_NETS = [
    ipaddress.ip_network(n)
    for n in (
        "203.0.113.0/24",
        "198.51.100.0/24",
        "192.0.2.0/24",
        "1.1.1.1/32",
        "8.8.8.8/32",
        "9.9.9.9/32",
        "0.0.0.0/32",
        "127.0.0.0/8",
        "2001:db8::/32",
        "::1/128",
        "::/128",
    )
]
_BUILTIN_STR = {
    "n0call",
    "n0tst",
    "fn31pr",
    "fn31",
    "00:11:22:33:44:55",
    "aa:bb:cc:dd:ee:ff",
    # SSH clone URLs for three documented public hosts; any other git@host needs a waiver with a reason
    "git@github.com",
    "git@gitlab.com",
    "git@bitbucket.org",
}


def _norm_path(p):
    p = (p or "").replace(os.sep, "/")
    return posixpath.normpath(p) if p else p


def _path_match(path, pat):
    """A literal waiver path is the exact repo-relative path; only * ? [ in the entry widen it."""
    p, q = _norm_path(path), _norm_path(pat)
    if any(c in q for c in "*?["):
        return fnmatch.fnmatchcase(p, q)
    return p == q


def _repo_rel(path):
    """Path as the waiver file spells it: relative to the working directory when under it."""
    if os.path.isabs(path):
        try:
            rel = os.path.relpath(path)
        except ValueError:
            return path
        if not rel.startswith(".."):
            return rel
    return path


def _read_config(path, what):
    """Read a small config file: regular files only, strict UTF-8, over the cap is an error."""
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise AllowError(f"{what}: not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
    except AllowError:
        raise
    except OSError:
        raise AllowError(f"cannot read {what}") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AllowError(f"{what}: not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(CONFIG_MAX_BYTES + 1)
    except OSError:
        raise AllowError(f"cannot read {what}") from None
    finally:
        os.close(fd)
    if len(data) > CONFIG_MAX_BYTES:
        raise AllowError(f"{what}: exceeds size cap")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise AllowError(f"{what}: not valid UTF-8") from None


class Allow:
    def __init__(self):
        self.nets = []  # (path_pattern or None, network)
        self.strs = []  # (path_pattern or None, lowercase glob/exact)

    @classmethod
    def load(cls, path):
        a = cls()
        raw = _read_config(path, "allow file")
        for n, line in enumerate(raw.splitlines(), 1):
            if len(line) > MAX_CONFIG_LINE:
                raise AllowError(f"allow file line {n}: line too long")
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split("|", 2)]  # only the first two bars separate; a reason may hold more
            if len(parts) == 2:
                where, value, reason = None, parts[0], parts[1]
            elif len(parts) == 3:
                where, value, reason = parts[0] or None, parts[1], parts[2]
                if where is None:
                    raise AllowError(f"allow file line {n}: empty path field")
            else:
                raise AllowError(
                    f"allow file line {n}: reason is mandatory ('value | reason' or 'path | value | reason')"
                )
            if not value:
                raise AllowError(f"allow file line {n}: empty value")
            if len(reason.split()) < 2:
                raise AllowError(f"allow file line {n}: reason is mandatory and must be at least two words")
            try:
                a.nets.append((where, ipaddress.ip_network(value, strict=False)))
            except ValueError:
                a.strs.append((where, value.lower()))
        return a

    def ip_ok(self, ip, path=None):
        for n in _BUILTIN_NETS:
            if ip.version == n.version and ip in n:
                return True
        for where, n in self.nets:
            if ip.version == n.version and ip in n and (where is None or _path_match(path, where)):
                return True
        return False

    def str_ok(self, raw, path=None):
        low = raw.lower()
        if low in _BUILTIN_STR:
            return True
        for where, pat in self.strs:
            if (where is None or _path_match(path, where)) and fnmatch.fnmatchcase(low, pat):
                return True
        # a per-file or global exact IP written as a string is handled via nets
        return False


# {n}, {n,}, {n,m}, {,m} (= {0,m}) and {,} (= {0,}); a bare {} is literal text to re
_QUANT = re.compile(r"\{(?:(\d+)(,(\d*))?|,(\d*))\}")


def _regex_is_safe(pat):
    """Conservative check that a pattern cannot backtrack catastrophically.

    Refuses backreferences, conditionals and lookarounds, a quantified group whose body holds a
    quantifier or an alternation ((a+)+, (a*)*, (a|aa)*, (.*)*), and more than two unbounded
    quantifiers.  A refused pattern is used as plain text instead.
    """
    if re.search(r"\\[1-9]|\(\?(?!:)", pat):
        return False
    stack, unbounded, variable, bounded_sum, i, n = [], 0, 0, 0, 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i += 1
            if i < n and pat[i] == "^":
                i += 1
            if i < n and pat[i] == "]":
                i += 1
            while i < n and pat[i] != "]":
                i += 2 if pat[i] == "\\" else 1
            i += 1
            continue
        if c == "(":
            stack.append(False)
            i += 3 if pat.startswith("(?:", i) else 1
            continue
        if c == "|" and stack:
            stack[-1] = True
        elif c == ")" and stack:
            body = stack.pop()
            nxt = pat[i + 1 : i + 2]
            qm = _QUANT.match(pat, i + 1) if nxt == "{" else None
            if nxt in ("*", "+") or qm:
                if body:
                    return False
                if stack:
                    stack[-1] = True
            elif body and stack:
                stack[-1] = True
        elif c in "*+?":
            unbounded += c != "?"
            variable += c != "?"
            if stack:
                stack[-1] = True
        elif c == "{":
            qm = _QUANT.match(pat, i)
            if qm:
                if qm.group(4) is not None:  # {,m}
                    lo, hi = 0, (None if qm.group(4) == "" else int(qm.group(4)))
                else:
                    lo = int(qm.group(1))
                    hi = lo if qm.group(2) is None else (None if qm.group(3) == "" else int(qm.group(3)))
                if hi is None or hi > 64:
                    unbounded += 1  # {n,} and wide {n,m} behave like * for backtracking cost
                if hi is None or hi - lo >= 2:
                    variable += 1
                    bounded_sum += 0 if hi is None else hi
                if stack:
                    stack[-1] = True
                i = qm.end()
                continue
        i += 1
    # three or more variable-width parts can overlap each other: a{0,64}a{0,64}a{0,64}b
    return unbounded <= 2 and variable <= 2 and bounded_sum <= 128


class _TooLong(Exception):
    pass


def _max_width(pat):
    """Longest text the pattern can match, or None when that cannot be worked out."""
    try:
        parser = re._parser if hasattr(re, "_parser") else __import__("sre_parse")
        return int(parser.parse(pat, re.I).getwidth()[1])
    except Exception:
        return None


def _window_params(width):
    """(window, step) for a pattern up to width characters wide: the overlap is the width."""
    overlap = min(width, DENY_MAX_WIDTH)
    window = max(DENY_WINDOW, 4 * overlap)
    return window, window - overlap


def _window_search(rx, text, width):
    """Search text for rx.  Long lines go in overlapping windows, never skipped; a pattern that is
    unbounded or wider than DENY_MAX_WIDTH sees the whole line."""
    if width is None or width > DENY_MAX_WIDTH:
        if len(text) > DENY_WHOLE_LINE_MAX:
            raise _TooLong
        return rx.search(text) is not None
    window, step = _window_params(width)
    if len(text) <= window:
        return rx.search(text) is not None
    for start in range(0, len(text), step):
        if rx.search(text[start : start + window]):
            return True
        if start + window >= len(text):
            break
    return False


def _deny_lines(pats, raws, norms):
    """(1-based numbers of the lines any pattern hits, whether a line was too long to match)."""
    hits, too_long = set(), False
    lits = [lit for rx, lit, _ in pats if rx is None]
    rxs = [(rx, w) for rx, _, w in pats if rx is not None]
    for n, (raw, norm) in enumerate(zip(raws, norms, strict=True), 1):
        views = (raw,) if norm == raw else (raw, norm)
        if lits:
            lows = [v.lower() for v in views]
            if any(lit in low for low in lows for lit in lits):
                hits.add(n)
                continue
        try:
            if any(_window_search(rx, v, w) for rx, w in rxs for v in views):
                hits.add(n)
        except _TooLong:
            too_long = True
    return hits, too_long


def _deny_worker(conn, pats, raws, norms):
    try:
        hits, too_long = _deny_lines(pats, raws, norms)
        conn.send((sorted(hits), too_long))
    finally:
        conn.close()


class Deny:
    """Caller-private deny patterns (for example a real callsign fed in from a secret).

    One literal-or-regex pattern per line, matched case-insensitively.  The operator wrote the
    file and is trusted; the guards below are there so a mistake cannot hang or silently blind the
    scan.

    * A line is a regex only when it compiles and passes _regex_is_safe (no nested quantifiers,
      backreferences or lookarounds, at most two variable-width parts); otherwise it is taken as
      literal text and the count is reported once on stderr, never the pattern.  That note does not
      change the exit code unless --strict-deny is given.
    * No deny regex ever runs in the scanner's own process.  The regex pass over one file, and over
      the file names of a run, runs in a worker process that is killed after DENY_BUDGET_SECONDS
      (--deny-budget, 1 to 60, default 5).  Only a deny file with no regex entry at all is matched
      in-process.  A huge legitimate scan can exceed the budget and degrade; raise the budget for it.
    * Long lines are searched in overlapping windows sized from the pattern's own maximum width, never
      skipped; a pattern that is unbounded or wider than DENY_MAX_WIDTH sees the whole line, and a line
      over DENY_WHOLE_LINE_MAX cannot be matched whole.
    * A killed pass, an over-long line, or a platform without fork (no kill guard) is a degraded
      run.  The literal text of each pattern is still searched, main() prints a note (counts only)
      and exits 2 (cannot tell) even when there are findings, which are still printed.  A degraded
      deny pass is never a clean exit.

    The file's content is never echoed: a hit reports only file:line:deny.
    """

    def __init__(self):
        self.pats = []  # (compiled regex or None, lowercase literal text, max width)
        self.literal_count = 0
        self.degraded = 0  # files (or the file-name batch) whose regex pass was killed or cut short
        self.no_guard = False  # regex entries exist but this platform cannot fork a killable worker
        self.budget = None  # seconds; None means DENY_BUDGET_SECONDS

    @classmethod
    def load(cls, path):
        d = cls()
        raw = _read_config(path, "deny file")
        for n, line in enumerate(raw.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if len(line) > MAX_CONFIG_LINE:
                raise AllowError(f"deny file line {n}: line too long")
            if s[:4].lower() == "(?i)":
                s = s[4:]  # matching is case-insensitive already; keep a plain string a substring test
            if len(s) > MAX_DENY_LEN or len(d.pats) >= MAX_DENY_PATTERNS:
                raise AllowError(f"deny file line {n}: pattern too long or too many patterns")
            rx = None
            if re.search(r"[\\.^$*+?{}\[\]|()]", s):  # a plain string is a substring test, no regex at all
                try:
                    rx = re.compile(s, re.I)
                except re.error:
                    d.literal_count += 1  # looks like a regex, does not compile: taken as text
                if rx is not None and not _regex_is_safe(s):
                    rx = None
                    d.literal_count += 1
            if (rx or re.compile(re.escape(s))).search(""):
                raise AllowError(f"deny file line {n}: pattern matches the empty string")
            d.pats.append((rx, s.lower(), _max_width(s) if rx is not None else len(s)))
        return d

    def lines_hit(self, raws, norms):
        """Set of 1-based line numbers with a deny hit.  See the class docstring for the guards."""
        has_regex = any(rx is not None for rx, _, _ in self.pats)
        literal = [(None, lit, w) for _, lit, w in self.pats]
        if not has_regex:
            return _deny_lines(self.pats, raws, norms)[0]
        if "fork" not in multiprocessing.get_all_start_methods():
            self.no_guard = True
            return _deny_lines(literal, raws, norms)[0]
        ctx = multiprocessing.get_context("fork")
        recv, send = ctx.Pipe(duplex=False)
        proc = ctx.Process(target=_deny_worker, args=(send, self.pats, raws, norms), daemon=True)
        proc.start()
        send.close()
        got = None
        try:
            if recv.poll(self.budget if self.budget is not None else DENY_BUDGET_SECONDS):
                got = recv.recv()
        except (EOFError, OSError):
            got = None
        if got is None:
            proc.kill()
            proc.join()
            self.degraded += 1
            return _deny_lines(literal, raws, norms)[0]
        proc.join()
        if got[1]:
            self.degraded += 1
        return set(got[0])


# --------------------------------------------------------------------- helpers
_ANGLE = re.compile(r"<[A-Za-z_][A-Za-z_ -]{0,30}>")
_PH = re.compile(
    r"x{4,}|your|change|example|placeholder|redact|sample|dummy|"
    r"token_here|secret_here|insert|replace|todo",
    re.I,
)


def _strip_angle(line):
    return _ANGLE.sub(lambda m: " " * len(m.group(0)), line)


def _is_placeholder(s):
    core = re.sub(r"[-_.]", "", s).lower()
    if len(set(core)) <= 2:
        return True
    return bool(_PH.search(s))


def _entropy(s):
    n = len(s)
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------- patterns
RE4 = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?!\w|\.\w)")
RE6_BODY = r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])"
RE6 = re.compile(r"(?<![\w:.])" + RE6_BODY)
RE6_AFTER = re.compile(RE6_BODY)
# word + colon or equals in front of an address: SPF ip6:, addr:, dns=
RE6_PREFIX = re.compile(
    r"(?<![\w])(?:ip6|ipv6|inet6|addr|address|aaaa|ip|via|dns|ns|gw|peer|host|server|a)[:=]\s?", re.I
)
RE6_CTX = re.compile(
    r"(?:\b(?:ip6|ipv6|inet6|ip|addr(?:ess)?|host(?:name)?|server|gateway|peer|dns|nameserver|via|aaaa)\b)\W{0,3}$",
    re.I,
)
REMAC = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})?"
    r"(?![0-9A-Fa-f]|[:-][0-9A-Fa-f])"
)
REMAIL = re.compile(
    r"(?<![\w.%+\"-])([\w.%+-]{1,64}|\"[^\"\r\n]{1,64}\")@"
    r"((?:[\w-]{1,63}\.)+(?:xn--[A-Za-z0-9-]{2,59}|[^\W\d_]{2,24}))(?![\w-])"
)
REEUI64 = re.compile(r"(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2}")
REMAC4 = re.compile(r"(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f]|\.[0-9A-Fa-f])")
REMAC12 = re.compile(r"(?<![\w.:-])[0-9A-Fa-f]{12}(?![\w.:-])")
REMAC_CTX = re.compile(r"(?<![A-Za-z])(?:mac|ether|hwaddr|hw[\s_-]?addr(?:ess)?|lladdr)(?![a-z])", re.I)
REMAC_NOT = re.compile(r"(?<![A-Za-z])(?:commit|sha\d*|hash|rev|checksum|digest|git|md5|tag)(?![A-Za-z])", re.I)
RE4_LONG = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?=\.\d)")
RE4_DEC = re.compile(r"(?<![\w.:-])(\d{8,10})(?![\w-]|\.\w)")
RE4_HEX = re.compile(r"(?<![\w.:-])0[xX]([0-9A-Fa-f]{1,8})(?![\w-]|\.\w)")
RE4_HEXQ = re.compile(
    r"(?<![\w.])0[xX]([0-9A-Fa-f]{1,2})\.0[xX]([0-9A-Fa-f]{1,2})\.0[xX]([0-9A-Fa-f]{1,2})\.0[xX]([0-9A-Fa-f]{1,2})(?![\w-]|\.\w)"
)
RE4_OCT = re.compile(r"(?<![\w.])(\d{1,4})\.(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?![\w-]|\.\w)")
# the words that make a short (2- or 3-part) legacy form count when it decodes to a public address;
# server/host/gateway/peer are left out because "Server 24.04" and "nginx server 1.25.3" are versions
RE_IPCTX_STRONG = re.compile(r"(?:\bip\b|\baddr(?:ess)?\b|https?://)\W{0,3}$", re.I)
RE_IPCTX = re.compile(
    r"(?:\bip\b|\baddr(?:ess)?\b|\bhost(?:name)?\b|\bserver\b|\bgateway\b|\bpeer\b|https?://)\W{0,3}$", re.I
)
# emphasis markers sitting between digits/dots: 10.23.**45**.67
REEMPH = re.compile(r"(?<=[0-9.])[*_`]+(?=[0-9.])")
RETAIL = re.compile(r"(?<![\w.])(?:\d{1,3}\.){1,3}$")
REHEAD = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){0,3})(?![\w-])")
# every Unicode category Cf character (soft hyphen, LRM/RLM, bidi controls, U+2061-2064, ZWSP/ZWNJ/ZWJ,
# word joiner, BOM, tag characters ...) plus the combining grapheme joiner and the Mongolian vowel separator
_INVISIBLE = re.compile(
    "[\u00ad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891\u08e2\u180e\u200b-\u200f\u202a-\u202e"
    "\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb\U000110bd\U000110cd\U00013430-\U0001343f"
    "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0001\U000e0020-\U000e007f]"
)
_DOTS = {0x3002: ".", 0xFE52: ".", 0xFF0E: ".", 0xFF61: "."}
_DEFANG = re.compile(r"(?<=[0-9])[\[({]\.[\])}](?=[0-9])")
# Hostnames are found in code, not with one nested-quantifier regex.  A pattern of
# the shape (label\.)+tld goes quadratic on a long "a.a.a.a." line as soon as its
# start guard is lost, and a guard the next edit can drop is a weak defense.  Here
# a linear regex cuts the line into maximal [\w.-] runs and plain code walks each
# run's dot-separated labels, so the work is one pass over the line by construction.
RERUN = re.compile(r"[\w.-]+")
RELABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_INTERNAL_TLDS = ("lan", "local", "localdomain", "home", "internal", "intranet", "corp")
RECALL = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z]{1,2}|[0-9][A-Za-z]{1,2}|[A-Za-z][0-9])[0-9][A-Za-z]{1,3}(?![A-Za-z0-9])"
)
RECALL_CTX = re.compile(
    r"(?<![A-Za-z])(?:call[\s_-]?signs?|ham|hams|amateur|qrz|qso|cq)"
    r"(?![A-Za-z])",
    re.I,
)
REGRID = re.compile(r"(?<![A-Za-z0-9])[A-Ra-r]{2}[0-9]{2}(?:[A-Xa-x]{2}(?:[0-9]{2})?)?(?![A-Za-z0-9])")
REGRID_CTX = re.compile(
    r"(?<![A-Za-z])(?:grid(?:[\s_-]?square)?|locator|maidenhead|qth)"
    r"(?![A-Za-z])",
    re.I,
)
REDISCORD = re.compile(
    r"https?://(?:www\.|ptb\.|canary\.)?discord(?:app)?\.com/api"
    r"(?:/v\d+)?/webhooks/(\d{5,})/([A-Za-z0-9_-]{8,})",
    re.I,
)
RESLACK = re.compile(
    r"https?://hooks\.slack\.com/services/(T[A-Z0-9]{2,})/(B[A-Z0-9]{2,})"
    r"/([A-Za-z0-9]{6,})",
    re.I,
)
REJWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")
REPEM = re.compile(r"-----BEGIN [A-Z0-9][A-Z0-9 ]{0,40}-----")
REAUTH = re.compile(r"(?<![A-Za-z])(bearer|basic)[ \t]+([A-Za-z0-9._~+/=-]{8,})", re.I)
RESECRET = re.compile(
    r"(?:key|token|secret|passw(?:or)?d|pwd)\w{0,20}[\s:=\"'`]{1,6}"
    r"([A-Za-z0-9+/_=-]{20,})",
    re.I,
)
REARN = re.compile(r"arn:aws[a-z-]{0,10}:[a-z0-9-]{0,30}:[a-z0-9-]{0,30}:(\d{12}):")
REAWSACCT = re.compile(r"account[\s_-]{0,2}(?:id|number|no)?[\s:=\"'`#]{1,6}(\d{12})(?!\d)", re.I)
REAWSKEY = re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}(?![A-Za-z0-9])")
REGUID = re.compile(
    r"(?:tenant|subscription|directory)\w{0,12}[\s:=\"'`]{1,6}"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"(?![0-9a-f])",
    re.I,
)
REORG = re.compile(
    r"(?:org(?:anization)?|tenant)[\s_-]{0,2}(?:id)?[\s:=\"'`]{1,6}"
    r"([0-9a-f]{24})(?![0-9a-f])",
    re.I,
)

_MASK_OCT = {0, 128, 192, 224, 240, 248, 252, 254, 255}
_DOC_EMAIL = ("example.com", "example.net", "example.org")
_DOC_EMAIL_SUFFIX = (".example.com", ".example.net", ".example.org", ".example", ".test", ".invalid", ".localhost")
_MAC_DOC_PREFIX = ("00:00:5e:00:53:", "00:00:5e:90:10:")
_KNOWN_ACCT_PLACEHOLDERS = {"123456789012"}

SHAPES = {
    "private-10": "10.x.x.x",
    "private-172": "172.16-31.x.x",
    "private-192": "192.168.x.x",
    "private-169": "169.254.x.x",
    "cgnat-ip": "100.64-127.x.x",
    "public-ip": "<public-ipv4>",
    "ipv6-local-ula": "fc00::/7 address",
    "ipv6-local-ll": "fe80::/10 address",
    "ipv6-public": "<public-ipv6>",
    "deny": "<deny-pattern>",
    "mac": "xx:xx:xx:xx:xx:xx",
    "email": "<user>@<domain>",
    "internal-host": "<host>.<internal-tld>",
    "callsign": "<callsign>",
    "grid": "<grid>",
    "webhook-discord": "https://discord.com/api/webhooks/<id>/<token>",
    "webhook-slack": "https://hooks.slack.com/services/<T>/<B>/<token>",
    "jwt": "eyJ<header>.eyJ<payload>.<sig>",
    "pem": "-----BEGIN <type>-----",
    "auth-bearer": "Bearer <value>",
    "auth-basic": "Basic <value>",
    "secret-token": "<secret-keyword> <redacted-value>",
    "cloud-aws-account": "<aws-account-id>",
    "cloud-aws-key": "<aws-access-key-id>",
    "cloud-guid": "<tenant-guid>",
    "cloud-org": "<org-id>",
}


def _classify_v4(ip, allow, path):
    """(class, shape) for a routable or private address that is not allowed, else None."""
    a, b = ip.packed[0], ip.packed[1]
    if a == 0 or a == 127 or a >= 224 or allow.ip_ok(ip, path):
        return None
    if a == 10:
        return "private-ip", SHAPES["private-10"]
    if a == 172 and 16 <= b <= 31:
        return "private-ip", SHAPES["private-172"]
    if a == 192 and b == 168:
        return "private-ip", SHAPES["private-192"]
    if a == 169 and b == 254:
        return "private-ip", SHAPES["private-169"]
    if a == 100 and 64 <= b <= 127:
        return "cgnat-ip", SHAPES["cgnat-ip"]
    return "public-ip", SHAPES["public-ip"]


def _ipv4_findings(line, allow, path, prev=""):
    for m in RE4.finditer(line):
        octs = [int(g) for g in m.groups()]
        if any(o > 255 for o in octs):
            continue
        if octs[0] == 255 and all(o in _MASK_OCT for o in octs):
            continue
        r = _classify_v4(ipaddress.IPv4Address(bytes(octs)), allow, path)
        if r:
            yield r
    # 10.1.2.3.4: five or more octets is malformed but suspicious.  The first four count when they
    # are private or shared space; a public-looking prefix is left alone (version and OID strings).
    for m in RE4_LONG.finditer(line):
        octs = [int(g) for g in m.groups()]
        if any(o > 255 for o in octs):
            continue
        r = _classify_v4(ipaddress.IPv4Address(bytes(octs)), allow, path)
        if r and r[0] != "public-ip":
            yield r


def _ipv4_alt_findings(line, allow, path, prev=""):
    """IPv4 written as one integer, 0x hex, dotted hex or octal octets.

    Only a token that stands alone counts, and an ordinary-looking number is an address
    only when it decodes to a routable, non-documentation one.  Integers and bare hex that
    decode to a public address additionally need an ip/host/server word just before them,
    so timestamps, sizes and magic numbers stay quiet.
    """
    for m in RE4_DEC.finditer(line):
        v = int(m.group(1))
        if v > 0xFFFFFFFF:
            continue
        r = _classify_v4(ipaddress.IPv4Address(v), allow, path)
        if not r:
            continue
        ctx = bool(RE_IPCTX.search(line[max(0, m.start() - 24) : m.start()]))
        if ctx or (len(m.group(1)) == 10 and r[0] == "private-ip" and v >= 0xA9FE0000):
            yield r
    for m in RE4_HEX.finditer(line):
        r = _classify_v4(ipaddress.IPv4Address(int(m.group(1), 16)), allow, path)
        if not r:
            continue  # includes every value below 0x01000000 (0.x.x.x): 0x1f, 0xdead, 0xffffff
        ctx = RE_IPCTX.search(line[max(0, m.start() - 24) : m.start()])
        # eight digits: public needs a word, private does not.  Fewer digits (0xa000001) is a
        # magic number unless an ip word says otherwise, whatever it decodes to.
        if ctx or (len(m.group(1)) == 8 and r[0] != "public-ip"):
            yield r
    for m in RE4_HEXQ.finditer(line):
        octs = [int(g, 16) for g in m.groups()]
        r = _classify_v4(ipaddress.IPv4Address(bytes(octs)), allow, path)
        if r:
            yield r
    for m in RE4_OCT.finditer(line):
        parts = m.groups()
        if not any(len(x) > 1 and x[0] == "0" for x in parts):
            continue
        try:
            octs = [int(x, 8) if x[0] == "0" and len(x) > 1 else int(x) for x in parts]
        except ValueError:
            continue
        if any(o > 255 for o in octs):
            continue
        r = _classify_v4(ipaddress.IPv4Address(bytes(octs)), allow, path)
        if r:
            yield r


_ATON_PART = r"(?:0[xX][0-9A-Fa-f]{1,8}|[0-9]{1,12})"
RE4_ATON = re.compile(r"(?<![\w.:-])(" + _ATON_PART + r"(?:\." + _ATON_PART + r"){1,3})(?![\w-]|\.\w)")
RE4_OCTAL12 = re.compile(r"(?<![\w.:-])(0[0-7]{8,11})(?![\w-]|\.\w)")


def _aton_part(x):
    if x[:2] in ("0x", "0X"):
        return int(x, 16)
    if len(x) > 1 and x[0] == "0":
        return int(x, 8)  # ValueError on 8 or 9: the caller skips the token
    return int(x)


def _ipv4_legacy_findings(line, allow, path, prev=""):
    """inet_aton spellings: 10.1, 10.65535, 10.1.65535, mixed octal/hex parts, one octal token.

    These look like version numbers, so a token only counts after an ip/host/server/gateway/peer/addr
    word or http:// within 24 characters, and only when it decodes to a routable, non-documentation
    address.  A 2- or 3-part form that decodes to a public address needs the stronger ip/addr/address
    word or http:// ("Server 24.04" and "nginx server 1.25.3" are versions; "server 8.8" is the
    accepted false negative); one that decodes to a private, CGNAT or link-local address counts after
    any of the words ("server 10.1").
    """
    for m in RE4_ATON.finditer(line):
        before = line[max(0, m.start() - 24) : m.start()]
        if not RE_IPCTX.search(before):
            continue
        try:
            vals = [_aton_part(x) for x in m.group(1).split(".")]
        except ValueError:
            continue
        n = len(vals)
        if any(v > 255 for v in vals[:-1]) or vals[-1] >= 256 ** (5 - n):
            continue
        v = 0
        for x in vals[:-1]:
            v = (v << 8) | x
        v = (v << (8 * (5 - n))) | vals[-1]
        r = _classify_v4(ipaddress.IPv4Address(v), allow, path)
        if r and (n == 4 or r[0] != "public-ip" or RE_IPCTX_STRONG.search(before)):
            yield r
    for m in RE4_OCTAL12.finditer(line):
        if RE_IPCTX.search(line[max(0, m.start() - 24) : m.start()]) and int(m.group(1), 8) <= 0xFFFFFFFF:
            r = _classify_v4(ipaddress.IPv4Address(int(m.group(1), 8)), allow, path)
            if r:
                yield r


def _ipv6_findings(line, allow, path, prev=""):
    if line.count(":") < 2:
        return
    cands = list(RE6.finditer(line))
    prefixed = []
    for pm in RE6_PREFIX.finditer(line):
        m = RE6_AFTER.match(line, pm.end())
        if m:
            cands.append(m)
            prefixed.append(m)
    for m in cands:
        if REEUI64.fullmatch(m.group(0)):
            continue  # eight two-digit groups is an EUI-64 hardware address; the MAC detector owns it
        try:
            ip = ipaddress.IPv6Address(m.group(0))
        except ValueError:
            continue
        groups = sum(1 for g in m.group(0).split(":") if g)
        ctx = m in prefixed or bool(RE6_CTX.search(line[max(0, m.start() - 24) : m.start()]))
        if ip.ipv4_mapped is not None:
            if allow.ip_ok(ip, path):
                continue
            r = _classify_v4(ip.ipv4_mapped, allow, path)
            if r:
                yield r
            continue
        if ip.is_unspecified or ip.is_loopback or ip.is_multicast or allow.ip_ok(ip, path):
            continue
        n = int(ip)
        if n >> 121 == 0x7E:
            yield "ipv6-local", SHAPES["ipv6-local-ula"]
        elif n >> 118 == 0x3FA:
            yield "ipv6-local", SHAPES["ipv6-local-ll"]
        elif groups >= 3 or (groups == 2 and ctx):
            # a global address needs three explicit groups, or two after an ip/addr/host/dns word or an
            # ip6:/addr:/dns= prefix: Beef::cafe, std::vector and "use ::dead;" are code, not hosts
            yield "ipv6-public", SHAPES["ipv6-public"]


def _mac_findings(line, allow, path, prev=""):
    for m in REMAC.finditer(line):
        norm = m.group(0).lower().replace("-", ":")
        if len(set(norm.replace(":", ""))) == 1 and norm[0] in "0f":
            continue
        if norm.startswith(_MAC_DOC_PREFIX) or allow.str_ok(norm, path):
            continue
        yield "mac", SHAPES["mac"]
    ctx = bool(REMAC_CTX.search(line) or REMAC_CTX.search(prev))
    for m in REMAC4.finditer(line):
        v = m.group(0).replace(".", "").lower()
        if (any(c in "abcdef" for c in v) or ctx) and not allow.str_ok(v, path):
            yield "mac", SHAPES["mac"]
    if not REMAC_NOT.search(line):
        for m in REMAC12.finditer(line):
            v = m.group(0).lower()
            if len(set(v)) == 1 or allow.str_ok(v, path):
                continue
            mixed = not v.isdigit() and not v.isalpha()
            if ctx or mixed:
                yield "mac", SHAPES["mac"]


def _email_findings(line, allow, path, prev=""):
    for m in REMAIL.finditer(line):
        dom = m.group(2).lower()
        if dom in _DOC_EMAIL or dom.endswith(_DOC_EMAIL_SUFFIX):
            continue
        if allow.str_ok(m.group(0), path):
            continue
        yield "email", SHAPES["email"]


def _internal_hosts(line):
    """Yield the internal-TLD hostname in each [\\w.-] run of line (at most one per run)."""
    low = line.lower()
    if not any("." + t in low for t in _INTERNAL_TLDS):
        return  # cheap pre-filter: no candidate suffix on this line
    for run in RERUN.finditer(line):
        labels = run.group(0).split(".")
        last = -1
        for i, label in enumerate(labels):
            if not RELABEL.fullmatch(label):
                break
            if i >= 1 and label.lower() in _INTERNAL_TLDS:
                last = i
        if last >= 1:
            yield ".".join(labels[: last + 1])


def _host_findings(line, allow, path, prev=""):
    for host in _internal_hosts(line):
        if allow.str_ok(host, path):
            continue
        yield "internal-host", SHAPES["internal-host"]


def _radio_findings(line, allow, path, prev=""):
    if RECALL_CTX.search(line) or RECALL_CTX.search(prev):
        for m in RECALL.finditer(line):
            if not allow.str_ok(m.group(0), path):
                yield "callsign", SHAPES["callsign"]
    if REGRID_CTX.search(line) or REGRID_CTX.search(prev):
        for m in REGRID.finditer(line):
            if not allow.str_ok(m.group(0), path):
                yield "grid", SHAPES["grid"]


def _secret_findings(line, allow, path, prev=""):
    for m in REDISCORD.finditer(line):
        if not _is_placeholder(m.group(2)):
            yield "webhook", SHAPES["webhook-discord"]
    for m in RESLACK.finditer(line):
        if not _is_placeholder(m.group(3)):
            yield "webhook", SHAPES["webhook-slack"]
    if "eyJ" in line and REJWT.search(line):
        yield "jwt", SHAPES["jwt"]
    if "-----BEGIN " in line and REPEM.search(line):
        yield "pem", SHAPES["pem"]
    for m in REAUTH.finditer(line):
        v = m.group(2)
        if _is_placeholder(v) or re.fullmatch(r"[A-Z]?[a-z]+", v):
            continue
        if not (any(c.isdigit() for c in v) or any(c.isupper() for c in v[1:])):
            continue
        if allow.str_ok(v, path):
            continue
        yield "auth-header", SHAPES["auth-" + m.group(1).lower()]
    for m in RESECRET.finditer(line):
        v = m.group(1)
        if (
            _is_placeholder(v)
            or not any(c.isdigit() for c in v)
            or not any(c.isalpha() for c in v)
            or _entropy(v) < 3.5
            or allow.str_ok(v, path)
        ):
            continue
        yield "secret-token", SHAPES["secret-token"]


def _cloud_findings(line, allow, path, prev=""):
    for rx in (REARN, REAWSACCT):
        for m in rx.finditer(line):
            v = m.group(1)
            if v in _KNOWN_ACCT_PLACEHOLDERS or _is_placeholder(v) or allow.str_ok(v, path):
                continue
            yield "cloud-id", SHAPES["cloud-aws-account"]
    for m in REAWSKEY.finditer(line):
        if not _is_placeholder(m.group(0)) and not allow.str_ok(m.group(0), path):
            yield "cloud-id", SHAPES["cloud-aws-key"]
    for m in REGUID.finditer(line):
        if not _is_placeholder(m.group(1)) and not allow.str_ok(m.group(1), path):
            yield "cloud-id", SHAPES["cloud-guid"]
    for m in REORG.finditer(line):
        if not _is_placeholder(m.group(1)) and not allow.str_ok(m.group(1), path):
            yield "cloud-id", SHAPES["cloud-org"]


_DETECTORS = (
    _ipv4_findings,
    _ipv4_alt_findings,
    _ipv4_legacy_findings,
    _ipv6_findings,
    _mac_findings,
    _email_findings,
    _host_findings,
    _radio_findings,
    _secret_findings,
    _cloud_findings,
)


def _normalize(line):
    """Undo the cheap disguises before matching.

    Invisible (Cf) characters, HTML entities, %XX, fullwidth forms and dot lookalikes are undone in
    up to three passes (so %252e and &amp;#46; decode), then [.] (.) {.} between digits become dots.
    Not undone, and so residual risk: HTML tags or comments between octets, and encodings nested more
    than three deep.
    """
    if line.isascii() and "&" not in line and "%" not in line and ".]" not in line and ".)" not in line:
        if ".}" not in line:
            return line
    for _ in range(3):
        before = line
        if not line.isascii():
            line = _INVISIBLE.sub("", line)
        if "&" in line:
            line = html.unescape(line)
        if "%" in line:
            line = urllib.parse.unquote(line)
        if not line.isascii():
            line = _INVISIBLE.sub("", unicodedata.normalize("NFKC", line)).translate(_DOTS)
        if line == before:
            break
    if "." in line:
        line = _DEFANG.sub(".", line)
    return line


_JOIN_EMAIL_TAIL = re.compile(r"(?<![\w.%+\"-])[\w.%+-]{1,64}@$")
_JOIN_EMAIL_HEAD = re.compile(r"^\s*((?:[\w-]{1,63}\.)+(?:xn--[A-Za-z0-9-]{2,59}|[^\W\d_]{2,24}))(?![\w-])")
_JOIN_MAC_TAIL = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){1,7}$")
_JOIN_MAC_HEAD = re.compile(r"^\s*([0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){0,6})(?![0-9A-Fa-f:-])")
_JOIN_EMAIL_DOT_TAIL = re.compile(r"(?<![\w.%+\"-])[\w.%+-]{1,64}@(?:[\w-]{1,63}\.)+$")
_JOIN_EMAIL_DOT_HEAD = re.compile(r"^\s*((?:[\w-]{1,63}\.)*(?:xn--[A-Za-z0-9-]{2,59}|[a-z]{2,24}))(?![\w-])")
_JOIN_MAC_MID_TAIL = re.compile(r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){1,6}[0-9A-Fa-f]$")
_JOIN_MAC_MID_HEAD = re.compile(r"^\s*([0-9A-Fa-f](?:[:-][0-9A-Fa-f]{2}){0,6})(?![0-9A-Fa-f:-])")
_JOIN_V6_COLON_TAIL = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{1,4}:){1,6}[0-9A-Fa-f]{1,4}$")
_JOIN_V6_COLON_HEAD = re.compile(r"^\s*(::[0-9A-Fa-f:]{0,38})(?![\w:-])")
_JOIN_V6_TAIL = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{1,4}:){1,7}$")
_JOIN_V6_HEAD = re.compile(r"^\s*([0-9A-Fa-f:]{1,40})(?![\w:-])")
_JOIN_HOST_TAIL = re.compile(r"(?<![\w.-])([a-z][a-z0-9-]{0,62}\.)$")
_JOIN_HOST_HEAD = re.compile(r"^(" + "|".join(_INTERNAL_TLDS) + r")(?![\w-])")


def _split_run_findings(ipline, nxt, allow, path):
    """An identifier that ends one line and starts the next: 10.23. / 45.67, bob@ / corp-mail.io,
    aa:bb:cc: / dd:ee:12, 2606:4700: / 4700::1111, printer. / corp.

    The IPv4 join only counts a private or shared-space result: a wrapped section number such as
    1.2. / 3.4 would otherwise read as a public address.  The hostname join needs a lowercase label
    and a lowercase suffix word at the very start of the next line, so prose stays clean.
    """
    tail = RETAIL.search(ipline.rstrip())
    head = REHEAD.match(REEMPH.sub("", nxt))
    if tail and head:
        for cls, shape in _ipv4_findings(tail.group(0) + head.group(1), allow, path):
            if cls != "public-ip":
                yield cls, shape
    stripped = ipline.rstrip()
    t = _JOIN_EMAIL_TAIL.search(stripped)
    h = _JOIN_EMAIL_HEAD.match(nxt)
    if t and h:
        yield from _email_findings(t.group(0) + h.group(1), allow, path)
    t = _JOIN_EMAIL_DOT_TAIL.search(stripped)
    h = _JOIN_EMAIL_DOT_HEAD.match(nxt)
    if t and h:
        yield from _email_findings(t.group(0) + h.group(1), allow, path)
    t = _JOIN_MAC_MID_TAIL.search(stripped)
    h = _JOIN_MAC_MID_HEAD.match(nxt)
    if t and h:
        yield from _mac_findings(t.group(0) + h.group(1), allow, path)
    t = _JOIN_V6_COLON_TAIL.search(stripped)
    h = _JOIN_V6_COLON_HEAD.match(nxt)
    if t and h:
        yield from _ipv6_findings(t.group(0) + h.group(1), allow, path)
    t = _JOIN_MAC_TAIL.search(stripped)
    h = _JOIN_MAC_HEAD.match(nxt)
    if t and h:
        yield from _mac_findings(t.group(0) + h.group(1), allow, path)
    t = _JOIN_V6_TAIL.search(stripped)
    h = _JOIN_V6_HEAD.match(nxt)
    if t and h:
        yield from _ipv6_findings(t.group(0) + h.group(1), allow, path)
    t = _JOIN_HOST_TAIL.search(stripped)
    h = _JOIN_HOST_HEAD.match(nxt)
    if t and h and not t.group(1)[:-1].isdigit():
        for host in _internal_hosts(t.group(1) + h.group(1)):
            if not allow.str_ok(host, path):
                yield "internal-host", SHAPES["internal-host"]


def scan_text(text, allow, path=None, deny=None):
    """Return a list of Finding (one per line+class).  Never retains matched text."""
    out = []
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    raws = text.split("\n")
    norm = [_normalize(r) for r in raws]
    deny_hits = deny.lines_hit(raws, norm) if deny is not None else ()
    for n, raw in enumerate(raws, 1):
        line = norm[n - 1]
        if n in deny_hits:
            out.append(Finding(n, "deny", SHAPES["deny"]))
        if len(line) < 4 and len(raw) < 4:
            continue
        prev = norm[n - 2] if n > 1 else ""
        nxt = norm[n] if n < len(norm) else ""
        line = _strip_angle(line)
        ipline = REEMPH.sub("", line) if ("*" in line or "_" in line or "`" in line) else line
        seen, hits = set(), []

        for det in _DETECTORS:
            view = ipline if det in (_ipv4_findings, _ipv4_alt_findings, _ipv4_legacy_findings) else line
            hits.extend(det(view, allow, path, prev))
        hits.extend(_split_run_findings(ipline, nxt, allow, path))
        for cls, shape in hits:
            if cls not in seen:
                seen.add(cls)
                out.append(Finding(n, cls, shape))
    return out


# --------------------------------------------------------------------- files
class ScanError(Exception):
    pass


def _read_file(path, max_bytes):
    try:
        st = os.lstat(path)
    except OSError as e:
        raise ScanError(f"cannot stat ({e.strerror or 'error'})") from None
    if stat.S_ISLNK(st.st_mode):
        raise ScanError("symlink refused")
    if not stat.S_ISREG(st.st_mode):
        raise ScanError("not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise ScanError("symlink refused" if e.errno == 40 else f"unreadable ({e.strerror or 'error'})") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ScanError("not a regular file")
        with os.fdopen(fd, "rb", closefd=False) as fh:
            data = fh.read(max_bytes + 1)
    except OSError as e:
        raise ScanError(f"unreadable ({e.strerror or 'error'})") from None
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise ScanError("exceeds size cap")
    if b"\x00" in data:
        raise ScanError("binary file (NUL byte)")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ScanError("not valid UTF-8") from None


def scan_file(path, allow, max_bytes=DEFAULT_MAX_BYTES, deny=None):
    return scan_text(_read_file(path, max_bytes), allow, _repo_rel(path), deny)


def _expand(arg, all_files, errors):
    """Yield file paths; record refusals in errors."""
    try:
        st = os.lstat(arg)
    except OSError as e:
        errors.append((arg, "cannot stat (%s)" % (e.strerror or "error")))
        return
    if stat.S_ISLNK(st.st_mode):
        errors.append((arg, "symlink refused"))
        return
    if not stat.S_ISDIR(st.st_mode):
        yield arg
        return
    stack = [arg]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(os.scandir(d), key=lambda e: e.name)
        except OSError as e:
            errors.append((d, "unreadable directory (%s)" % (e.strerror or "error")))
            continue
        subdirs = []
        for e in entries:
            p = os.path.join(d, e.name)
            if e.name == ".git" and not e.is_symlink():
                continue
            if e.is_symlink():
                if all_files or e.name.lower().endswith(MD_EXT) or e.is_dir(follow_symlinks=True):
                    errors.append((p, "symlink refused"))
                continue
            if e.is_dir(follow_symlinks=False):
                subdirs.append(p)
            elif all_files or e.name.lower().endswith(MD_EXT):
                yield p
        stack.extend(reversed(subdirs))


_SEP_NUMS = re.compile(r"(?<![0-9])[0-9]{1,3}(?:[-_xX][0-9]{1,3}){2,}(?![0-9])")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{1,4}-){3,}-?[0-9A-Fa-f]{0,4}(?![0-9A-Za-z])")
_HEX8 = re.compile(r"(?<![0-9A-Za-z])(?:0[xX])?[0-9A-Fa-f]{8}(?![0-9A-Za-z])")
_GRID_TOKEN = re.compile(r"[A-Ra-r]{2}[0-9]{2}(?:[A-Xa-x]{2}(?:[0-9]{2})?)?")


def _spells_an_address(path):
    """True for a name that looks like an address in any separator: a.b, a-b-c, a_b_c, 192x168x7x9,
    one long decimal run, 8 hex digits (gw-c0a80709, 0xC0A80709), or a hyphenated hex-group run.
    Over-redacts on purpose (versions, dates, short hashes)."""
    if re.search(r"[0-9]\.[0-9]|[0-9]{8}", path) or _SEP_NUMS.search(path) or _HEX8.search(path):
        return True
    return any(any(c in "abcdefABCDEF" for c in m.group(0)) or "--" in m.group(0) for m in _HEX_RUN.finditer(path))


def _name_is_plain(component):
    """A path component that may be printed: only [A-Za-z0-9._-], no address spelling, and no
    callsign- or grid-shaped token (radio identifiers are context-gated in text, not in names)."""
    if not re.fullmatch(r"[A-Za-z0-9._-]*", component) or component.startswith("-"):
        return False
    if _spells_an_address(component):
        return False
    return not any(
        RECALL.fullmatch(tok) or _GRID_TOKEN.fullmatch(tok) for tok in re.findall(r"[A-Za-z0-9]+", component)
    )


def _name_probes(path):
    """The strings a file name is checked as: the name itself, with a trailing space, extension stripped."""
    spaced = path.replace("/", " ")
    return [spaced, spaced + " ", re.sub(r"\.[A-Za-z0-9]{1,8}$", "", path).replace("/", " ") + " "]


def display_path(path, index, denied=False):
    """A path that is safe to print.

    It prints as is only when every component is plain (see _name_is_plain), the name carries no
    identifier the scanner knows, and no deny pattern hits it (``denied``, decided by the caller in the
    guarded worker).  Otherwise it prints as path#<index>/<basename>, the basename again only when
    plain, else <redacted>.  Nothing of a non-ASCII or @-containing name is ever printed.
    Over-redaction is accepted.
    """
    probe = Allow()  # the caller's waivers do not apply to what we print
    comps = path.split("/")
    base = comps[-1]

    def clean(text):
        return not any(scan_text(x, probe) for x in _name_probes(text))

    if all(_name_is_plain(c) for c in comps) and clean(path) and not denied:
        return path
    shown = base if _name_is_plain(base) and clean(base) and not denied else "<redacted>"
    return f"path#{index}/{shown}"


def _denied_paths(deny, paths):
    """Which of paths a deny pattern hits, decided in one guarded worker call for the whole run."""
    if deny is None or not paths:
        return set()
    flat, owner = [], []
    for p in paths:
        for probe in [*_name_probes(p), p.rsplit("/", 1)[-1]]:
            flat.append(probe)
            owner.append(p)
    hits = deny.lines_hit(flat, flat)
    return {owner[n - 1] for n in hits}


def run(paths, allow, all_files=False, max_bytes=DEFAULT_MAX_BYTES, deny=None):
    findings, errors, nfiles = [], [], 0
    walk_errors = []
    for arg in paths:
        for p in _expand(arg, all_files, walk_errors):
            nfiles += 1
            try:
                for f in scan_file(p, allow, max_bytes, deny):
                    findings.append((p, nfiles, f))
            except ScanError as e:
                errors.append((p, str(e), nfiles))
    errors.extend((p, r, 0) for p, r in walk_errors)
    return findings, errors, nfiles


def _budget(text):
    try:
        v = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number of seconds from 1 to 60") from None
    if not 1 <= v <= 60:
        raise argparse.ArgumentTypeError("must be a number of seconds from 1 to 60")
    return v


def _nonneg_int(text):
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from None
    if v < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return v


def main(argv=None):
    """Run the scan; anything unexpected is exit 2 (cannot tell) with no traceback and no content."""
    try:
        return _main(argv)
    except SystemExit:
        raise
    except Exception:
        print("identscan: error: internal error, cannot tell", file=sys.stderr)
        return 2


def _main(argv=None):
    ap = argparse.ArgumentParser(prog="identscan", description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--allow", metavar="FILE", help="waivers: 'value | reason' or 'path | value | reason'")
    ap.add_argument("--deny-file", metavar="FILE", help="private patterns to flag, one literal-or-regex per line")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--all", action="store_true", help="scan every file in directories")
    ap.add_argument("--max-bytes", type=_nonneg_int, default=DEFAULT_MAX_BYTES)
    ap.add_argument(
        "--strict-deny", action="store_true", help="a deny entry that had to be taken as literal text is exit 2"
    )
    ap.add_argument(
        "--deny-budget",
        type=_budget,
        default=None,
        metavar="SECONDS",
        help="per-file budget for deny regexes, 1 to 60 (default 5)",
    )
    args = ap.parse_args(argv)

    allow, deny = Allow(), None
    try:
        if args.allow:
            allow = Allow.load(args.allow)
        if args.deny_file:
            deny = Deny.load(args.deny_file)
            deny.budget = args.deny_budget
    except AllowError as e:
        print(f"identscan: error: {e}", file=sys.stderr)
        return 2

    if deny is not None and deny.literal_count:
        print(
            f"identscan: note: {deny.literal_count} deny pattern(s) treated as literal text (invalid or unsafe regex)",
            file=sys.stderr,
        )
    findings, errors, nfiles = run(args.paths, allow, args.all, args.max_bytes, deny)
    shown_paths = sorted({p for p, _, _ in findings} | {p for p, _, _ in errors})
    before_names = (deny.degraded, deny.no_guard) if deny is not None else (0, False)
    denied = _denied_paths(deny, shown_paths)
    # a name pass that was killed, cut short or ran unguarded cannot say which names the deny file hits,
    # so no name is printed in the clear
    names_unsure = deny is not None and (deny.degraded, deny.no_guard) != before_names
    degraded = deny.degraded if deny is not None else 0
    no_guard = deny is not None and deny.no_guard
    strict = args.strict_deny and deny is not None and deny.literal_count > 0
    code = 2 if (errors or degraded or no_guard or strict) else (1 if findings else 0)
    if degraded:
        print(f"identscan: note: deny matching degraded (budget) in {degraded} file(s); cannot tell", file=sys.stderr)
    if no_guard:
        print("identscan: note: deny regex pass ran without a kill guard (no fork); cannot tell", file=sys.stderr)
    fshow = [(display_path(p, i, names_unsure or p in denied), f) for p, i, f in findings]
    eshow = [(display_path(p, i, names_unsure or p in denied), r) for p, r, i in errors]
    if args.format == "json":
        print(
            json.dumps(
                {
                    "tool": "identscan",
                    "exit": code,
                    "files_scanned": nfiles,
                    "deny_degraded_files": degraded,
                    "findings": [{"file": p, "line": f.line, "class": f.cls, "shape": f.shape} for p, f in fshow],
                    "errors": [{"file": p, "reason": r} for p, r in eshow],
                },
                indent=1,
            )
        )
    else:
        for p, f in fshow:
            print(f"{p}:{f.line}:{f.cls}: {f.shape}")
        for p, r in eshow:
            print(f"{p}: error: {r}", file=sys.stderr)
        print(f"identscan: files={nfiles} findings={len(findings)} errors={len(errors)} exit={code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
