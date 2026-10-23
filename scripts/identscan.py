#!/usr/bin/env python3
"""identscan: fail a docs build on identifier-class leaks that secret scanners miss.

Usage: python3 -I scripts/identscan.py <dir-or-files...> [--allow FILE] [--deny-file FILE] [--format text|json]
                               [--all] [--max-bytes N]

Placeholder-looking emails such as you@your-domain.com are findings unless the allow file
waives them with a reason.

Residual risk (not caught):
  * an address split by HTML tags or comments between the octets, text encoded more than three
    levels deep, and a public IPv4 split across a line break;
  * a public IPv6 address with only two explicit groups (2001::1, 2a00::5, 2620::1);
  * spelled-out or defanged forms other than [.] (.) {.} between digits: "10 dot 23", "[dot]";
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
DENY_WINDOW = 1024  # a longer line is searched in windows this wide, overlapping by DENY_OVERLAP
DENY_OVERLAP = 256  # so a pattern up to MAX_DENY_LEN (256) characters wide is never split by a boundary
DENY_BUDGET_SECONDS = 5.0  # per file; the regex pass runs in a worker that is killed at this point
DENY_INPROC_MAX = 4096  # total characters at or under which the regex pass runs in-process (file names)
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


_QUANT = re.compile(r"\{(\d+)(,(\d*))?\}")


def _regex_is_safe(pat):
    """Conservative check that a pattern cannot backtrack catastrophically.

    Refuses backreferences, conditionals and lookarounds, a quantified group whose body holds a
    quantifier or an alternation ((a+)+, (a*)*, (a|aa)*, (.*)*), and more than two unbounded
    quantifiers.  A refused pattern is used as plain text instead.
    """
    if re.search(r"\\[1-9]|\(\?(?!:)", pat):
        return False
    stack, unbounded, i, n = [], 0, 0, len(pat)
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
            if stack:
                stack[-1] = True
        elif c == "{":
            qm = _QUANT.match(pat, i)
            if qm:
                if qm.group(2) is not None and (qm.group(3) == "" or int(qm.group(3)) > 64):
                    unbounded += 1  # {n,} and wide {n,m} behave like * for backtracking cost
                if stack:
                    stack[-1] = True
                i = qm.end()
                continue
        i += 1
    return unbounded <= 2


def _window_search(rx, text):
    """Search text, in overlapping windows when it is long.  Never skips a long line."""
    if len(text) <= DENY_WINDOW:
        return rx.search(text) is not None
    step = DENY_WINDOW - DENY_OVERLAP
    for start in range(0, len(text), step):
        if rx.search(text[start : start + DENY_WINDOW]):
            return True
        if start + DENY_WINDOW >= len(text):
            break
    return False


def _deny_lines(pats, raws, norms):
    """1-based numbers of the lines any pattern hits.  A pattern with no regex is a substring test."""
    hits = set()
    lits = [lit for rx, lit in pats if rx is None]
    rxs = [rx for rx, _ in pats if rx is not None]
    for n, (raw, norm) in enumerate(zip(raws, norms, strict=True), 1):
        views = (raw,) if norm == raw else (raw, norm)
        if lits:
            lows = [v.lower() for v in views]
            if any(lit in low for low in lows for lit in lits):
                hits.add(n)
                continue
        if any(_window_search(rx, v) for rx in rxs for v in views):
            hits.add(n)
    return hits


def _deny_worker(conn, pats, raws, norms):
    try:
        conn.send(sorted(_deny_lines(pats, raws, norms)))
    finally:
        conn.close()


class Deny:
    """Caller-private deny patterns (for example a real callsign fed in from a secret).

    One literal-or-regex pattern per line, matched case-insensitively.  The operator wrote the
    file and is trusted; the guards below are there so a mistake cannot hang or silently blind the
    scan.

    * A line is a regex only when it compiles and passes _regex_is_safe (no nested quantifiers,
      backreferences or lookarounds); otherwise it is taken as literal text and the count is
      reported once on stderr, never the pattern.  That note does not change the exit code.
    * Long lines are searched in overlapping windows (DENY_WINDOW wide, DENY_OVERLAP overlap), never
      skipped.
    * The regex pass over one file runs in a worker process that is killed after
      DENY_BUDGET_SECONDS.  A killed pass falls back to the literal text of each pattern and counts
      the file as degraded; main() then prints a note (counts only) and exits 2 (cannot tell), or 1
      when there are findings.  A degraded deny pass is never a clean exit.

    The file's content is never echoed: a hit reports only file:line:deny.
    """

    def __init__(self):
        self.pats = []  # (compiled regex or None, lowercase literal text)
        self.literal_count = 0
        self.degraded = 0  # files whose regex pass was killed at the budget

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
            if len(s) > MAX_DENY_LEN or len(d.pats) >= MAX_DENY_PATTERNS:
                raise AllowError(f"deny file line {n}: pattern too long or too many patterns")
            rx = None
            try:
                rx = re.compile(s, re.I)
            except re.error:
                pass
            if rx is not None and not _regex_is_safe(s):
                rx = None
                d.literal_count += 1
            if (rx or re.compile(re.escape(s))).search(""):
                raise AllowError(f"deny file line {n}: pattern matches the empty string")
            d.pats.append((rx, s.lower()))
        return d

    def lines_hit(self, raws, norms):
        """Set of 1-based line numbers with a deny hit.  See the class docstring for the guards."""
        total = sum(len(x) for x in raws)
        has_regex = any(rx is not None for rx, _ in self.pats)
        if not has_regex or total <= DENY_INPROC_MAX or "fork" not in multiprocessing.get_all_start_methods():
            return _deny_lines(self.pats, raws, norms)
        ctx = multiprocessing.get_context("fork")
        recv, send = ctx.Pipe(duplex=False)
        proc = ctx.Process(target=_deny_worker, args=(send, self.pats, raws, norms), daemon=True)
        proc.start()
        send.close()
        got = None
        try:
            if recv.poll(DENY_BUDGET_SECONDS):
                got = recv.recv()
        except (EOFError, OSError):
            got = None
        if got is None:
            proc.kill()
            proc.join()
            self.degraded += 1
            return _deny_lines([(None, lit) for _, lit in self.pats], raws, norms)
        proc.join()
        return set(got)


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
REMAC = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})?"
    r"(?![0-9A-Fa-f]|[:-][0-9A-Fa-f])"
)
REMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\"-])([A-Za-z0-9._%+-]{1,64}|\"[^\"\r\n]{1,64}\")@"
    r"((?:[A-Za-z0-9-]{1,63}\.)+(?:xn--[A-Za-z0-9-]{2,59}|[A-Za-z]{2,24}))(?![A-Za-z0-9-])"
)
REEUI64 = re.compile(r"(?:[0-9A-Fa-f]{2}:){7}[0-9A-Fa-f]{2}")
REMAC4 = re.compile(r"(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f]|\.[0-9A-Fa-f])")
REMAC12 = re.compile(r"(?<![\w.:-])[0-9A-Fa-f]{12}(?![\w.:-])")
REMAC_CTX = re.compile(r"(?<![A-Za-z])(?:mac|ether|hwaddr|hw[\s_-]?addr(?:ess)?|lladdr)(?![a-z])", re.I)
REMAC_NOT = re.compile(r"(?<![A-Za-z])(?:commit|sha\d*|hash|rev|checksum|digest|git|md5|tag)(?![A-Za-z])", re.I)
RE4_LONG = re.compile(r"(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?=\.\d)")
RE4_DEC = re.compile(r"(?<![\w.:-])(\d{8,10})(?![\w-]|\.\w)")
RE4_HEX = re.compile(r"(?<![\w.:-])0[xX]([0-9A-Fa-f]{8})(?![\w-]|\.\w)")
RE4_HEXQ = re.compile(
    r"(?<![\w.])0[xX]([0-9A-Fa-f]{1,2})\.0[xX]([0-9A-Fa-f]{1,2})\.0[xX]([0-9A-Fa-f]{1,2})\.0[xX]([0-9A-Fa-f]{1,2})(?![\w-]|\.\w)"
)
RE4_OCT = re.compile(r"(?<![\w.])(\d{1,4})\.(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?![\w-]|\.\w)")
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
REGRID = re.compile(r"(?<![A-Za-z0-9])[A-Ra-r]{2}[0-9]{2}(?:[A-Xa-x]{2})?(?![A-Za-z0-9])")
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
        if r and (r[0] != "public-ip" or RE_IPCTX.search(line[max(0, m.start() - 24) : m.start()])):
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


def _ipv6_findings(line, allow, path, prev=""):
    if line.count(":") < 2:
        return
    cands = list(RE6.finditer(line))
    for pm in RE6_PREFIX.finditer(line):
        m = RE6_AFTER.match(line, pm.end())
        if m:
            cands.append(m)
    for m in cands:
        if REEUI64.fullmatch(m.group(0)):
            continue  # eight two-digit groups is an EUI-64 hardware address; the MAC detector owns it
        try:
            ip = ipaddress.IPv6Address(m.group(0))
        except ValueError:
            continue
        groups = sum(1 for g in m.group(0).split(":") if g)
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
        elif groups >= 3:
            # a global address needs three explicit groups: Beef::cafe and "use ::dead;" are code, not hosts
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


def _split_run_findings(ipline, nxt, allow, path):
    """A dotted run that ends one line and starts the next: 10.23. / 45.67.

    Only a private or shared-space result counts: a wrapped section number such as 1.2. / 3.4
    would otherwise read as a public address.
    """
    tail = RETAIL.search(ipline.rstrip())
    head = REHEAD.match(REEMPH.sub("", nxt))
    if tail and head:
        for cls, shape in _ipv4_findings(tail.group(0) + head.group(1), allow, path):
            if cls != "public-ip":
                yield cls, shape


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
            view = ipline if det in (_ipv4_findings, _ipv4_alt_findings) else line
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


def _safe_name(name):
    return re.sub(r"[^A-Za-z0-9._-]", "?", name)


_SEP_NUMS = re.compile(r"(?<![0-9])[0-9]{1,3}(?:[-_][0-9]{1,3}){3,}(?![0-9])")
_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{1,4}-){3,}-?[0-9A-Fa-f]{0,4}(?![0-9A-Za-z])")


def _spells_an_address(path):
    """True for a name that looks like an address in any separator: a.b, a-b-c-d, a_b_c_d, one long
    decimal run, or a hyphenated hex-group run.  Over-redacts on purpose (versions, dates)."""
    if re.search(r"[0-9]\.[0-9]|[0-9]{8}", path) or _SEP_NUMS.search(path):
        return True
    return any(any(c in "abcdefABCDEF" for c in m.group(0)) or "--" in m.group(0) for m in _HEX_RUN.finditer(path))


def display_path(path, index, deny=None):
    """A path that is safe to print: no control characters, no identifier from the name.

    A path made only of [A-Za-z0-9._/-] that carries no identifier prints as is.  Anything else
    prints as path#<index>/<basename> with every other character shown as '?', and the basename
    becomes <redacted> when the name (original or escaped) looks like an identifier itself.
    """
    safe = re.fullmatch(r"[A-Za-z0-9._/-]*", path) is not None
    probe = Allow()  # the caller's waivers do not apply to what we print
    # a digit.digit run is never printed: the scanner's own address pattern refuses a match followed by
    # ".md" (as in gw-10.1.2.3.md), so any name with one is treated as an identifier
    risky = _spells_an_address(path)
    spaced = path.replace("/", " ")
    names = [spaced, spaced + " ", re.sub(r"\.[A-Za-z0-9]{1,8}$", "", path).replace("/", " ") + " "]
    if safe and not risky and not any(scan_text(x, probe, None, deny) for x in names) and not path.startswith("-"):
        return path
    base = path.rsplit("/", 1)[-1]
    shown = _safe_name(base)
    if risky or any(scan_text(x, probe, None, deny) for x in (base, base + " ", shown, path, *names)):
        shown = "<redacted>"
    return f"path#{index}/{shown}"


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
    args = ap.parse_args(argv)

    allow, deny = Allow(), None
    try:
        if args.allow:
            allow = Allow.load(args.allow)
        if args.deny_file:
            deny = Deny.load(args.deny_file)
    except AllowError as e:
        print(f"identscan: error: {e}", file=sys.stderr)
        return 2

    if deny is not None and deny.literal_count:
        print(
            f"identscan: note: {deny.literal_count} deny pattern(s) treated as literal text (unsafe regex)",
            file=sys.stderr,
        )
    findings, errors, nfiles = run(args.paths, allow, args.all, args.max_bytes, deny)
    degraded = deny.degraded if deny is not None else 0
    code = 2 if errors else (1 if findings else (2 if degraded else 0))
    if degraded:
        print(f"identscan: note: deny matching degraded (budget) in {degraded} file(s); cannot tell", file=sys.stderr)
    fshow = [(display_path(p, i, deny), f) for p, i, f in findings]
    eshow = [(display_path(p, i, deny), r) for p, r, i in errors]
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
