#!/usr/bin/env python3
"""identscan: fail a docs build on identifier-class leaks that secret scanners miss.

Usage: python3 -I scripts/identscan.py <dir-or-files...> [--allow FILE] [--format text|json]
                               [--all] [--max-bytes N]

Exit 0 clean, 1 findings, 2 cannot tell (unreadable, bad encoding, symlink, oversize,
bad allow file).  Exit 2 wins over 1 when both occur.

The report NEVER contains a matched value: only file, line, class and a constant
redacted shape.  Python 3 standard library only; all patterns are linear-time by
construction (bounded quantifiers; hostnames are walked in code, not matched with a nested quantifier).
"""

import argparse
import fnmatch
import ipaddress
import json
import math
import os
import re
import stat
import sys

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
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
    )
]
_BUILTIN_STR = {"n0call", "n0tst", "fn31pr", "fn31", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"}


def _path_match(path, pat):
    p = (path or "").replace(os.sep, "/")
    pat = pat.replace(os.sep, "/")
    return p == pat or p.endswith("/" + pat) or fnmatch.fnmatchcase(p, pat) or fnmatch.fnmatchcase(p, "*/" + pat)


class Allow:
    def __init__(self):
        self.nets = []  # (path_pattern or None, network)
        self.strs = []  # (path_pattern or None, lowercase glob/exact)

    @classmethod
    def load(cls, path):
        a = cls()
        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read(1024 * 1024)
        except (OSError, UnicodeDecodeError):
            raise AllowError("cannot read allow file") from None
        for n, line in enumerate(raw.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = [p.strip() for p in s.split("|", 2)]
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
RE6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
REMAC = re.compile(
    r"(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
    r"(?![0-9A-Fa-f]|[:-][0-9A-Fa-f])"
)
REMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])([A-Za-z0-9._%+-]{1,64})@"
    r"((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-])"
)
# Hostnames are found in code, not with one nested-quantifier regex.  A pattern of
# the shape (label\.)+tld goes quadratic on a long "a.a.a.a." line as soon as its
# start guard is lost, and a guard the next edit can drop is a weak defense.  Here
# a linear regex cuts the line into maximal [\w.-] runs and plain code walks each
# run's dot-separated labels, so the work is one pass over the line by construction.
RERUN = re.compile(r"[\w.-]+")
RELABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_INTERNAL_TLDS = ("lan", "local", "home", "internal", "corp")
RECALL = re.compile(r"(?<![A-Za-z0-9])[A-Z]{1,2}[0-9][A-Z]{1,3}(?![A-Za-z0-9])")
RECALL_CTX = re.compile(
    r"(?<![A-Za-z])(?:call[\s_-]?signs?|ham|hams|amateur|qrz|qso|cq)"
    r"(?![A-Za-z])",
    re.I,
)
REGRID = re.compile(r"(?<![A-Za-z0-9])[A-R]{2}[0-9]{2}(?:[a-x]{2})?(?![A-Za-z0-9])")
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


def _ipv4_findings(line, allow, path):
    for m in RE4.finditer(line):
        octs = [int(g) for g in m.groups()]
        if any(o > 255 for o in octs):
            continue
        a, b = octs[0], octs[1]
        if a == 255 and all(o in _MASK_OCT for o in octs):
            continue
        if a == 0 or a == 127 or a >= 224:
            continue
        ip = ipaddress.IPv4Address(".".join(map(str, octs)))
        if allow.ip_ok(ip, path):
            continue
        if a == 10:
            yield "private-ip", SHAPES["private-10"]
        elif a == 172 and 16 <= b <= 31:
            yield "private-ip", SHAPES["private-172"]
        elif a == 192 and b == 168:
            yield "private-ip", SHAPES["private-192"]
        elif a == 169 and b == 254:
            yield "private-ip", SHAPES["private-169"]
        elif a == 100 and 64 <= b <= 127:
            yield "cgnat-ip", SHAPES["cgnat-ip"]
        else:
            yield "public-ip", SHAPES["public-ip"]


def _ipv6_findings(line, allow, path):
    if line.count(":") < 2:
        return
    for m in RE6.finditer(line):
        try:
            ip = ipaddress.IPv6Address(m.group(0))
        except ValueError:
            continue
        n = int(ip)
        if n >> 121 == 0x7E:
            kind = "ipv6-local-ula"
        elif n >> 118 == 0x3FA:
            kind = "ipv6-local-ll"
        else:
            continue
        if allow.ip_ok(ip, path):
            continue
        yield "ipv6-local", SHAPES[kind]


def _mac_findings(line, allow, path):
    for m in REMAC.finditer(line):
        norm = m.group(0).lower().replace("-", ":")
        if len(set(norm.replace(":", ""))) == 1 and norm[0] in "0f":
            continue
        if norm.startswith(_MAC_DOC_PREFIX) or allow.str_ok(norm, path):
            continue
        yield "mac", SHAPES["mac"]


def _email_findings(line, allow, path):
    for m in REMAIL.finditer(line):
        local, dom = m.group(1).lower(), m.group(2).lower()
        if dom in _DOC_EMAIL or dom.endswith(_DOC_EMAIL_SUFFIX) or local == "git":
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


def _host_findings(line, allow, path):
    for host in _internal_hosts(line):
        if allow.str_ok(host, path):
            continue
        yield "internal-host", SHAPES["internal-host"]


def _radio_findings(line, allow, path):
    if RECALL_CTX.search(line):
        for m in RECALL.finditer(line):
            if not allow.str_ok(m.group(0), path):
                yield "callsign", SHAPES["callsign"]
    if REGRID_CTX.search(line):
        for m in REGRID.finditer(line):
            if not allow.str_ok(m.group(0), path):
                yield "grid", SHAPES["grid"]


def _secret_findings(line, allow, path):
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


def _cloud_findings(line, allow, path):
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
    _ipv6_findings,
    _mac_findings,
    _email_findings,
    _host_findings,
    _radio_findings,
    _secret_findings,
    _cloud_findings,
)


def scan_text(text, allow, path=None):
    """Return a list of Finding (one per line+class).  Never retains matched text."""
    out = []
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    for n, raw in enumerate(text.split("\n"), 1):
        if len(raw) < 6:
            continue
        line = _strip_angle(raw)
        seen = set()
        for det in _DETECTORS:
            for cls, shape in det(line, allow, path):
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


def scan_file(path, allow, max_bytes=DEFAULT_MAX_BYTES):
    return scan_text(_read_file(path, max_bytes), allow, path)


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


def run(paths, allow, all_files=False, max_bytes=DEFAULT_MAX_BYTES):
    findings, errors, nfiles = [], [], 0
    for arg in paths:
        for p in _expand(arg, all_files, errors):
            nfiles += 1
            try:
                for f in scan_file(p, allow, max_bytes):
                    findings.append((p, f))
            except ScanError as e:
                errors.append((p, str(e)))
    return findings, errors, nfiles


def main(argv=None):
    ap = argparse.ArgumentParser(prog="identscan", description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--allow", metavar="FILE")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--all", action="store_true", help="scan every file in directories")
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = ap.parse_args(argv)

    allow = Allow()
    if args.allow:
        try:
            allow = Allow.load(args.allow)
        except AllowError as e:
            print(f"identscan: error: {e}", file=sys.stderr)
            return 2

    findings, errors, nfiles = run(args.paths, allow, args.all, args.max_bytes)
    code = 2 if errors else (1 if findings else 0)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "tool": "identscan",
                    "exit": code,
                    "files_scanned": nfiles,
                    "findings": [{"file": p, "line": f.line, "class": f.cls, "shape": f.shape} for p, f in findings],
                    "errors": [{"file": p, "reason": r} for p, r in errors],
                },
                indent=1,
            )
        )
    else:
        for p, f in findings:
            print(f"{p}:{f.line}:{f.cls}: {f.shape}")
        for p, r in errors:
            print(f"{p}: error: {r}", file=sys.stderr)
        print(f"identscan: files={nfiles} findings={len(findings)} errors={len(errors)} exit={code}")
    return code


if __name__ == "__main__":
    sys.exit(main())
