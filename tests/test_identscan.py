"""identscan is a gate on public wiki pages; this is the check on it.

Fixtures are synthetic: documentation ranges, example.com, and values assembled at
runtime. The redaction tests assert that no matched value reaches stdout, stderr or
the JSON report; the timing tests feed it 200 KB hostile lines.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = str(REPO / "scripts" / "identscan.py")
_spec = importlib.util.spec_from_file_location("identscan", TOOL)
ids = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ids)


def classes(text, allow=None):
    return sorted({(f.line, f.cls) for f in ids.scan_text(text, allow or ids.Allow())})


def cls_set(text, allow=None):
    return {c for _, c in classes(text, allow)}


def run(*args, timeout=30):
    p = subprocess.run([sys.executable, "-I", TOOL, *args], capture_output=True, timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


class Tmp(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def w(self, name, data, mode="w"):
        p = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(data, bytes):
            mode = "wb"
        with open(p, mode, **({} if mode == "wb" else {"encoding": "utf-8", "newline": ""})) as fh:
            fh.write(data)
        return p


class TestIPv4(unittest.TestCase):
    def test_private_ranges(self):
        for ip in ("10.20.30.40", "172.16.0.9", "172.31.255.1", "192.168.77.41"):
            self.assertEqual(cls_set("host " + ip + " up"), {"private-ip"}, ip)

    def test_private_boundaries_are_public(self):
        for ip in ("172.15.0.1", "172.32.0.1", "192.169.0.1", "11.0.0.1"):
            self.assertEqual(cls_set("x " + ip), {"public-ip"}, ip)

    def test_cgnat(self):
        self.assertEqual(cls_set("tailnet 100.64.0.1"), {"cgnat-ip"})
        self.assertEqual(cls_set("tailnet 100.127.255.254"), {"cgnat-ip"})
        self.assertEqual(cls_set("x 100.63.0.1"), {"public-ip"})
        self.assertEqual(cls_set("x 100.128.0.1"), {"public-ip"})

    def test_public_flagged(self):
        self.assertEqual(cls_set("server 45.33.32.156"), {"public-ip"})

    def test_not_ips(self):
        for t in (
            "v1.2.3.4",
            "version 1.2.3.4.5",
            "999.1.1.1",
            "mask 255.255.255.0",
            "mask 255.255.255.255",
            "1.2.3",
            "multicast 224.0.0.251",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_builtin_allow(self):
        for ip in (
            "203.0.113.7",
            "198.51.100.200",
            "192.0.2.1",
            "127.0.0.1",
            "127.9.9.9",
            "0.0.0.0",
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
        ):
            self.assertEqual(cls_set("x " + ip), set(), ip)

    def test_placeholders(self):
        for t in ("192.168.1.x", "10.0.0.x/24", "x.x.x.x", "192.168.x.x", "<IP>", "<HOST>", "ssh admin@<IP>"):
            self.assertEqual(cls_set(t), set(), t)

    def test_partial_private_forms_are_not_findings(self):
        for t in (
            "192.168.1.x",
            "192.168.1.X",
            "192.168.1.xxx",
            "10.0.x.x",
            "10.0.0.x",
            "172.16.x.x",
            "172.16.0.x/12",
            "ssh admin@192.168.1.x",
            "gw 192.168.<N>.1",
            "192.168.1.<IP>",
            "http://<IP>:8080/",
            "<IP>",
            "<ip>",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_partial_form_does_not_hide_a_real_neighbor(self):
        self.assertEqual(cls_set("192.168.1.x and 10.20.30.40"), {"private-ip"})
        self.assertEqual(cls_set("<IP> 192.168.1.x 172.20.1.1"), {"private-ip"})

    def test_angle_placeholder_does_not_hide_real_value(self):
        self.assertEqual(cls_set("<IP> and 192.168.4.4"), {"private-ip"})

    def test_fenced_code_counts(self):
        txt = "text\n```bash\nssh root@10.1.2.3\n```\n"
        self.assertEqual(classes(txt), [(3, "private-ip")])

    def test_one_per_line_class(self):
        self.assertEqual(classes("10.1.1.1 10.2.2.2"), [(1, "private-ip")])


class TestIPv6(unittest.TestCase):
    def test_local(self):
        self.assertEqual(cls_set("addr fd12:3456:789a::1"), {"ipv6-local"})
        self.assertEqual(cls_set("addr fe80::1ff:fe23:4567:890a"), {"ipv6-local"})
        self.assertEqual(cls_set("addr fc00::1"), {"ipv6-local"})

    def test_not_flagged(self):
        for t in ("2001:db8::1", "2001:db8:abcd::7", "::1", "time 12:30:45", "::", "ff02::1"):
            self.assertEqual(cls_set(t), set(), t)

    def test_mac_not_ipv6(self):
        self.assertEqual(cls_set("aa:bb:cc:dd:ee:f0"), {"mac"})


class TestMac(unittest.TestCase):
    def test_flag(self):
        self.assertEqual(cls_set("nic 3c:52:82:aa:10:5b"), {"mac"})
        self.assertEqual(cls_set("nic 3C-52-82-AA-10-5B"), {"mac"})

    def test_placeholder_and_special(self):
        for t in (
            "00:11:22:33:44:xx",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "00:00:5e:00:53:af",
            "aa:bb:..",
            "xx:xx:xx:xx:xx:xx",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_not_part_of_longer(self):
        self.assertEqual(cls_set("3c:52:82:aa:10:5b:99"), set())


class TestEmailHost(unittest.TestCase):
    def test_email(self):
        self.assertEqual(cls_set("mail bob.smith@corp-mail.io"), {"email"})
        self.assertEqual(cls_set("From: Bob <bob@corp-mail.io>"), {"email"})

    def test_email_allowed(self):
        for t in (
            "a@example.com",
            "a@example.net",
            "a@example.org",
            "a@mail.example",
            "a@sub.example.com",
            "git@github.com",
            "a@host.test",
            "a@x.invalid",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_not_email(self):
        for t in ("pkg@1.2.3", "@scope/name", "user@host", "a@b"):
            self.assertEqual(cls_set(t), set(), t)

    def test_internal_hosts(self):
        for h in ("nas.lan", "printer.home", "db01.prod.internal", "fs.corp", "pi.local", "NAS.LAN"):
            self.assertEqual(cls_set("connect to " + h + " now"), {"internal-host"}, h)

    def test_hosts_not_flagged(self):
        for t in (
            "example.com",
            "host.example",
            ".env.local",
            "localhost",
            "<HOST>",
            "www.github.com",
            "the file config.localx",
        ):
            self.assertEqual(cls_set(t), set(), t)


class TestHostnameWalk(unittest.TestCase):
    def test_hits(self):
        for t in (
            "nas.lan",
            "host a.b.corp ok",
            "ping NAS.LAN.",
            "see (db1.internal)",
            "x.home/path",
            "a-b.c-d.local:22",
            "svc.lan.example.com",
        ):
            self.assertEqual(cls_set(t), {"internal-host"}, t)

    def test_misses(self):
        for t in (
            "lan",
            ".lan",
            "x_y.lan",
            "-a.lan",
            "a-.lan",
            "a.lanx",
            "a.lan-x",
            "a..lan",
            "file.localhost",
            "word.homes",
            "a" * 64 + ".lan",
            "x.lan_y",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_label_length_edge(self):
        self.assertEqual(cls_set("a" * 63 + ".lan"), {"internal-host"})

    def test_allow_sees_the_whole_host(self):
        a = ids.Allow()
        a.strs.append((None, "nas.lan"))
        self.assertEqual(cls_set("nas.lan.", a), set())
        self.assertEqual(cls_set("other.nas.lan", a), {"internal-host"})


class TestRadio(unittest.TestCase):
    def test_callsign_with_context(self):
        self.assertEqual(cls_set("My callsign is W1ABC."), {"callsign"})
        self.assertEqual(cls_set("callsign: K9XYZ"), {"callsign"})
        self.assertEqual(cls_set("Licensed ham AB1CD here"), {"callsign"})

    def test_callsign_without_context(self):
        for t in ("Part number W1ABC", "model K9XYZ", "H2O and CO2 and S3B"):
            self.assertEqual(cls_set(t), set(), t)

    def test_callsign_allow(self):
        self.assertEqual(cls_set("callsign N0CALL and N0TST"), set())

    def test_callsign_lowercase_is_found(self):
        # fix round 1, item 5: the identifier matches in either case (the spike pinned the opposite)
        self.assertEqual(cls_set("callsign w1abc"), {"callsign"})

    def test_grid_with_context(self):
        self.assertEqual(cls_set("Grid square: EM73ab"), {"grid"})
        self.assertEqual(cls_set("my QTH locator is FM18"), {"grid"})

    def test_grid_without_context(self):
        for t in ("Model EM73ab", "EM73", "see AB12cd"):
            self.assertEqual(cls_set(t), set(), t)

    def test_grid_allow(self):
        self.assertEqual(cls_set("grid FN31pr and FN31"), set())


class TestSecrets(unittest.TestCase):
    def test_webhooks(self):
        d = "https://discord.com/api/webhooks/" + "1234567890123456" + "/" + "AbC" * 12
        s = "https://hooks.slack.com/services/T0ABC1234/B0DEF5678/" + "q9W8e7R6t5Y4u3I2o1P0aSdF"
        self.assertEqual(cls_set(d), {"webhook"})
        self.assertEqual(cls_set(s), {"webhook"})
        self.assertEqual(cls_set("https://discord.com/api/webhooks/ID/TOKEN"), set())
        self.assertEqual(cls_set("https://hooks.slack.com/services/T000/B000/XXXX"), set())

    def test_jwt(self):
        j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpM"
        self.assertEqual(cls_set("tok " + j), {"jwt"})
        self.assertEqual(cls_set("eyJ is a prefix"), set())

    def test_pem(self):
        self.assertEqual(cls_set("-----BEGIN RSA PRIVATE KEY-----"), {"pem"})
        self.assertEqual(cls_set("-----BEGIN CERTIFICATE-----"), {"pem"})

    def test_auth_headers(self):
        self.assertEqual(cls_set("Authorization: Bearer Zx81kLmQ92pTrv0aBc"), {"auth-header"})
        self.assertEqual(cls_set("Authorization: Basic dXNlcjpwYXNzd29yZA=="), {"auth-header"})
        for t in (
            "Bearer authentication is used",
            "Basic Authentication",
            "Authorization: Bearer <token>",
            "Authorization: Bearer $TOKEN",
            "Bearer YOUR_TOKEN_HERE",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_secret_token(self):
        v = "k3J9xQ2mZ7vL0pR4tY8wB1nC6dF5gH"
        for t in ("api_key = " + v, 'token: "' + v + '"', "export SECRET_TOKEN=" + v, "the password " + v):
            self.assertEqual(cls_set(t), {"secret-token"}, t)

    def test_secret_token_negatives(self):
        for t in (
            "api_key = changeme",
            "token: " + "a" * 40,
            "secret: your-secret-goes-here-xx",
            "key configuration-management-guidelines",
            "API_KEY=${API_KEY_VALUE_FROM_ENV}",
            "token: xxxxxxxxxxxxxxxxxxxxxxxxxx1",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_cloud_ids(self):
        self.assertEqual(cls_set("AWS account id: 493017265804"), {"cloud-id"})
        self.assertEqual(cls_set("arn:aws:iam::493017265804:role/x"), {"cloud-id"})
        self.assertEqual(cls_set("key AKIA" + "QWERTYUIOPASDFGH"), {"cloud-id"} | cls_set("key"))
        self.assertEqual(cls_set("tenant_id = 7b1f3c2e-90ad-4c11-8e5d-2a6f4d1c9b03"), {"cloud-id"})
        self.assertEqual(cls_set("org id: 5f3a9c1d7e2b4a6c8d0e1f2a"), {"cloud-id"})

    def test_cloud_id_placeholders(self):
        for t in (
            "account id: 123456789012",
            "tenant_id = 00000000-0000-0000-0000-000000000000",
            "account id: 000000000000",
            "org id: 000000000000000000000000",
            "account id: <ACCOUNT_ID>",
        ):
            self.assertEqual(cls_set(t), set(), t)


class TestAllow(Tmp):
    def af(self, body):
        return self.w("allow.txt", body)

    def test_cidr_and_exact(self):
        a = ids.Allow.load(
            self.af(
                "# c\n10.20.0.0/16 | lab net documented in the public wiki\nnas.lan | demo host used in screenshots\n"
            )
        )
        self.assertEqual(cls_set("10.20.5.5", a), set())
        self.assertEqual(cls_set("10.21.5.5", a), {"private-ip"})
        self.assertEqual(cls_set("nas.lan", a), set())
        self.assertEqual(cls_set("db.lan", a), {"internal-host"})

    def test_per_file(self):
        a = ids.Allow.load(self.af("docs/a.md | 10.9.9.9 | sample in a.md only\n"))
        f = ids.scan_text("10.9.9.9", a, path="docs/a.md")
        g = ids.scan_text("10.9.9.9", a, path="docs/b.md")
        self.assertEqual(len(f), 0)
        self.assertEqual(len(g), 1)

    def test_reason_mandatory(self):
        for body in ("10.9.9.9\n", "10.9.9.9 |\n", "10.9.9.9 |   \n", "a.md | 10.9.9.9 | \n", "|reason only\n"):
            with self.assertRaises(ids.AllowError, msg=body):
                ids.Allow.load(self.af(body))

    def test_documentation_private_range_waiver_needs_a_reason(self):
        t = self.w("a.md", "lab at 192.168.50.7\n")
        ok = self.af("192.168.50.0/24 | documentation private range\n")
        code, out, _ = run(t, "--allow", ok)
        self.assertEqual(code, 0, out)
        self.assertEqual(run(t)[0], 1)
        for body in (
            "192.168.50.0/24\n",
            "192.168.50.0/24 |\n",
            "192.168.50.0/24 |   \n",
            "192.168.50.0/24 | docs\n",
            "a.md | 192.168.50.0/24 |\n",
        ):
            code, out, err = run(t, "--allow", self.af(body))
            self.assertEqual(code, 2, body)
            self.assertNotIn("192.168.50.7", out + err)

    def test_reasonless_entry_wins_over_findings_and_clean(self):
        clean = self.w("c.md", "nothing here\n")
        self.assertEqual(run(clean, "--allow", self.af("10.0.0.0/8\n"))[0], 2)

    def test_cli_refuses_bad_allow(self):
        t = self.w("a.md", "10.1.1.1\n")
        al = self.af("10.1.1.1\n")
        code, out, err = run(t, "--allow", al)
        self.assertEqual(code, 2)
        self.assertNotIn("10.1.1.1", out + err)

    def test_missing_allow_file(self):
        code, _, _ = run(self.w("a.md", "ok\n"), "--allow", os.path.join(self.d, "nope"))
        self.assertEqual(code, 2)


class TestCLI(Tmp):
    def test_clean_exit0(self):
        p = self.w("a.md", "# hi\nnothing here 203.0.113.9\n")
        code, out, err = run(p)
        self.assertEqual(code, 0, out + err)

    def test_findings_exit1_format(self):
        p = self.w("a.md", "ok\nip 192.168.77.41\n")
        code, out, _ = run(p)
        self.assertEqual(code, 1)
        self.assertIn(p + ":2:private-ip", out)
        self.assertIn("192.168.x.x", out)

    def test_json(self):
        p = self.w("a.md", "ip 192.168.77.41\n")
        code, out, _ = run(p, "--format", "json")
        self.assertEqual(code, 1)
        j = json.loads(out)
        self.assertEqual(j["exit"], 1)
        self.assertEqual(j["findings"][0]["class"], "private-ip")
        self.assertEqual(j["findings"][0]["line"], 1)
        self.assertEqual(j["findings"][0]["file"], p)

    def test_dir_only_md_by_default(self):
        self.w("a.md", "10.1.1.1\n")
        self.w("sub/b.txt", "10.2.2.2\n")
        self.w(".git/c.md", "10.3.3.3\n")
        code, out, _ = run(self.d)
        self.assertEqual(code, 1)
        self.assertIn("a.md:1", out)
        self.assertNotIn("b.txt", out)
        self.assertNotIn(".git", out)
        code, out, _ = run(self.d, "--all")
        self.assertIn("b.txt:1", out)
        self.assertNotIn(".git", out)

    def test_explicit_file_any_ext(self):
        p = self.w("x.txt", "10.2.2.2\n")
        self.assertEqual(run(p)[0], 1)

    def test_crlf_line_numbers(self):
        p = self.w("a.md", "one\r\ntwo\r\nip 10.1.1.1\r\nfour\r\n")
        self.assertIn(":3:private-ip", run(p)[1])

    def test_bom(self):
        p = self.w("a.md", b"\xef\xbb\xbfip 10.1.1.1\n")
        self.assertIn(":1:private-ip", run(p)[1])

    def test_missing_file_exit2(self):
        self.assertEqual(run(os.path.join(self.d, "nope.md"))[0], 2)

    def test_no_args_exit2(self):
        self.assertEqual(run()[0], 2)

    def test_empty_dir_clean(self):
        self.assertEqual(run(self.d)[0], 0)


class TestHostile(Tmp):
    def test_symlink_file_refused(self):
        real = self.w("real.md", "10.1.1.1\n")
        link = os.path.join(self.d, "link.md")
        os.symlink(real, link)
        code, out, err = run(link)
        self.assertEqual(code, 2)
        self.assertIn("symlink", err + out)
        self.assertNotIn("private-ip", out)

    def test_symlink_in_dir_refused(self):
        sub = os.path.join(self.d, "docs")
        os.makedirs(sub)
        outside = tempfile.mkdtemp()
        try:
            with open(os.path.join(outside, "o.md"), "w") as fh:
                fh.write("10.1.1.1\n")
            os.symlink(os.path.join(outside, "o.md"), os.path.join(sub, "l.md"))
            os.symlink(outside, os.path.join(sub, "ld"))
            code, out, err = run(sub)
            self.assertEqual(code, 2)
            self.assertNotIn("private-ip", out)
            self.assertGreaterEqual((out + err).count("symlink"), 2)
        finally:
            for r, _ds, fs in os.walk(outside):
                for f in fs:
                    os.unlink(os.path.join(r, f))
            os.rmdir(outside)

    def test_fifo_refused_no_hang(self):
        fifo = os.path.join(self.d, "p.md")
        os.mkfifo(fifo)
        code, out, err = run(fifo, timeout=10)
        self.assertEqual(code, 2)

    def test_size_cap(self):
        p = self.w("big.md", "a" * 5000 + "\n10.1.1.1\n")
        code, out, err = run(p, "--max-bytes", "1000")
        self.assertEqual(code, 2)
        self.assertNotIn("private-ip", out)
        self.assertEqual(run(p)[0], 1)

    def test_non_utf8_exit2_others_still_scanned(self):
        bad = self.w("bad.md", b"caf\xe9 \xff\xfe 10.5.5.5\n")
        good = self.w("good.md", "ip 10.1.1.1\n")
        code, out, err = run(bad, good)
        self.assertEqual(code, 2)
        self.assertIn("good.md:1:private-ip", out)
        self.assertIn("bad.md", out + err)
        self.assertNotIn("10.5.5.5", out + err)
        self.assertNotIn("\\xe9", out + err)
        self.assertNotIn("0xe9", out + err)
        self.assertNotIn("0xff", out + err)

    def test_nul_byte_exit2(self):
        p = self.w("n.md", b"abc\x00def 10.1.1.1\n")
        self.assertEqual(run(p)[0], 2)

    def test_directory_arg_unreadable_ok(self):
        # a file that exists but is unreadable
        p = self.w("u.md", "10.1.1.1\n")
        os.chmod(p, 0)
        try:
            if os.access(p, os.R_OK):
                self.skipTest("running as a user that ignores modes")
            self.assertEqual(run(p)[0], 2)
        finally:
            os.chmod(p, 0o600)

    def test_linear_time(self):
        n = 400_000
        hostile = [
            "a" * n,
            "1." * (n // 2),
            "a." * (n // 2),
            "a@" * (n // 2),
            "a" * n + "@",
            ":" * n,
            "fe80:" * (n // 5),
            "-----BEGIN " * (n // 11),
            "key " * (n // 4),
            "key" + "a" * n,
            "token=" + "a" * n,
            "Bearer " + "a" * n,
            "eyJ" * (n // 3),
            "eyJaaaaa." * (n // 9),
            "0123456789abcdef-" * (n // 17),
            "a-" * (n // 2) + ".lan",
            "callsign " + "A1B" * (n // 3),
            "x" * n + ".local",
            "10." * (n // 3),
            "AA:" * (n // 3),
            "(" * n,
            "<" * n,
            "<a" * (n // 2),
        ]
        for h in hostile:
            t0 = time.monotonic()
            ids.scan_text(h, ids.Allow())
            dt = time.monotonic() - t0
            self.assertLess(dt, 3.0, f"slow on {h[:20]!r}... ({dt:.1f}s)")

    def test_hostile_200kb_lines_under_one_second(self):
        n = 200_000
        hostile = {
            "hyphens": "a-" * (n // 2),
            "dots": "a." * (n // 2),
            "digits and dots": ("1234567890." * (n // 11 + 1))[:n],
            "dots then tld": "a." * (n // 2 - 2) + "lan",
            "hyphens then tld": "a-" * (n // 2 - 2) + ".lan",
            "spaced labels": "a.b " * (n // 4),
        }
        for name, h in hostile.items():
            self.assertGreaterEqual(len(h), n - 12, name)
            t0 = time.monotonic()
            ids.scan_text(h, ids.Allow())
            dt = time.monotonic() - t0
            self.assertLess(dt, 1.0, f"{name} took {dt:.2f}s")

    def test_timing_guard_bites(self):
        # negative control: the old nested-quantifier pattern with its start guard
        # removed is quadratic on this input, so a time budget of this size sees it.
        import re

        bad = re.compile(r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:lan|local)(?![\w-])")
        t0 = time.monotonic()
        bad.search("a." * 8000 + "x")
        self.assertGreater(time.monotonic() - t0, 0.05)

    def test_many_lines(self):
        t0 = time.monotonic()
        ids.scan_text("plain line without anything\n" * 50000, ids.Allow())
        self.assertLess(time.monotonic() - t0, 5.0)


class TestRedaction(Tmp):
    """A matched value must never appear in stdout, stderr or JSON."""

    def values(self):
        return {
            "private-ip": "192.168.77.41",
            "cgnat-ip": "100.64.12.34",
            "public-ip": "45.33.32.156",
            "ipv6-local": "fd12:3456:789a::beef",
            "mac": "3c:52:82:aa:10:5b",
            "email": "bob.smith@corp-mail.io",
            "internal-host": "secretbox17.lan",
            "callsign": "W1ZQX",
            "grid": "EM73ab",
            "webhook": "https://discord.com/api/webhooks/1234567890123456/" + "AbC" * 12,
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpM",
            "pem": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "auth-header": "Zx81kLmQ92pTrv0aBc",
            "secret-token": "k3J9xQ2mZ7vL0pR4tY8wB1nC6dF5gH",
            "cloud-id": "493017265804",
        }

    def lines(self):
        v = self.values()
        return [
            "ip " + v["private-ip"],
            "ip " + v["cgnat-ip"],
            "ip " + v["public-ip"],
            "v6 " + v["ipv6-local"],
            "mac " + v["mac"],
            "mail " + v["email"],
            "host " + v["internal-host"],
            "callsign " + v["callsign"],
            "grid square " + v["grid"],
            v["webhook"],
            v["jwt"],
            v["pem"],
            "Authorization: Bearer " + v["auth-header"],
            "api_key = " + v["secret-token"],
            "AWS account id: " + v["cloud-id"],
        ]

    def fragments(self):
        out = []
        for v in self.values().values():
            out.append(v)
        out += [
            "77.41",
            "12.34",
            "32.156",
            "789a",
            "beef",
            "aa:10",
            "smith",
            "corp-mail",
            "secretbox17",
            "ZQX",
            "W1ZQX",
            "73ab",
            "1234567890123456",
            "AbCAbC",
            "SflKxw",
            "OPENSSH",
            "Zx81kL",
            "k3J9xQ",
            "7265804",
            "493017",
        ]
        return out

    def test_all_classes_detected(self):
        p = self.w("a.md", "\n".join(self.lines()) + "\n")
        code, out, _ = run(p, "--format", "json")
        self.assertEqual(code, 1)
        found = {f["class"] for f in json.loads(out)["findings"]}
        self.assertEqual(found, set(self.values()))

    def test_no_value_in_output(self):
        p = self.w("a.md", "\n".join(self.lines()) + "\n")
        for fmt in ("text", "json"):
            code, out, err = run(p, "--format", fmt)
            blob = out + err
            for frag in self.fragments():
                self.assertNotIn(frag, blob, fmt)
            self.assertNotIn(frag.lower(), blob.lower())

    def test_no_value_in_output_with_errors(self):
        p = self.w("a.md", "\n".join(self.lines()) + "\n")
        bad = self.w("bad.md", b"\xff\xfe" + "\n".join(self.lines()).encode())
        big = self.w("big.md", "\n".join(self.lines()) * 50)
        os.symlink(p, os.path.join(self.d, "ln.md"))
        for fmt in ("text", "json"):
            code, out, err = run(p, bad, big, os.path.join(self.d, "ln.md"), "--max-bytes", "4000", "--format", fmt)
            self.assertEqual(code, 2)
            blob = out + err
            for frag in self.fragments():
                self.assertNotIn(frag, blob, fmt)

    def test_distinctive_value_absent_from_every_stream(self):
        # built at runtime from fragments so no literal sits in the source
        octs = ("10", "77", "13", "214")
        ip = ".".join(octs)
        host = "zq" + "kv" + "9" + ".lan"
        mail = "".join(("zqk", "v9")) + "@" + "mail-" + "zqkv9" + ".io"
        text = f"ip {ip}\nhost {host}\nmail {mail}\n"
        p = self.w("a.md", text)
        bad_allow = self.w("al.txt", f"{ip} |\n")
        frags = (ip, "77.13", "13.214", host, "zqkv9", mail)
        runs = [
            (p,),
            (p, "--format", "json"),
            (p, "--allow", bad_allow),
            (p, "--allow", bad_allow, "--format", "json"),
            (p, "--max-bytes", "5"),
            (p, "--max-bytes", "5", "--format", "json"),
        ]
        for args in runs:
            code, out, err = run(*args)
            self.assertIn(code, (1, 2), args)
            for frag in frags:
                self.assertNotIn(frag, out, (args, "stdout"))
                self.assertNotIn(frag, err, (args, "stderr"))
        code, out, err = run(p, "--format", "json")
        self.assertEqual(code, 1)
        self.assertEqual({f["class"] for f in json.loads(out)["findings"]}, {"private-ip", "internal-host", "email"})
        self.assertEqual(len(json.loads(out)["findings"]), 3)
        for frag in frags:
            self.assertNotIn(frag, json.dumps(json.loads(out)))

    def test_redaction_guard_bites(self):
        # negative control: the fragment check really does see values if they leak
        self.assertIn("77.41", "leaked 192.168.77.41")

    def test_api_findings_never_carry_value(self):
        for f in ids.scan_text("\n".join(self.lines()), ids.Allow()):
            blob = repr(f) + str(f.shape) + str(f.cls)
            for frag in self.fragments():
                self.assertNotIn(frag, blob)

    def test_filtered_values_do_not_show_in_allow_errors(self):
        p = self.w("a.md", "10.1.1.1\n")
        al = self.w("al.txt", "10.1.1.1 |\nsecretbox17.lan\n")
        code, out, err = run(p, "--allow", al)
        self.assertEqual(code, 2)
        self.assertNotIn("secretbox17", out + err)
        self.assertNotIn("10.1.1.1", out + err)


# ----------------------------------------------------------------- fix round 1
def fnd(text, allow=None, deny=None, path=None):
    return (
        ids.scan_text(text, allow or ids.Allow(), path, deny)
        if deny
        else ids.scan_text(text, allow or ids.Allow(), path)
    )


class TestPublicIPv6(unittest.TestCase):
    def test_public_v6_found(self):
        for a in ("2606:4700:4700::1111", "2001:4860:4860::8888", "2606:4700::1111", "2a00:1450:4001:81b::200e"):
            self.assertEqual(cls_set("resolver " + a), {"ipv6-public"}, a)

    def test_mapped_hex_is_ipv4(self):
        self.assertEqual(cls_set("peer ::ffff:a17:2d43"), {"private-ip"})
        self.assertEqual(cls_set("peer ::ffff:2d21:209c"), {"public-ip"})
        self.assertEqual(cls_set("peer ::ffff:cb00:7107"), set())  # 203.0.113.7

    def test_documentation_and_special_not_found(self):
        for a in ("2001:db8::1", "2001:db8:ffff::9", "::", "::1"):
            self.assertEqual(cls_set("x " + a), set(), a)


class TestNormalization(unittest.TestCase):
    def test_encodings_of_a_private_address(self):
        ip = "10.23.45.67"
        forms = [
            "10%2e23%2e45%2e67",
            "10&#46;23&#46;45&#46;67",
            "10&period;23&period;45&period;67",
            "10\u200b.23\u200c.45\u200d.67\u2060\ufeff",
            "\uff11\uff10\uff0e\uff12\uff13\uff0e\uff14\uff15\uff0e\uff16\uff17",
            "10.23.**45**.67",
            "10.__23__.`45`.67",
            "10.23.*45*.67",
        ]
        for f in forms:
            self.assertEqual(cls_set("host " + f), {"private-ip"}, f)
        self.assertEqual(cls_set("host " + ip), {"private-ip"})

    def test_single_integer_hex_and_octal_forms(self):
        self.assertEqual(cls_set("host 3232235777"), {"private-ip"})  # 192.168.1.1
        self.assertEqual(cls_set("host 0xC0A80101"), {"private-ip"})
        self.assertEqual(cls_set("host 0xc0.0xa8.0x01.0x01"), {"private-ip"})
        self.assertEqual(cls_set("host 0300.0250.01.01"), {"private-ip"})
        self.assertEqual(cls_set("host 0xc0a80101."), {"private-ip"})
        self.assertEqual(cls_set("host 0x2d21209c"), {"public-ip"})
        self.assertEqual(cls_set("ip address 755437724"), {"public-ip"})  # public, with an address word before it

    def test_ordinary_numbers_are_not_addresses(self):
        for t in (
            "ts 1700000000",
            "total 123456789",
            "id 4294967295",
            "size 0x7fffffff bytes",
            "code 0xdeadbeef01",
            "n 3405803777 (doc)",
            "color 0xFF00FF",
            "x 3221225985",  # 192.0.2.1 documentation
            "year 2024 and 12345678",
            "ver 0.1.2.3",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_partial_run_split_across_lines(self):
        self.assertEqual(classes("ssh to 10.23.\n45.67 now"), [(1, "private-ip")])
        self.assertEqual(classes("see 192.168.\n  7.8\n"), [(1, "private-ip")])
        self.assertEqual(classes("ssh to 10.23.\n45.67.89 now"), [])
        self.assertEqual(classes("Section 1.2.\n3.4 continues"), [])
        self.assertEqual(classes("v 10.23.\nhello"), [])

    def test_normalization_keeps_line_numbers(self):
        self.assertEqual(classes("a\nb\nip 10%2e1%2e1%2e1\n"), [(3, "private-ip")])


class TestFilenames(Tmp):
    def test_hostile_name_never_printed(self):
        ip = ".".join(("10", "77", "13", "214"))
        mail = "zqkv9" + "@" + "corp-mail." + "io"
        fake = "identscan: files=0 findings=0 errors=0 exit=0"
        name = "a\n" + fake + "\r\x1b[2J " + ip + " " + mail + ".md"
        p = self.w("sub/" + name, "ip " + ip + "\n")
        for fmt in ("text", "json"):
            code, out, err = run(self.d, "--all", "--format", fmt)
            blob = out + err
            self.assertEqual(code, 1)
            for frag in (ip, mail, "zqkv9", "\x1b", "\r", "77.13.214"):
                self.assertNotIn(frag, blob, fmt)
            if fmt == "text":
                self.assertEqual(out.count("identscan: files="), 1, out)
                self.assertEqual(sum(1 for x in out.splitlines() if x.startswith("identscan: files=0")), 0)
                self.assertTrue(all(len(x.splitlines()) == 1 for x in out.splitlines()))
                self.assertIn(":1:private-ip", out)
            else:
                j = json.loads(out)
                self.assertEqual(len(j["findings"]), 1)
                self.assertEqual(j["findings"][0]["class"], "private-ip")
                self.assertNotIn("\n", j["findings"][0]["file"])
        self.assertTrue(os.path.exists(p))

    def test_plain_path_printed_as_is(self):
        p = self.w("docs/page.md", "ip 10.1.1.1\n")
        self.assertIn(p + ":1:private-ip", run(p)[1])

    def test_error_lines_are_sanitized_too(self):
        bad = self.w("b\nfake: error: x\x1b[0m.md", b"\xff\xfe")
        code, out, err = run(bad)
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", out + err)
        self.assertEqual(len(err.splitlines()), 1)


class TestEmailMacRound1(unittest.TestCase):
    def test_quoted_local_part(self):
        self.assertEqual(cls_set('mail "bob smith"@corp-mail.io now'), {"email"})

    def test_punycode_tld(self):
        self.assertEqual(cls_set("mail bob@corp-mail.xn--p1ai"), {"email"})

    def test_git_user_no_blanket_exemption(self):
        self.assertEqual(cls_set("clone git@build-box.io:team/repo.git"), {"email"})
        for t in ("git@github.com:o/r.git", "git@gitlab.com:o/r.git", "git@bitbucket.org:o/r.git"):
            self.assertEqual(cls_set(t), set(), t)

    def test_git_user_waived_with_reason(self):
        a = ids.Allow()
        a.strs.append((None, "git@build-box.io"))
        self.assertEqual(cls_set("git@build-box.io:o/r.git", a), set())

    def test_mac_dotted_quad(self):
        self.assertEqual(cls_set("nic 3c52.82aa.105b"), {"mac"})
        self.assertEqual(cls_set("nic 3C52.82AA.105B up"), {"mac"})
        self.assertEqual(cls_set("date 2024.1231.1200"), set())

    def test_mac_bare_with_context(self):
        self.assertEqual(cls_set("mac 3c5282aa105b"), {"mac"})
        self.assertEqual(cls_set("hwaddr=3C5282AA105B"), {"mac"})
        self.assertEqual(cls_set("ether\n3c5282aa105b"), {"mac"})
        self.assertEqual(cls_set("lladdr 123456789012"), {"mac"})

    def test_mac_bare_standalone(self):
        self.assertEqual(cls_set("device 3c5282aa105b ready"), {"mac"})

    def test_mac_false_positives(self):
        for t in (
            "count 123456789012",  # 12-digit number, no context
            "serial 123456789012 shipped",
            "commit 3c5282aa105b fixes it",  # git short sha context
            "sha 3c5282aa105b",
            "word abcdefabcdef.",  # letters only
            "id 3c5282aa105b5",  # longer token
            "3c5282aa105",  # shorter token
            "macOS 123456789012",
        ):
            self.assertEqual(cls_set(t), set(), t)


class TestRadioRound1(unittest.TestCase):
    def test_case_insensitive_identifier(self):
        self.assertEqual(cls_set("callsign w1zqx"), {"callsign"})
        self.assertEqual(cls_set("callsign W1zqx"), {"callsign"})

    def test_digit_first_prefixes(self):
        self.assertEqual(cls_set("callsign 3DA0ABC"), {"callsign"})
        self.assertEqual(cls_set("my ham call 2E0ABC"), {"callsign"})
        self.assertEqual(cls_set("callsign 9a1abc"), {"callsign"})

    def test_context_on_previous_line(self):
        self.assertEqual(classes("My callsign is:\nW1ZQX"), [(2, "callsign")])
        self.assertEqual(classes("Grid square:\nEM73ab"), [(2, "grid")])
        self.assertEqual(classes("callsign\n\nW1ZQX"), [])  # two lines back is out of range

    def test_grid_either_case(self):
        for g in ("EM73AB", "EM73ab", "em73ab", "em73AB", "EM73"):
            self.assertEqual(cls_set("grid " + g), {"grid"}, g)

    def test_placeholders_stay_clean(self):
        for t in ("callsign N0CALL", "callsign n0call", "ham N0TST", "grid FN31pr", "grid fn31PR", "grid FN31"):
            self.assertEqual(cls_set(t), set(), t)

    def test_no_bare_callsign(self):
        self.assertEqual(cls_set("the W1ZQX station"), set())


class TestDeny(Tmp):
    def df(self, body):
        return self.w("deny.txt", body)

    def test_hit_reports_deny_class_only(self):
        secret = "zq" + "kv" + "9" + "ab"
        d = ids.Deny.load(self.df("# comment\n\n" + secret + "\nr[a-z]{3}\\d\n"))
        f = ids.scan_text("one\nthe " + secret.upper() + " here\nrabc7", ids.Allow(), None, d)
        self.assertEqual([(x.line, x.cls) for x in f], [(2, "deny"), (3, "deny")])

    def test_cli_never_prints_pattern_or_match(self):
        secret = "zq" + "kv" + "9" + "ab"
        pat = "xx" + secret + "[0-9]+"
        match = "xx" + secret + "4417"
        t = self.w("a.md", "line one\nuse " + match + " ok\n")
        d = self.df(pat + "\n")
        for fmt in ("text", "json"):
            code, out, err = run(t, "--deny-file", d, "--format", fmt)
            self.assertEqual(code, 1)
            for frag in (secret, "4417", "[0-9]", pat, match):
                self.assertNotIn(frag, out + err, fmt)
            if fmt == "text":
                self.assertIn(t + ":2:deny", out)
            else:
                self.assertEqual(json.loads(out)["findings"][0]["class"], "deny")

    def test_literal_when_not_a_regex(self):
        d = ids.Deny.load(self.df("a(b\n"))
        self.assertEqual(len(ids.scan_text("xx a(b yy", ids.Allow(), None, d)), 1)

    def test_empty_matching_pattern_refused(self):
        code, out, err = run(self.w("a.md", "hello world\n"), "--deny-file", self.df("a*\n"))
        self.assertEqual(code, 2)
        self.assertNotIn("a*", out + err)

    def test_deny_file_hardening(self):
        t = self.w("a.md", "hello world\n")
        self.assertEqual(run(t, "--deny-file", os.path.join(self.d, "nope"))[0], 2)
        self.assertEqual(run(t, "--deny-file", self.d)[0], 2)
        fifo = os.path.join(self.d, "f")
        os.mkfifo(fifo)
        self.assertEqual(run(t, "--deny-file", fifo, timeout=10)[0], 2)
        self.assertEqual(run(t, "--deny-file", self.w("bad.txt", b"\xff\xfe\n"))[0], 2)
        big = self.w("big.txt", "#" * (ids.CONFIG_MAX_BYTES + 1))
        self.assertEqual(run(t, "--deny-file", big)[0], 2)

    def test_deny_in_filename_is_redacted(self):
        secret = "zq" + "kv" + "9" + "ab"
        t = self.w("dir/" + secret + ".md", "x " + secret + " y\n")
        code, out, err = run(t, "--deny-file", self.df(secret + "\n"))
        self.assertEqual(code, 1)
        self.assertNotIn(secret, out + err)


class TestPathWaivers(unittest.TestCase):
    def a(self, entry):
        al = ids.Allow()
        al.nets.append((entry, ids.ipaddress.ip_network("10.9.9.9/32")))
        return al

    def test_exact_path_only(self):
        a = self.a("docs/a.md")
        n = lambda path: len(ids.scan_text("ip 10.9.9.9", a, path))  # noqa: E731
        self.assertEqual(n("docs/a.md"), 0)
        self.assertEqual(n("./docs/a.md"), 0)
        self.assertEqual(n("archive/docs/a.md"), 1)
        self.assertEqual(n("unrelated/docs/a.md"), 1)
        self.assertEqual(n("docs/a.md.bak"), 1)
        self.assertEqual(n("xdocs/a.md"), 1)

    def test_explicit_globs(self):
        a = self.a("docs/*.md")
        self.assertEqual(len(ids.scan_text("ip 10.9.9.9", a, "docs/a.md")), 0)
        self.assertEqual(len(ids.scan_text("ip 10.9.9.9", a, "other/docs/a.md")), 1)
        b = self.a("**/docs/a.md")
        self.assertEqual(len(ids.scan_text("ip 10.9.9.9", b, "x/y/docs/a.md")), 0)

    def test_cli_waiver_is_relative_to_cwd(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "docs"))
            os.makedirs(os.path.join(d, "archive", "docs"))
            for sub in ("docs", "archive/docs"):
                with open(os.path.join(d, sub, "a.md"), "w") as fh:
                    fh.write("ip 10.9.9.9\n")
            with open(os.path.join(d, "allow.txt"), "w") as fh:
                fh.write("docs/a.md | 10.9.9.9 | sample in a.md only\n")
            p = subprocess.run(
                [sys.executable, "-I", TOOL, "docs", "archive", "--allow", "allow.txt"],
                capture_output=True,
                cwd=d,
            )
            out = p.stdout.decode()
            self.assertEqual(p.returncode, 1)
            self.assertIn("archive/docs/a.md:1:private-ip", out)
            self.assertNotIn("\ndocs/a.md:1", "\n" + out)


class TestConfigFileLoading(Tmp):
    def test_fifo_refused_no_hang(self):
        t = self.w("a.md", "hello world\n")
        fifo = os.path.join(self.d, "al")
        os.mkfifo(fifo)
        self.assertEqual(run(t, "--allow", fifo, timeout=10)[0], 2)

    def test_directory_refused(self):
        self.assertEqual(run(self.w("a.md", "hello world\n"), "--allow", self.d)[0], 2)

    def test_device_refused(self):
        if not os.path.exists("/dev/null"):
            self.skipTest("no /dev/null")
        self.assertEqual(run(self.w("a.md", "hello world\n"), "--allow", "/dev/null")[0], 2)

    def test_over_cap_is_exit_2_not_truncated(self):
        # a reasonless entry sits just past the cap; truncation would hide it
        pad = "#" * (ids.CONFIG_MAX_BYTES - 1) + "\n"
        body = pad + "10.1.1.1\n"
        self.assertGreater(len(body), ids.CONFIG_MAX_BYTES)
        t = self.w("a.md", "ip 10.1.1.1\n")
        code, out, err = run(t, "--allow", self.w("big.txt", body))
        self.assertEqual(code, 2)
        self.assertNotIn("10.1.1.1", out + err)

    def test_exactly_at_cap_is_read(self):
        body = ("#" * (ids.CONFIG_MAX_BYTES - 1)) + "\n"
        self.assertEqual(len(body), ids.CONFIG_MAX_BYTES)
        self.assertEqual(run(self.w("a.md", "hello world\n"), "--allow", self.w("ok.txt", body))[0], 0)

    def test_non_utf8_allow_file(self):
        self.assertEqual(run(self.w("a.md", "hello world\n"), "--allow", self.w("b.txt", b"\xff\xfe\n"))[0], 2)


class TestRound1Timing(unittest.TestCase):
    def test_new_patterns_are_linear(self):
        n = 200_000
        d = ids.Deny()
        d.pats.append(ids.re.compile("zz[0-9]+", ids.re.I))
        hostile = {
            "percent": "%2e" * (n // 3),
            "entities": "&#46;" * (n // 5),
            "zero width": "1\u200b" * (n // 2),
            "fullwidth": "\uff11\uff0e" * (n // 2),
            "emphasis": "1.*" * (n // 3),
            "hex dots": "0x1." * (n // 4),
            "octal dots": "01." * (n // 3),
            "callsign run": "cq " + "1a" * (n // 2),
            "mac run": "mac " + "ab12ab12ab12 " * (n // 13),
            "quotes": '"a@' * (n // 3),
            "split dotted": "1." * (n // 2) + "\n" + "1." * (n // 2),
        }
        for name, h in hostile.items():
            t0 = time.monotonic()
            ids.scan_text(h, ids.Allow(), None, d)
            dt = time.monotonic() - t0
            self.assertLess(dt, 1.0, f"{name} took {dt:.2f}s")
