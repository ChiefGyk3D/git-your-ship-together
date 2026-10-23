"""identscan is a gate on public wiki pages; this is the check on it.

Fixtures are synthetic: documentation ranges, example.com, and values assembled at
runtime. The redaction tests assert that no matched value reaches stdout, stderr or
the JSON report; the timing tests feed it 200 KB hostile lines.
"""

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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
                self.assertNotIn(frag.lower(), blob.lower(), fmt)

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
        # negative control through the real pipeline: if the report did carry a value, the
        # fragment check used by the tests above would see it.
        p = self.w("a.md", "ip " + self.values()["private-ip"] + "\n")
        leaky = {"private-192": "192.168.x.x " + self.values()["private-ip"]}
        for fmt in ("text", "json"):
            buf = io.StringIO()
            with mock.patch.dict(ids.SHAPES, leaky), contextlib.redirect_stdout(buf):
                self.assertEqual(ids.main([p, "--format", fmt]), 1)
            self.assertIn("77.41", buf.getvalue(), fmt)
        code, out, err = run(p)
        self.assertNotIn("77.41", out + err)

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
        # five octets once joined: the first four still count (round 2, item 7)
        self.assertEqual(classes("ssh to 10.23.\n45.67.89 now"), [(1, "private-ip")])
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
        line = "#" * 1023 + "\n"
        self.assertEqual(ids.CONFIG_MAX_BYTES % len(line), 0)
        pad = line * (ids.CONFIG_MAX_BYTES // len(line))
        self.assertEqual(len(pad), ids.CONFIG_MAX_BYTES)
        body = pad + "10.1.1.1\n"
        self.assertGreater(len(body), ids.CONFIG_MAX_BYTES)
        t = self.w("a.md", "ip 10.1.1.1\n")
        code, out, err = run(t, "--allow", self.w("big.txt", body))
        self.assertEqual(code, 2)
        self.assertIn("exceeds size cap", err)
        self.assertNotIn("10.1.1.1", out + err)

    def test_exactly_at_cap_is_read(self):
        line = "#" * 1023 + "\n"  # a line is capped at 4096 characters, so build the file from short ones
        self.assertEqual(ids.CONFIG_MAX_BYTES % len(line), 0)
        body = line * (ids.CONFIG_MAX_BYTES // len(line))
        self.assertEqual(len(body), ids.CONFIG_MAX_BYTES)
        self.assertEqual(run(self.w("a.md", "hello world\n"), "--allow", self.w("ok.txt", body))[0], 0)

    def test_non_utf8_allow_file(self):
        self.assertEqual(run(self.w("a.md", "hello world\n"), "--allow", self.w("b.txt", b"\xff\xfe\n"))[0], 2)


class TestTiming(Tmp):
    """Hostile input runs in a subprocess under a hard timeout, so a regression fails fast
    instead of hanging CI.  The budget is generous (5 s for 200 KB that takes about 0.05 s)."""

    BUDGET = 5

    def finishes(self, argv, timeout):
        try:
            subprocess.run(argv, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        return True

    def assert_fast(self, name, text, *extra):
        p = self.w("hostile.md", text)
        self.assertTrue(
            self.finishes([sys.executable, "-I", TOOL, p, *extra], self.BUDGET),
            f"{name}: no answer within {self.BUDGET}s",
        )

    def test_timeout_helper_bites(self):
        # negative control: the helper really reports a process that does not finish
        self.assertFalse(self.finishes([sys.executable, "-c", "import time; time.sleep(30)"], 1))
        self.assertTrue(self.finishes([sys.executable, "-c", "pass"], 30))

    def test_hostile_lines(self):
        n = 200_000
        hostile = {
            "hyphens": "a-" * (n // 2),
            "dots": "a." * (n // 2),
            "digits and dots": ("1234567890." * (n // 11 + 1))[:n],
            "dots then tld": "a." * (n // 2 - 2) + "lan",
            "hyphens then tld": "a-" * (n // 2 - 2) + ".lan",
            "spaced labels": "a.b " * (n // 4),
            "at": "a@" * (n // 2),
            "colons": ":" * n,
            "v6": "fe80:" * (n // 5),
            "pem": "-----BEGIN " * (n // 11),
            "key words": "key " * (n // 4),
            "token run": "token=" + "a" * n,
            "bearer run": "Bearer " + "a" * n,
            "jwt": "eyJaaaaa." * (n // 9),
            "callsign": "callsign " + "A1B" * (n // 3),
            "mac": "AA:" * (n // 3),
            "angle": "<a" * (n // 2),
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
            "long octets": "10.1.2.3." * (n // 9),
        }
        for name, h in hostile.items():
            self.assertGreaterEqual(len(h), n - 40, name)
            self.assert_fast(name, h)

    def test_hostile_with_deny_file(self):
        d = self.w("deny.txt", "zz[0-9]+\n")
        self.assert_fast("deny", "zz1 " * 50_000, "--deny-file", d)

    def test_many_lines(self):
        self.assert_fast("many lines", "plain line without anything\n" * 50000)


class TestRound2(Tmp):
    FAKE = "identscan: files=1 findings=0 errors=0 exit=0"

    def test_forged_summary_in_a_file_name(self):
        p = self.w("clean\n" + self.FAKE + "\nx.md", "ip 192.168.9.9\n")
        code, out, err = run(p)
        self.assertEqual(code, 1)
        self.assertEqual(sum(1 for x in out.splitlines() if x.startswith("identscan: files=")), 1)
        self.assertNotIn(self.FAKE, out + err)
        self.assertNotIn("findings=0", out + err)

    def test_escape_sequence_in_a_file_name(self):
        p = self.w("a\x1b[2Jb.md", "ip 192.168.9.9\n")
        bad = self.w("c\x1b[2Jd\n" + self.FAKE + ".md", b"\xff\xfe")
        code, out, err = run(p, bad)
        self.assertEqual(code, 2)
        self.assertNotIn("\x1b", out + err)
        self.assertNotIn(self.FAKE, out + err)
        self.assertEqual(len(err.splitlines()), 1)

    def test_non_utf8_file_name(self):
        raw = os.fsencode(self.d) + b"/bad\xff.md"
        with open(raw, "wb") as fh:
            fh.write(b"ip 192.168.9.9\n")
        for env_extra in ({"LC_ALL": "C"}, {"LC_ALL": "C.UTF-8"}, {"PYTHONUTF8": "1"}):
            env = dict(os.environ, **env_extra)
            p = subprocess.run([sys.executable, "-I", TOOL, raw], capture_output=True, env=env)
            self.assertEqual(p.returncode, 1, (env_extra, p.stderr))
            self.assertNotIn(b"Traceback", p.stderr)
            self.assertIn(b"identscan: files=1 findings=1", p.stdout)
            p = subprocess.run([sys.executable, "-I", TOOL, raw, "--format", "json"], capture_output=True, env=env)
            self.assertEqual(json.loads(p.stdout)["files_scanned"], 1)
        # an unreadable non-UTF-8 name goes through the error line
        bad = os.fsencode(self.d) + b"/worse\xfe.md"
        with open(bad, "wb") as fh:
            fh.write(b"\xff\xfe\x00")
        p = subprocess.run([sys.executable, "-I", TOOL, bad], capture_output=True, env=dict(os.environ, LC_ALL="C"))
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b"Traceback", p.stderr)
        self.assertIn(b"identscan: files=1", p.stdout)

    def test_negative_max_bytes_is_exit_2(self):
        p = self.w("a.md", "ip 192.168.9.9\n")
        for v in ("-5", "abc"):
            code, out, err = run(p, "--max-bytes", v)
            self.assertEqual(code, 2, v)
            self.assertNotIn("Traceback", out + err)
            self.assertNotIn("192.168", out + err)
            self.assertIn("non-negative", err, v)

    def test_unexpected_exception_is_exit_2_without_content(self):
        p = self.w("a.md", "ip 192.168.9.9\n")
        out, err = io.StringIO(), io.StringIO()
        boom = RuntimeError("secret " + "192.168.9.9")
        with (
            mock.patch.object(ids, "run", side_effect=boom),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = ids.main([p])
        self.assertEqual(code, 2)
        blob = out.getvalue() + err.getvalue()
        self.assertNotIn("192.168", blob)
        self.assertNotIn("Traceback", blob)
        self.assertNotIn("secret", blob)
        self.assertIn("cannot tell", blob)

    def test_eui64_and_cisco_mac(self):
        for t in ("nic 3c:52:82:ff:fe:aa:10:5b", "nic 3C-52-82-FF-FE-AA-10-5B", "nic aabb.cc11.2233"):
            self.assertEqual(cls_set(t), {"mac"}, t)
        self.assertEqual(cls_set("nic 3c:52:82:ff:fe:aa:10:5b:99"), set())

    def test_allow_reason_may_contain_pipes(self):
        a = ids.Allow.load(self.w("al.txt", "docs/a.md | 10.9.9.9 | sample | with | pipes in the reason\n"))
        self.assertEqual(len(ids.scan_text("ip 10.9.9.9", a, "docs/a.md")), 0)
        self.assertEqual(len(ids.scan_text("ip 10.9.9.9", a, "docs/b.md")), 1)

    def test_allow_long_line_says_so(self):
        al = self.w("al.txt", "x" * 10_000 + "\n")
        code, out, err = run(self.w("a.md", "hello world\n"), "--allow", al)
        self.assertEqual(code, 2)
        self.assertIn("line too long", err)
        self.assertNotIn("reason is mandatory", err)

    def test_allow_fifo_does_not_hang(self):
        fifo = os.path.join(self.d, "al.fifo")
        os.mkfifo(fifo)
        self.assertEqual(run(self.w("a.md", "hello world\n"), "--allow", fifo, timeout=10)[0], 2)

    def test_more_internal_suffixes(self):
        for h in ("nas.localdomain", "wiki.intranet", "NAS.LocalDomain."):
            self.assertEqual(cls_set("connect to " + h), {"internal-host"}, h)
        self.assertEqual(cls_set("a.intranets and b.localdomains"), set())

    def test_five_octets_still_flag_the_first_four(self):
        self.assertEqual(cls_set("host 10.1.2.3.4"), {"private-ip"})
        self.assertEqual(cls_set("host 192.168.1.1.5 and"), {"private-ip"})
        self.assertEqual(cls_set("host 100.64.1.1.9"), {"cgnat-ip"})
        for t in ("version 1.2.3.4.5", "oid 1.3.6.1.4.1", "x 203.0.113.9.1"):
            self.assertEqual(cls_set(t), set(), t)

    def test_placeholder_email_is_a_finding_unless_waived(self):
        self.assertEqual(cls_set("mail you@your-domain.com"), {"email"})
        a = ids.Allow()
        a.strs.append((None, "you@your-domain.com"))
        self.assertEqual(cls_set("mail you@your-domain.com", a), set())


class TestRound3(Tmp):
    def test_ip_in_file_name_is_never_printed(self):
        names = ("k/router-10.23.45.67.md", "e/gw-192.168.7.9.md", "e/gw-52.1.2.3.md", "e/10.23.45.67.md")
        for n in names:
            self.w(n, "ip 10.99.88.77\n")
        frags = ("10.23.45.67", "192.168.7.9", "52.1.2.3", "23.45.67", "168.7.9", "1.2.3")
        for fmt in ("text", "json"):
            code, out, err = run(self.d, "--format", fmt)
            self.assertEqual(code, 1)
            self.assertEqual(out.count("private-ip"), 4)
            for frag in frags:
                self.assertNotIn(frag, out + err, (fmt, frag))

    def test_ip_in_error_line_file_name_is_never_printed(self):
        p = self.w("e/gw-52.1.2.3.md", b"\xff\xfe")
        code, out, err = run(p)
        self.assertEqual(code, 2)
        self.assertNotIn("52.1.2.3", out + err)

    def test_any_digit_dot_digit_name_is_redacted(self):
        # even a name the address patterns would not match, such as a version
        p = self.w("docs/release-1.2.md", "ip 10.99.88.77\n")
        out = run(p)[1]
        self.assertNotIn("1.2", out)
        self.assertIn("/<redacted>:1:private-ip", out)

    def test_ordinary_names_still_print(self):
        p = self.w("docs/page-one.md", "ip 10.99.88.77\n")
        self.assertIn(p + ":1:private-ip", run(p)[1])

    # ---- deny file: no catastrophic regex
    def test_regex_safety_check(self):
        for bad in ("(a+)+$", "(a*)*", "(a+)*", "(.*)*", "(a|aa)+", "(a|a)*b", "(a)\\1", "(?P<x>a)(?P=x)", "a*a*a*"):
            self.assertFalse(ids._regex_is_safe(bad), bad)
        for ok in ("W1[A-Z]{3}", "zz[0-9]+", "foo\\d+bar", "r[a-z]{3}\\d", "(ab)c", "(?:ab){2}", "x[+*]y"):
            self.assertTrue(ids._regex_is_safe(ok), ok)

    def test_catastrophic_deny_pattern_finishes(self):
        d = self.w("deny.txt", "(a+)+$\nzzmarker\n")
        p = self.w("a.md", ("a" * 30 + "!\n") + ("aaa!" * 50_000 + "\n") + "zzmarker\n")
        try:
            q = subprocess.run([sys.executable, "-I", TOOL, p, "--deny-file", d], capture_output=True, timeout=5)
        except subprocess.TimeoutExpired:
            self.fail("catastrophic deny pattern hung the scan")
        out, err = q.stdout.decode(), q.stderr.decode()
        self.assertEqual(q.returncode, 1)
        self.assertIn(":3:deny", out)
        self.assertIn("treated as literal", err)
        self.assertNotIn("(a+)", out + err)

    # ---- invisible characters and dot lookalikes
    def test_invisible_characters_are_stripped(self):
        invisibles = ("\u00ad", "\u200e", "\u200f", "\u2061", "\u2062", "\u2063", "\u2064", "\u034f", "\u180e")
        invisibles += ("\u202a", "\u202c", "\u2066", "\u2069", "\u061c", "\u200b", "\ufeff")
        for ch in invisibles:
            self.assertEqual(cls_set("host 10.23.45." + ch + "67"), {"private-ip"}, hex(ord(ch)))
            self.assertEqual(cls_set("host 10" + ch + ".23.45.67"), {"private-ip"}, hex(ord(ch)))
            self.assertEqual(cls_set("host " + ch + "10.23.45.67" + ch), {"private-ip"}, hex(ord(ch)))

    def test_dot_lookalikes_and_defanging(self):
        for f in (
            "10\u300223\u300245\u300267",
            "10\ufe5223\ufe5245\ufe5267",
            "10\uff0e23\uff0e45\uff0e67",
            "10\uff6123\uff6145\uff6167",
            "10[.]23[.]45[.]67",
            "10(.)23(.)45(.)67",
            "10{.}23{.}45{.}67",
            "10[.]23.45(.)67",
        ):
            self.assertEqual(cls_set("host " + f), {"private-ip"}, f)

    def test_defang_is_limited_to_numeric_runs(self):
        for t in ("see a[.]b and [.] here", "list(.)map and x[.]y", "arr[.]length"):
            self.assertEqual(cls_set(t), set(), t)

    # ---- double encoding
    def test_double_encoding(self):
        for f in (
            "10%252e23%252e45%252e67",
            "10&amp;#46;23&amp;#46;45&amp;#46;67",
            "10%26%2346%3B23.45.67",
            "10%25252e23%25252e45%25252e67",
            "10&amp;amp;#46;23.45.67",
        ):
            self.assertEqual(cls_set("host " + f), {"private-ip"}, f)

    def test_zero_width_inside_an_entity(self):
        self.assertEqual(cls_set("host 10&#4\u200b6;23.45.67"), {"private-ip"})
        self.assertEqual(cls_set("host 10%2\u200be23.45.67"), {"private-ip"})
        self.assertEqual(cls_set("host 10&#8203;.23.45.67"), {"private-ip"})

    # ---- IPv6 false positives
    def test_ipv6_lookalikes_are_not_findings(self):
        for t in (
            "::add-mask::secret",
            "::add-path::/x",
            "::error file=a::b",
            "use ::dead;",
            "Beef::cafe",
            "call Cafe::bad()",
            "::set-output name=x::y",
            "::cafe-",
            "word ::beef-x",
        ):
            self.assertEqual(cls_set(t), set(), t)

    def test_ipv6_real_ones_still_found(self):
        self.assertEqual(cls_set("r 2606:4700:4700::1111"), {"ipv6-public"})
        self.assertEqual(cls_set("r 2001:4860:4860::8888"), {"ipv6-public"})
        self.assertEqual(cls_set("r ::ffff:a17:2d43"), {"private-ip"})
        self.assertEqual(cls_set("r fc00::1 and fe80::1"), {"ipv6-local"})
        for t in ("r 2001:db8::1", "r ::", "r ::1", "r ff02::1"):
            self.assertEqual(cls_set(t), set(), t)

    def test_ipv6_followed_by_a_hyphen_is_still_an_address(self):
        # round 4, item 3: a trailing hyphen must not hide a real address (round 3 pinned the opposite)
        self.assertEqual(cls_set("r 2606:4700:4700::1111-x"), {"ipv6-public"})
        self.assertEqual(cls_set("r fc00::1-x"), {"ipv6-local"})

    def test_invisible_table_covers_every_cf_character(self):
        import unicodedata

        missing = [
            hex(c)
            for c in range(sys.maxunicode + 1)
            if unicodedata.category(chr(c)) == "Cf" and not ids._INVISIBLE.fullmatch(chr(c))
        ]
        self.assertEqual(missing, [])
        self.assertTrue(ids._INVISIBLE.fullmatch("\u034f") and ids._INVISIBLE.fullmatch("\u180e"))
        self.assertIsNone(ids._INVISIBLE.fullmatch("a"))


class TestRound4(Tmp):
    def deny_run(self, text, patterns, *extra, timeout=60):
        d = self.w("deny.txt", "\n".join(patterns) + "\n")
        t = self.w("a.md", text)
        q = subprocess.run(
            [sys.executable, "-I", TOOL, t, "--deny-file", d, *extra], capture_output=True, timeout=timeout
        )
        return q.returncode, q.stdout.decode(), q.stderr.decode()

    # ---- long lines are windowed, never skipped
    def test_match_after_a_long_prefix_is_found(self):
        code, out, err = self.deny_run("x" * 1100 + " sneakyword7 tail\n", ["sneakyword[0-9]"])
        self.assertEqual(code, 1, err)
        self.assertIn(":1:deny", out)

    def test_match_straddling_a_window_boundary_is_found(self):
        step = ids.DENY_WINDOW - ids.DENY_OVERLAP
        for edge in (ids.DENY_WINDOW, ids.DENY_WINDOW + step, ids.DENY_WINDOW + 2 * step):
            for off in range(edge - 12, edge + 1, 4):
                text = "x" * off + "sneakyword7" + "y" * 50
                d = ids.Deny.load(self.w("d.txt", "sneakyword[0-9]\n"))
                self.assertEqual(len(ids.scan_text(text, ids.Allow(), None, d)), 1, off)

    def test_a_wide_pattern_is_not_missed_at_a_boundary(self):
        wide = "q" * 250 + "!"
        d = ids.Deny.load(self.w("d.txt", wide + "\n"))
        self.assertTrue(d.pats[0][0] is not None)
        for off in range(ids.DENY_WINDOW - 260, ids.DENY_WINDOW + 5, 7):
            text = "x" * off + wide + "y" * 40
            self.assertEqual(len(ids.scan_text(text, ids.Allow(), None, d)), 1, off)

    # ---- a weakened deny pass is never a clean exit
    def test_reviewer_case_499_regexes_on_a_big_file_is_never_clean(self):
        pats = [f"p{i:04d}[0-9]" for i in range(499)] + ["sneakyword[0-9]"]
        filler = ("lorem ipsum dolor sit amet " * 4)[:100] + "\n"
        text = filler * 105_000 + "SNEAKYWORD2\n"
        self.assertGreater(len(text), 10_500_000)
        t0 = time.monotonic()
        code, out, err = self.deny_run(text, pats, "--max-bytes", "20000000")
        self.assertIn(code, (1, 2), (out[-200:], err))
        self.assertLess(time.monotonic() - t0, ids.DENY_BUDGET_SECONDS + 55)
        if code == 2:
            self.assertIn("deny matching degraded", err)

    def test_catastrophic_pattern_the_check_misses_is_killed(self):
        filler = "plain filler line number one\n" * 400
        d = self.w("deny.txt", "(a?){32}a{32}\n")
        t = self.w("a.md", "a" * 32 + "!\n" + filler)
        out, err = io.StringIO(), io.StringIO()
        t0 = time.monotonic()
        with (
            mock.patch.object(ids, "_regex_is_safe", return_value=True),
            mock.patch.object(ids, "DENY_BUDGET_SECONDS", 1.0),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = ids.main([t, "--deny-file", d])
        dt = time.monotonic() - t0
        self.assertEqual(code, 2, out.getvalue())
        self.assertLess(dt, 2.0)
        self.assertIn("deny matching degraded", err.getvalue())
        self.assertNotIn("(a?)", out.getvalue() + err.getvalue())

    def test_degraded_with_a_finding_is_exit_1_with_the_note(self):
        filler = "plain filler line number one\n" * 400
        d = self.w("deny.txt", "(a?){32}a{32}\nzzmarker\n")
        t = self.w("a.md", "a" * 32 + "!\nzzmarker here\n" + filler)
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(ids, "_regex_is_safe", return_value=True),
            mock.patch.object(ids, "DENY_BUDGET_SECONDS", 1.0),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = ids.main([t, "--deny-file", d])
        self.assertEqual(code, 1)
        self.assertIn(":2:deny", out.getvalue())
        self.assertIn("deny matching degraded", err.getvalue())

    def test_unsafe_entry_is_literal_with_a_note_and_stays_fast(self):
        t0 = time.monotonic()
        code, out, err = self.deny_run(("a" * 32 + "!\n") + "plain filler line\n" * 400, ["(a?){32}a{32}"])
        self.assertLess(time.monotonic() - t0, 5)
        self.assertEqual(code, 0)
        self.assertIn("treated as literal", err)

    def test_degraded_is_per_file_and_reported_in_json(self):
        filler = "plain filler line number one\n" * 400
        d = self.w("deny.txt", "(a?){32}a{32}\n")
        bad = self.w("bad.md", "a" * 32 + "!\n" + filler)
        good = self.w("good.md", "hello world\n" + filler)
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.object(ids, "_regex_is_safe", return_value=True),
            mock.patch.object(ids, "DENY_BUDGET_SECONDS", 1.0),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = ids.main([bad, good, "--deny-file", d, "--format", "json"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["deny_degraded_files"], 1)

    # ---- regex safety, round 4
    def test_more_unsafe_shapes(self):
        for bad in ("(a?){32}a{32}", "(x?){3}", "(ab?){2,5}", "a{1,500}b{1,500}c{1,500}", "(a{2,5}){2,5}", "(a|b){2}"):
            self.assertFalse(ids._regex_is_safe(bad), bad)
        for ok in ("W1[A-Z]{3}", "(?:ab){2}", "(ab){2}", "a{1,5}b{1,5}", "foo[0-9]{1,3}bar", "x?y"):
            self.assertTrue(ids._regex_is_safe(ok), ok)

    # ---- IPv6 after a prefix, and trailing hyphens
    def test_ipv6_after_a_word_and_colon_prefix(self):
        for t in (
            "v=spf1 ip6:2a00:1450:4001:81b::200e -all",
            "addr:2606:4700:4700::1111",
            "ip6=2606:4700:4700::1111",
            "inet6 2606:4700:4700::1111/64",
            "AAAA 2606:4700:4700::1111",
            "dns:2001:4860:4860::8888",
            "ipv6:fd12:3456:789a::1",
        ):
            self.assertIn(cls_set(t), ({"ipv6-public"}, {"ipv6-local"}), t)

    def test_trailing_hyphen_does_not_hide_a_real_address(self):
        for t in ("r 2a00:1450:4001:81b::200e-", "r 2a00:1450:4001:81b::200e-extra", "r 2a00:1450:4001:81b::200e - x"):
            self.assertEqual(cls_set(t), {"ipv6-public"}, t)

    def test_prefixes_do_not_create_false_positives(self):
        for t in ("::add-mask::secret", "::set-output name=x::y", "addr:beef", "ip6:", "key:cafe::bad"):
            self.assertEqual(cls_set(t), set(), t)

    # ---- file names that spell an address with separators
    def test_separator_spelled_names_are_redacted(self):
        names = (
            "a/gw-192-168-7-9.md",
            "b/gw-10_23_45_67.md",
            "c/x-3232235777.md",
            "d/h-2a00-1450-4001-81b--200e.md",
            "e/report-20240115.md",  # accepted false redaction, pinned
        )
        for n in names:
            self.w(n, "ip 10.99.88.77\n")
        frags = ("192-168-7-9", "10_23_45_67", "3232235777", "2a00-1450", "81b--200e", "20240115")
        for fmt in ("text", "json"):
            code, out, err = run(self.d, "--format", fmt)
            self.assertEqual(code, 1)
            self.assertEqual(out.count("private-ip"), 5, out)
            for frag in frags:
                self.assertNotIn(frag, out + err, (fmt, frag))
        for n in names:
            p = self.w("err/" + n.replace("/", "_"), b"\xff\xfe")
            code, out, err = run(p)
            self.assertEqual(code, 2)
            for frag in frags:
                self.assertNotIn(frag, out + err, (n, frag))

    def test_plain_hyphenated_names_still_print(self):
        for n in ("docs/getting-started.md", "docs/page-2-of-3.md", "a/b_c-d.md"):
            p = self.w(n, "ip 10.99.88.77\n")
            self.assertIn(p + ":1:private-ip", run(p)[1], n)
