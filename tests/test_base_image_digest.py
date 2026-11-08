"""scripts/base_image_digest.py: reading the pins out of a Dockerfile, and deciding what a bump would fix.

The Dockerfile and the Trivy reports are data from outside, so the hostile cases come first: a FROM that is not
an image, a variable with no value, a stage name that looks like an image, a reference with shell syntax in it.
Each negative case has a positive twin so a parser that rejects everything cannot pass.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "base_image_digest.py"
D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64


def run(*args: str | Path):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *map(str, args)],
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
        check=False,
    )


def listing(tmp_path: Path, text: str, *flags: str):
    path = tmp_path / "Containerfile"
    path.write_text(text)
    return run("list", path, *flags)


def pins_of(tmp_path: Path, text: str, *flags: str):
    done = listing(tmp_path, text, *flags)
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


# --- list ---------------------------------------------------------------------------------------


def test_a_pinned_base_is_found_with_its_tag_and_digest(tmp_path):
    (pin,) = pins_of(tmp_path, f"FROM python:3.14-slim@{D1}\nRUN true\n")
    assert pin == {"line": 1, "image": "python:3.14-slim", "repo": "python", "tag": "3.14-slim", "digest": D1}


def test_a_multi_stage_file_lists_each_external_image_once_and_skips_stages_and_scratch(tmp_path):
    text = f"""\
# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.24@{D1} AS build
FROM build AS test
FROM scratch AS empty
FROM Build
FROM golang:1.24@{D1}
FROM registry.example.com:5000/team/app:v2@{D2}
"""
    got = pins_of(tmp_path, text.replace("$BUILDPLATFORM", "linux/amd64"))
    assert [(p["line"], p["image"]) for p in got] == [(2, "golang:1.24"), (7, "registry.example.com:5000/team/app:v2")]


def test_continuations_comments_and_case_are_handled(tmp_path):
    text = f"from \\\n  # a comment inside the instruction\n  alpine:3.22@{D1} \\\n  as final\n"
    assert pins_of(tmp_path, text)[0]["image"] == "alpine:3.22"


def test_an_arg_with_a_default_before_the_first_from_is_resolved(tmp_path):
    text = f'ARG BASE=python:3.14-slim@{D1}\nARG OTHER="x"\nFROM ${{BASE}}\nFROM $BASE AS second\n'
    got = pins_of(tmp_path, text)
    assert len(got) == 1 and got[0]["digest"] == D1


@pytest.mark.parametrize(
    "line, message",
    [
        ("FROM python:3.14", "not pinned by digest"),
        (f"FROM python@{D1}", "names no tag"),
        ("FROM ${UNSET}", "variable with no default"),
        (f"FROM python:3.14@{D1.upper().replace('SHA256', 'sha256')}", "not an image reference"),
        (f"FROM python:3.14@sha256:{'a' * 63}", "not an image reference"),
        (f"FROM python:3.14@{D1};touch${{IFS}}x", "variable with no default"),
        (f"FROM python:3.14@{D1};touch", "not an image reference"),
        (f"FROM $(id):1@{D1}", "variable with no default"),
        (f"FROM `id`:1@{D1}", "not an image reference"),
        (f"FROM py thon:1@{D1}", "cannot read this FROM"),
        ("FROM", "names no image"),
        (f"FROM ../etc:1@{D1}", "not an image reference"),
        (f"FROM -x:1@{D1}", "not an image reference"),
    ],
)
def test_a_from_that_cannot_be_followed_fails_naming_the_line(tmp_path, line, message):
    done = listing(tmp_path, f"\n{line}\n")
    assert done.returncode == 1, done.stdout
    assert "FAIL line 2" in done.stdout and message in done.stdout and "Traceback" not in done.stderr


def test_an_unpinned_base_is_allowed_only_on_request_and_something_pinned_must_remain(tmp_path):
    text = f"FROM alpine:3.22\nFROM python:3.14@{D1}\n"
    assert listing(tmp_path, text).returncode == 1
    assert [p["image"] for p in pins_of(tmp_path, text, "--allow-unpinned")] == ["python:3.14"]
    only_unpinned = listing(tmp_path, "FROM alpine:3.22\n", "--allow-unpinned")
    assert only_unpinned.returncode == 1 and "nothing to check" in only_unpinned.stdout


@pytest.mark.parametrize("text", ["", "# only a comment\n", "FROM scratch\n", "RUN true\n", "ARG X=1\n"])
def test_a_file_with_no_external_base_fails(tmp_path, text):
    done = listing(tmp_path, text)
    assert done.returncode == 1 and "nothing to check" in done.stdout


def test_a_value_cannot_forge_a_log_line(tmp_path):
    done = listing(tmp_path, "FROM x\n::error::forged\n")
    assert all(not line.startswith("::") for line in done.stdout.splitlines())


def test_a_missing_or_binary_dockerfile_fails_cleanly(tmp_path):
    assert run("list", tmp_path / "nope").returncode == 1
    (tmp_path / "bin").write_bytes(b"\xff\xfe\x00FROM")
    done = run("list", tmp_path / "bin")
    assert done.returncode == 1 and "Traceback" not in done.stderr
    assert run("list", tmp_path).returncode == 1  # a directory


# --- diff ---------------------------------------------------------------------------------------


def vuln(vid="CVE-2026-0001", pkg="libssl3", fixed="3.0.2", sev="HIGH", installed="3.0.1"):
    return {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": sev,
    }


def report(*vulns, key="Vulnerabilities"):
    return {"Results": [{"Target": "debian", key: list(vulns)}] if vulns else []}


def diff(tmp_path: Path, pinned, current):
    (tmp_path / "pinned.json").write_text(json.dumps(pinned))
    (tmp_path / "current.json").write_text(json.dumps(current))
    return run("diff", tmp_path / "pinned.json", tmp_path / "current.json")


def test_a_finding_the_current_digest_fixes_fails_and_names_it(tmp_path):
    done = diff(tmp_path, report(vuln()), report())
    assert done.returncode == 1
    assert 'FIXED "CVE-2026-0001" HIGH "libssl3" "3.0.1" -> "3.0.2"' in done.stdout


def test_a_finding_in_both_is_not_a_reason_to_bump(tmp_path):
    done = diff(tmp_path, report(vuln()), report(vuln()))
    assert done.returncode == 0 and done.stdout.startswith("ok")


def test_only_the_fixed_one_of_two_is_named(tmp_path):
    done = diff(tmp_path, report(vuln(), vuln("CVE-2026-0002", "zlib")), report(vuln("CVE-2026-0002", "zlib")))
    assert done.returncode == 1 and "CVE-2026-0001" in done.stdout and "CVE-2026-0002" not in done.stdout


def test_the_same_advisory_in_another_package_is_a_different_finding(tmp_path):
    done = diff(tmp_path, report(vuln(pkg="a")), report(vuln(pkg="b")))
    assert done.returncode == 1 and '"a"' in done.stdout


def test_a_new_finding_in_the_current_digest_does_not_fail(tmp_path):
    assert diff(tmp_path, report(), report(vuln())).returncode == 0


@pytest.mark.parametrize("fixed", ["", None])
def test_an_unfixable_finding_is_not_actionable(tmp_path, fixed):
    pinned = vuln(fixed=fixed)
    if fixed is None:
        del pinned["FixedVersion"]
    assert diff(tmp_path, report(pinned), report()).returncode == 0


def test_findings_spread_over_several_targets_are_all_seen(tmp_path):
    pinned = {"Results": [{"Target": "os", "Vulnerabilities": [vuln()]}, {"Target": "py", "Vulnerabilities": None}]}
    assert diff(tmp_path, pinned, report()).returncode == 1


@pytest.mark.parametrize(
    "current",
    [
        {},  # no Results key: a scan that did not happen is not a scan that found nothing
        {"Results": None},
        [],
        "x",
    ],
    ids=["no Results", "null Results", "a list", "a string"],
)
def test_a_current_report_that_is_not_a_report_fails_rather_than_passing(tmp_path, current):
    done = diff(tmp_path, report(vuln()), current)
    assert done.returncode == 1 and "FAIL" in done.stdout and "Traceback" not in done.stderr


def test_a_pinned_report_that_is_not_a_report_fails(tmp_path):
    assert diff(tmp_path, {}, report()).returncode == 1


def test_junk_inside_results_is_ignored_not_crashed_on(tmp_path):
    pinned = {"Results": ["x", None, {"Vulnerabilities": ["y", 3, vuln()]}, {"Vulnerabilities": "z"}]}
    done = diff(tmp_path, pinned, report())
    assert done.returncode == 1 and "CVE-2026-0001" in done.stdout


def test_a_value_in_a_report_cannot_forge_a_log_line(tmp_path):
    done = diff(tmp_path, report(vuln(vid="x\n::error::forged")), report())
    assert all(not line.startswith("::") for line in done.stdout.splitlines())


def test_unreadable_reports_fail_cleanly(tmp_path):
    (tmp_path / "p.json").write_text("{nope")
    (tmp_path / "c.json").write_text(json.dumps(report()))
    assert run("diff", tmp_path / "p.json", tmp_path / "c.json").returncode == 1
    assert run("diff", tmp_path / "missing.json", tmp_path / "c.json").returncode == 1
