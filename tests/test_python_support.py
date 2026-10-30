"""The supported CPython versions live in `.github/python-support.json`; everything else repeats it.

A workflow input default is a literal (GitHub reads no file there), so these
tests hold each copy equal to the list, and fail when a listed version is past
its security-support end date. The clock is always injected: a check takes
`today`, and the one test that reads the real date only passes it in.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from datetime import date

import pytest
from test_workflows import README, REPO, WORKFLOW_FILES, WORKFLOWS, load

sys.path.insert(0, str(REPO / "scripts"))
import python_support  # noqa: E402  (scripts/ is not a package)
import tool_locks  # noqa: E402

DATA = python_support.load()
LISTED = python_support.versions(DATA)


def inputs_of(path):
    doc = load(path)
    triggers = doc.get("on") or doc.get(True)  # PyYAML reads a bare `on:` key as True
    call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
    return (call or {}).get("inputs") or {}


def test_the_list_is_well_formed():
    assert LISTED == sorted(LISTED, key=python_support.minor), "oldest first"
    assert len(set(LISTED)) == len(LISTED)
    ends = [date.fromisoformat(e["security_end"]) for e in DATA["versions"]]
    assert ends == sorted(ends), "a newer CPython is supported at least as long as an older one"
    for entry in DATA["versions"]:
        assert re.fullmatch(r"3\.\d+", entry["version"])
        if entry["bugfix_end"]:
            assert date.fromisoformat(entry["bugfix_end"]) < date.fromisoformat(entry["security_end"])
    assert DATA["coverage_version"] in LISTED


def test_the_issue_242_dates():
    """The dates supplied on 2026-10-30, checked the same day against the devguide (which gives the month)."""
    assert {e["version"]: e["security_end"] for e in DATA["versions"]} == {
        "3.11": "2027-10-31",
        "3.12": "2028-10-31",
        "3.13": "2029-10-31",
        "3.14": "2030-10-31",
        "3.15": "2031-10-31",
    }


# --- the clock is injectable and the guard bites -----------------------------------------------------------------


def test_no_listed_version_is_past_its_security_end_today():
    assert python_support.expired(date.today()) == [], (
        "drop the version from .github/python-support.json and every default"
    )


@pytest.mark.parametrize(
    ("today", "expected"),
    [
        (date(2026, 10, 30), []),
        (date(2027, 10, 31), []),  # the last day of support still counts
        (date(2027, 11, 1), ["3.11"]),
        (date(2028, 11, 1), ["3.11", "3.12"]),
        (date(2031, 11, 1), ["3.11", "3.12", "3.13", "3.14", "3.15"]),
    ],
)
def test_expired_follows_the_injected_clock(today, expected):
    data = copy.deepcopy(DATA)
    data["grace"] = []
    found = [re.search(r"Python (3\.\d+)", p).group(1) for p in python_support.expired(today, data)]
    assert found == expected


def test_a_lapsed_grace_entry_is_reported():
    assert python_support.expired(date(2026, 11, 30)) == []
    assert any("3.10" in p for p in python_support.expired(date(2026, 12, 1)))


def test_the_script_exits_nonzero_when_expired(capsys):
    assert python_support.main(["--today", "2026-10-30"]) == 0
    assert python_support.main(["--today", "2027-11-01"]) == 1
    assert "3.11" in capsys.readouterr().err


# --- every copy of the list equals the list ----------------------------------------------------------------------


def test_python_ci_default_matrix_is_the_list():
    default = inputs_of(WORKFLOWS / "python-ci.yml")["python-versions"]["default"]
    assert json.loads(default) == LISTED


def test_python_ci_coverage_leg_is_listed_and_documented():
    inputs = inputs_of(WORKFLOWS / "python-ci.yml")
    assert inputs["coverage-python-version"]["default"] == DATA["coverage_version"]
    assert DATA["coverage_version"] in json.loads(inputs["python-versions"]["default"])


def python_version_defaults():
    """Every workflow_call input that names a Python, and the version it defaults to."""
    found = []
    for path in WORKFLOW_FILES:
        for name, spec in inputs_of(path).items():
            if name.endswith("python-version") and spec.get("default"):  # an empty default means "not set"
                found.append((path.name, name, str(spec["default"])))
    return found


def unlisted(defaults, listed):
    return [(f, n, v) for f, n, v in defaults if v not in listed]


def test_every_python_version_default_is_a_listed_version():
    found = python_version_defaults()
    assert len(found) >= 6, "the collector found the inputs"
    assert not unlisted(found, LISTED), "defaults outside .github/python-support.json"


def test_the_default_guard_bites():
    assert unlisted([("x.yml", "python-version", "3.10")], LISTED) == [("x.yml", "python-version", "3.10")]
    assert unlisted([("x.yml", "python-version", "3.13")], LISTED) == []


def test_new_repo_fallback_is_the_list():
    text = (REPO / "scripts" / "new-repo.sh").read_text()
    match = re.search(r"""py_versions='([^']+)'""", text)
    assert match, "the fallback line exists"
    assert [v.strip('" ') for v in match.group(1).split(",")] == LISTED


def test_readme_documents_the_default_matrix():
    text = README.read_text()
    row = re.search(r"^\| `python-versions` \| `([^`]+)` \|", text, re.M)
    assert row, "the python-ci input table row"
    assert json.loads(row.group(1).strip("'")) == LISTED


# --- the tool locks follow the list too --------------------------------------------------------------------------


def test_tool_locks_newest_minor_comes_from_the_list():
    assert tool_locks.NEWEST_MINOR == python_support.minor(DATA["tool_locks"]["newest"])
    assert DATA["tool_locks"]["newest"] in LISTED


def test_every_tool_lock_floor_is_listed_or_in_unexpired_grace():
    graced = {g["version"] for g in DATA.get("grace", [])}
    for tool, (_, _, oldest) in tool_locks.TOOLS.items():
        assert f"3.{oldest}" in LISTED or f"3.{oldest}" in graced, (
            f"{tool} is locked from 3.{oldest}, which is not supported"
        )


def test_lock_headers_say_the_newest_minor():
    reqs = REPO / ".github" / "requirements"
    for tool in tool_locks.TOOLS:
        head = (reqs / f"{tool}.txt").read_text().splitlines()[1]
        assert head.endswith(f"-3.{tool_locks.NEWEST_MINOR} only (see that script)."), f"{tool}: {head}"
