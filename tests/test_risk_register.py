"""The risk register (baseline/risk-register.yaml) is data the audit trusts; this checks its shape.

An entry with no reason, no owner, or a review date a year out would let an
exception live quietly. Each rule here is one the audit relies on.
"""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
REGISTER = REPO / "baseline" / "risk-register.yaml"
REPOS = REPO / "baseline" / "repos.txt"

REQUIRED = ("id", "package", "versions", "repos", "where", "reason", "mitigation", "accepted", "review_by", "owner")
ADVISORY = re.compile(r"^(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|CVE-\d{4}-\d{4,})$")
MAX_REVIEW_DAYS = 90


def entries() -> list[dict]:
    data = yaml.safe_load(REGISTER.read_text()) or {}
    return list(data.get("entries") or [])


def known_repos() -> set[str]:
    return {
        line.strip().lower() for line in REPOS.read_text().splitlines() if line.strip() and not line.startswith("#")
    }


def test_every_entry_has_every_field_filled():
    for entry in entries():
        for field in REQUIRED:
            assert entry.get(field) not in (None, "", [], {}), f"{entry.get('id')}: {field} is missing or empty"


def test_ids_and_aliases_look_like_advisories():
    for entry in entries():
        for advisory in (entry["id"], *(entry.get("aliases") or [])):
            assert ADVISORY.match(str(advisory)), f"{advisory!r} is not a GHSA, PYSEC or CVE ID"


def test_no_advisory_is_entered_twice():
    seen: set[str] = set()
    for entry in entries():
        for advisory in (entry["id"], *(entry.get("aliases") or [])):
            assert advisory not in seen, f"{advisory} appears in two entries"
            seen.add(advisory)


def test_repos_are_in_the_baseline_list():
    known = known_repos()
    for entry in entries():
        for repo in entry["repos"]:
            assert str(repo).lower() in known, f"{entry['id']}: {repo} is not in baseline/repos.txt"


def test_where_names_a_check_that_takes_exceptions():
    for entry in entries():
        for where in entry["where"]:
            assert where in ("pip-audit", "dependency-review"), f"{entry['id']}: unknown check {where!r}"


def test_dates_are_dates_and_the_review_is_at_most_ninety_days_out():
    for entry in entries():
        accepted, review_by = entry["accepted"], entry["review_by"]
        assert isinstance(accepted, dt.date), f"{entry['id']}: accepted must be YYYY-MM-DD"
        assert isinstance(review_by, dt.date), f"{entry['id']}: review_by must be YYYY-MM-DD"
        assert review_by > accepted, f"{entry['id']}: review_by is not after accepted"
        assert (review_by - accepted).days <= MAX_REVIEW_DAYS, (
            f"{entry['id']}: review_by is more than {MAX_REVIEW_DAYS} days after accepted"
        )


def test_no_entry_has_expired():
    """An expired entry fails the audit for its repository; catch it here first, where the fix is."""
    today = dt.date.today()
    for entry in entries():
        assert entry["review_by"] >= today, f"{entry['id']}: review_by {entry['review_by']} has passed; renew or remove"
