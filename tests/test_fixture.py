"""The fixture project (fixture/README.md) is what this repository's CI runs the reusable workflows against."""

import re
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent.parent / "fixture"
REQUIREMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==\S+")


def requirement_blocks():
    """Each requirement with its continuation lines, comments dropped."""
    blocks = []
    for raw in (FIXTURE / "requirements.txt").read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        if REQUIREMENT.match(line):
            blocks.append([line])
        else:
            assert blocks, f"continuation before any requirement: {raw!r}"
            blocks[-1].append(line.strip())
    return blocks


def test_every_fixture_requirement_is_pinned_with_a_hash():
    """`--require-hashes` refuses a line without one; the lock must never carry such a line."""
    blocks = requirement_blocks()
    assert blocks, "fixture/requirements.txt lists nothing"
    for block in blocks:
        text = " ".join(block)
        assert "--hash=sha256:" in text, f"no hash for {block[0]}"


def test_every_direct_dependency_is_in_the_lock():
    direct = {
        line.split("==")[0].lower()
        for line in (FIXTURE / "requirements.in").read_text().splitlines()
        if line and not line.startswith("#")
    }
    locked = {block[0].split("==")[0].lower() for block in requirement_blocks()}
    assert direct <= locked, f"in requirements.in but not the lock: {sorted(direct - locked)}"


def test_the_fixture_image_runs_as_a_non_root_user():
    dockerfile = (FIXTURE / "Dockerfile").read_text()
    assert re.search(r"^USER (?!root\b)\S+", dockerfile, re.M), "fixture/Dockerfile has no non-root USER"
    assert re.search(r"^FROM \S+@sha256:[0-9a-f]{64}", dockerfile, re.M), "base image is not pinned by digest"
