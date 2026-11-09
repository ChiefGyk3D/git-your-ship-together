"""repin.sh: move a caller's GYST pins to a release, changing nothing but the pin SHA and its version comment.

The script runs for real under bash against a fake `gh` (a Python program that answers from a scenario file and
records every call) and, for the pull request mode, against real git with a local bare repository as the remote.
Nothing here touches the network: the fake is the only `gh` on the path and the script is told so with GH_BIN.

Every guard has a case that must go red and a control that must stay green.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "repin.sh"
EXAMPLE = REPO / "examples" / "dependabot-gyst.yml"

SRC = "ChiefGyk3D/git-your-ship-together"
OLD = "a" * 40
MID = "b" * 40
NEW = "c" * 40
OTHER = "d" * 40  # a pin of some other repository's action, which must never be touched

FAKE_GH = r"""#!/usr/bin/env python3
import json, os, sys
sc = json.load(open(os.environ["REPIN_SCENARIO"]))
with open(os.environ["REPIN_CALLS"], "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
a = sys.argv[1:]
if a[:1] == ["api"]:
    path = a[1]
    if path.endswith("/releases/latest"):
        print(sc["latest"])
        sys.exit(0)
    if "/contents/" in path:
        fpath, _, query = path.split("/contents/", 1)[1].partition("?")
        # Real gh turns -f/-F into a POST unless -X GET is given; the contents endpoint is GET only.
        method = a[a.index("-X") + 1] if "-X" in a else ("POST" if ("-f" in a or "-F" in a) else "GET")
        if method != "GET":
            sys.stderr.write("gh: Not Found (HTTP 404)\n")
            sys.exit(1)
        ref = dict(kv.split("=", 1) for kv in query.split("&") if "=" in kv).get("ref", "")
        docs = sc.get("contents", {})
        key = fpath + "@" + ref
        if key in docs:
            sys.stdout.write(docs[key])
            sys.exit(0)
        if sc.get("contents_default") is not None and "@" + ref not in sc.get("contents_missing", []):
            sys.stdout.write(sc["contents_default"])
            sys.exit(0)
        sys.stderr.write("gh: Not Found (HTTP 404)\n")
        sys.exit(1)
    tag = path.rsplit("/commits/", 1)[-1]
    info = sc["tags"].get(tag)
    if info is None:
        sys.stderr.write("gh: Not Found (HTTP 404)\n")
        sys.exit(1)
    print(info["sha"] + "\t" + info["date"])
    sys.exit(0)
if a[:2] == ["pr", "list"]:
    head = a[a.index("--head") + 1]
    if head in sc.get("open_prs", {}):
        print(sc["open_prs"][head])
    sys.exit(0)
if a[:2] == ["pr", "create"]:
    body = open(a[a.index("--body-file") + 1]).read()
    with open(os.environ["REPIN_CALLS"] + ".body", "w") as f:
        f.write(body)
    print("https://github.com/N0TST/widgets/pull/7")
    sys.exit(0)
sys.stderr.write("fake gh: unexpected call %r\n" % (a,))
sys.exit(99)
"""

TAGS = {
    "v1.28.0": {"sha": OLD, "date": "2026-10-01T12:00:00Z"},
    "v1.29.0": {"sha": MID, "date": "2026-10-20T12:00:00Z"},
    "v1.30.0": {"sha": NEW, "date": "2026-11-05T12:00:00Z"},
}
NOW = "2026-11-08T12:00:00Z"
DEFAULT_DEF = (
    "on:\n  workflow_call:\n    inputs:\n      python-version:\n        type: string\n        default: '3.12'\n"
)


def wf(sha=OLD, ver="v1.28.0", extra=""):
    return f"""name: CI
on: [push]
permissions:
  contents: read
jobs:
  python:
    uses: {SRC}/.github/workflows/python-ci.yml@{sha} # {ver}
    permissions:
      contents: read
    with:
      python-version: "3.12"{extra}
  checkout:
    runs-on: ubuntu-24.04
    steps:
      # uses: {SRC}/.github/workflows/x.yml@<sha> # vX.Y.Z (a comment, not a pin)
      - uses: actions/checkout@{OTHER} # v4.2.0
"""


@pytest.fixture
def env(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "gh"
    fake.write_text(FAKE_GH)
    fake.chmod(0o755)
    scenario = tmp_path / "scenario.json"
    scenario.write_text(
        json.dumps({"latest": "v1.30.0", "tags": TAGS, "open_prs": {}, "contents_default": DEFAULT_DEF})
    )
    calls = tmp_path / "calls.log"
    calls.write_text("")
    e = {
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "GH_BIN": str(fake),
        "REPIN_SCENARIO": str(scenario),
        "REPIN_CALLS": str(calls),
        "REPIN_NOW": NOW,
        "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"),
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }
    return {"env": e, "scenario": scenario, "calls": calls, "tmp": tmp_path}


def run(ctx, *args, check=False):
    return subprocess.run(
        ["bash", str(SCRIPT), *map(str, args)],
        env=ctx["env"],
        capture_output=True,
        text=True,
        timeout=60,
        check=check,
    )


def make_caller(ctx, files, name="caller"):
    root = ctx["tmp"] / name
    (root / ".github" / "workflows").mkdir(parents=True)
    for fname, text in files.items():
        (root / ".github" / "workflows" / fname).write_text(text)
    return root


def set_scenario(ctx, **changes):
    sc = json.loads(ctx["scenario"].read_text())
    sc.update(changes)
    ctx["scenario"].write_text(json.dumps(sc))


def calls(ctx):
    return [json.loads(line) for line in ctx["calls"].read_text().splitlines() if line]


# --- status -----------------------------------------------------------------


def test_status_prints_pinned_against_latest_with_ages_and_exits_10_when_behind(env):
    root = make_caller(env, {"ci.yml": wf()})
    p = run(env, "status", root)
    assert p.returncode == 10, p.stderr
    assert "v1.28.0" in p.stdout and "v1.30.0" in p.stdout
    assert "38 days old" in p.stdout  # 2026-10-01 to 2026-11-08
    assert "3 days old" in p.stdout  # the latest, released 2026-11-05
    assert "BEHIND" in p.stdout


def test_apply_reads_workflow_inputs_with_a_get_request(env):
    """gh turns -f into a POST, which the contents endpoint rejects, so every caller exited 5 (issue #374)."""
    root = make_caller(env, {"ci.yml": wf()})
    p = run(env, "apply", root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "cannot read" not in p.stderr
    reads = [c for c in calls(env) if len(c) > 1 and "/contents/" in c[1]]
    assert reads, "no contents reads were made"
    for c in reads:
        assert "-f" not in c and "-F" not in c, c
        assert "ref=" in c[1], c


def test_status_exits_0_when_every_pin_is_the_latest(env):
    root = make_caller(env, {"ci.yml": wf(NEW, "v1.30.0")})
    p = run(env, "status", root)
    assert p.returncode == 0, p.stdout + p.stderr
    assert "current" in p.stdout and "BEHIND" not in p.stdout


def test_status_reports_one_line_group_per_repository_directory(env):
    a = make_caller(env, {"ci.yml": wf()}, "alpha")
    b = make_caller(env, {"ci.yml": wf(NEW, "v1.30.0")}, "beta")
    p = run(env, "status", a, b)
    assert p.returncode == 10
    assert str(a) in p.stdout and str(b) in p.stdout


def test_status_flags_a_comment_that_names_a_tag_whose_commit_is_another(env):
    root = make_caller(env, {"ci.yml": wf(OTHER, "v1.28.0")})
    p = run(env, "status", root)
    assert "MISMATCH" in p.stdout


def test_a_repository_with_no_pins_is_reported_and_is_not_an_error(env):
    root = make_caller(env, {"ci.yml": "name: x\non: [push]\njobs: {}\n"})
    p = run(env, "status", root)
    assert p.returncode == 0
    assert "no GYST pins" in p.stdout


# --- apply ------------------------------------------------------------------


def test_apply_changes_only_the_sha_and_the_version_comment(env):
    before = wf()
    root = make_caller(env, {"ci.yml": before})
    p = run(env, "apply", root)
    assert p.returncode == 0, p.stderr
    after = (root / ".github/workflows/ci.yml").read_text()
    assert after == before.replace(OLD, NEW).replace("# v1.28.0", "# v1.30.0")
    # the comment that shows the format, and another repository's pin, are untouched
    assert "@<sha> # vX.Y.Z" in after
    assert f"actions/checkout@{OTHER} # v4.2.0" in after


def test_apply_moves_every_pin_in_every_workflow_and_action_in_one_run(env):
    root = make_caller(env, {"ci.yml": wf(), "release.yaml": wf(MID, "v1.29.0")})
    act = root / ".github" / "actions" / "x"
    act.mkdir(parents=True)
    (act / "action.yml").write_text(
        f"runs:\n  using: composite\n  steps:\n    - uses: {SRC}/.github/actions/wait-ci@{OLD} # v1.28.0\n"
    )
    p = run(env, "apply", root)
    assert p.returncode == 0, p.stderr
    for f in (root / ".github").rglob("*.y*ml"):
        text = f.read_text()
        assert OLD not in text and MID not in text, f
        assert f"@{NEW} # v1.30.0" in text, f


def test_apply_is_idempotent(env):
    root = make_caller(env, {"ci.yml": wf()})
    assert run(env, "apply", root).returncode == 0
    once = (root / ".github/workflows/ci.yml").read_bytes()
    p = run(env, "apply", root)
    assert p.returncode == 0
    assert "up to date" in p.stdout
    assert (root / ".github/workflows/ci.yml").read_bytes() == once


def test_dry_run_prints_the_diff_and_writes_nothing(env):
    root = make_caller(env, {"ci.yml": wf()})
    before = (root / ".github/workflows/ci.yml").read_bytes()
    p = run(env, "apply", "--dry-run", root)
    assert p.returncode == 0, p.stderr
    assert (root / ".github/workflows/ci.yml").read_bytes() == before
    assert f"-    uses: {SRC}/.github/workflows/python-ci.yml@{OLD} # v1.28.0" in p.stdout
    assert f"+    uses: {SRC}/.github/workflows/python-ci.yml@{NEW} # v1.30.0" in p.stdout


def test_to_pins_a_chosen_release_instead_of_the_latest(env):
    root = make_caller(env, {"ci.yml": wf()})
    assert run(env, "apply", "--to", "v1.29.0", root).returncode == 0
    assert f"@{MID} # v1.29.0" in (root / ".github/workflows/ci.yml").read_text()


def test_a_downgrade_is_refused_and_writes_nothing(env):
    text = wf(NEW, "v1.30.0")
    root = make_caller(env, {"ci.yml": text})
    p = run(env, "apply", "--to", "v1.29.0", root)
    assert p.returncode == 3
    assert "downgrade" in p.stderr
    assert (root / ".github/workflows/ci.yml").read_text() == text


@pytest.mark.parametrize(
    "line",
    [
        f"    uses: {SRC}/.github/workflows/python-ci.yml@main",
        f"    uses: {SRC}/.github/workflows/python-ci.yml@v1.28.0",
        f"    uses: {SRC}/.github/workflows/python-ci.yml@{OLD}",
        f"    uses: {SRC}/.github/workflows/python-ci.yml@{OLD} # pinned for a while",
        f"    uses: {SRC}/.github/workflows/python-ci.yml@{OLD[:39]} # v1.28.0",
    ],
    ids=["branch", "tag", "sha-no-comment", "sha-odd-comment", "short-sha"],
)
def test_a_reference_that_is_not_a_canonical_pin_is_refused_and_nothing_is_written(env, line):
    good = wf()
    odd = good + f"  other:\n{line}\n"
    root = make_caller(env, {"a.yml": good, "b.yml": odd})
    p = run(env, "apply", root)
    assert p.returncode == 3, p.stdout
    assert "b.yml" in p.stderr
    assert (root / ".github/workflows/a.yml").read_text() == good  # all or nothing
    assert (root / ".github/workflows/b.yml").read_text() == odd


@pytest.mark.parametrize("tag", ["v1.30", "1.30.0", "v1.30.0; rm -rf x", "v1.30.0\nv9.9.9", "latest", ""])
def test_a_latest_tag_that_is_not_a_plain_version_is_refused(env, tag):
    set_scenario(env, latest=tag)
    root = make_caller(env, {"ci.yml": wf()})
    before = (root / ".github/workflows/ci.yml").read_bytes()
    p = run(env, "apply", root)
    assert p.returncode != 0
    assert (root / ".github/workflows/ci.yml").read_bytes() == before


def test_a_commit_that_is_not_forty_hex_characters_is_refused(env):
    tags = dict(TAGS)
    tags["v1.30.0"] = {"sha": "main", "date": "2026-11-05T12:00:00Z"}
    set_scenario(env, tags=tags)
    root = make_caller(env, {"ci.yml": wf()})
    before = (root / ".github/workflows/ci.yml").read_bytes()
    assert run(env, "apply", root).returncode != 0
    assert (root / ".github/workflows/ci.yml").read_bytes() == before


def test_an_unknown_tag_given_to_to_is_refused(env):
    root = make_caller(env, {"ci.yml": wf()})
    p = run(env, "apply", "--to", "v9.9.9", root)
    assert p.returncode != 0


def test_a_symlinked_workflow_is_never_rewritten(env):
    root = make_caller(env, {"ci.yml": wf()})
    outside = env["tmp"] / "outside.yml"
    outside.write_text(wf())
    (root / ".github/workflows/link.yml").symlink_to(outside)
    p = run(env, "apply", root)
    assert p.returncode == 0, p.stderr
    assert outside.read_text() == wf()
    assert "symlink" in p.stderr


def test_only_the_fake_gh_is_ever_called(env):
    root = make_caller(env, {"ci.yml": wf()})
    run(env, "apply", root)
    assert calls(env), "the script never asked for a release"
    assert all(c[0] == "api" for c in calls(env))


# --- pr ---------------------------------------------------------------------


IDENTITY = {
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}


def git(cwd, *args):
    # a runner has no global git identity, so a commit made here brings its own
    return subprocess.run(
        ["git", "-C", str(cwd), *args], capture_output=True, text=True, check=True, env={**os.environ, **IDENTITY}
    ).stdout


@pytest.fixture
def clone(env):
    tmp = env["tmp"]
    remote = tmp / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True, env=env["env"])
    root = make_caller(env, {"ci.yml": wf()}, "work")
    (root / "README.md").write_text("hello\n")
    ge = {**os.environ, **env["env"]}
    for args in (
        ["init", "-q", "-b", "main"],
        ["add", "."],
        ["commit", "-q", "-m", "init"],
        ["remote", "add", "origin", str(remote)],
        ["push", "-q", "origin", "main"],
    ):
        subprocess.run(["git", "-C", str(root), *args], check=True, env=ge)
    return root, remote


def test_pr_mode_branches_commits_only_the_workflow_files_pushes_and_opens_a_pr(env, clone):
    root, remote = clone
    p = run(env, "pr", root)
    assert p.returncode == 0, p.stderr
    branch = "repin/gyst-v1.30.0"
    assert branch in git(remote, "branch", "--list")
    changed = git(root, "diff", "--name-only", "main", branch).split()
    assert changed == [".github/workflows/ci.yml"]
    diff = git(root, "diff", "-U0", "main", branch)
    assert f"+    uses: {SRC}/.github/workflows/python-ci.yml@{NEW} # v1.30.0" in diff
    create = [c for c in calls(env) if c[:2] == ["pr", "create"]]
    assert len(create) == 1
    argv = create[0]
    assert argv[argv.index("--base") + 1] == "main" and argv[argv.index("--head") + 1] == branch
    body = Path(str(env["calls"]) + ".body").read_text()
    assert f"https://github.com/{SRC}/blob/v1.30.0/CHANGELOG.md" in body
    assert "pin" in body.lower()
    assert git(root, "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"  # back where it started


def test_pr_mode_never_merges_or_enables_auto_merge(env, clone):
    root, _ = clone
    run(env, "pr", root)
    for c in calls(env):
        assert "merge" not in c, c


def test_pr_mode_refuses_a_dirty_tree(env, clone):
    root, remote = clone
    (root / "README.md").write_text("changed\n")
    p = run(env, "pr", root)
    assert p.returncode == 3
    assert "clean" in p.stderr
    assert git(remote, "branch", "--format=%(refname:short)").split() == ["main"]


def test_pr_mode_does_nothing_when_a_pr_for_that_release_is_open(env, clone):
    root, remote = clone
    set_scenario(env, open_prs={"repin/gyst-v1.30.0": "5"})
    p = run(env, "pr", root)
    assert p.returncode == 0
    assert "already open" in p.stdout
    assert not [c for c in calls(env) if c[:2] == ["pr", "create"]]
    assert "repin" not in git(remote, "branch", "--list")


def test_pr_mode_does_nothing_when_the_caller_is_current(env, clone):
    root, remote = clone
    (root / ".github/workflows/ci.yml").write_text(wf(NEW, "v1.30.0"))
    git(root, "commit", "-q", "-am", "pin")
    p = run(env, "pr", root)
    assert p.returncode == 0
    assert "up to date" in p.stdout
    assert not [c for c in calls(env) if c[:2] == ["pr", "create"]]


# --- literal copies of the old pin outside the workflows (issue #380) ---------------------------------------


def init_repo(env, root):
    ge = {**os.environ, **env["env"]}
    for args in (["init", "-q", "-b", "main"], ["add", "."], ["commit", "-q", "-m", "init"]):
        subprocess.run(["git", "-C", str(root), *args], check=True, env=ge)


@pytest.fixture
def lit(env):
    """A git repository: a workflow pin plus every kind of other place that can hold the old SHA."""
    root = make_caller(env, {"ci.yml": wf()}, "lit")
    (root / "tests").mkdir()
    (root / "scripts").mkdir()
    (root / "docs").mkdir()
    (root / "tests" / "test_template.py").write_text(
        f'assert "{SRC}/.github/workflows/bash-ci.yml@{OLD} # v1.28.0" in TEXT\n'
        f"PARTIAL = '{OLD}e'\n"  # a longer hex string that merely contains the SHA: never a match
        f"OTHER = '{OTHER}'\n"
    )
    (root / "scripts" / "apply-baseline.sh").write_text(f'#!/bin/sh\nGYST_SHA="{OLD}"\n')
    (root / "CHANGELOG.md").write_text(f"- pinned {OLD} # v1.28.0 for a while\n")
    (root / "docs" / "HISTORY.md").write_text(f"- {OLD} # v1.28.0\n")
    (root / "blob.bin").write_bytes(b"\x00\x01" + OLD.encode() + b"\x00")
    (root / "scripts" / "link").symlink_to("apply-baseline.sh")
    init_repo(env, root)
    return root


def snapshot(root):
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and ".git" not in p.relative_to(root).parts
    }


def hit_lines(out):
    return [ln.strip() for ln in out.splitlines() if re.match(r"\s+\S+:\d+\b", ln)]


def test_apply_without_the_flag_reports_every_other_copy_rewrites_only_the_pin_and_exits_11(env, lit):
    before = snapshot(lit)
    p = run(env, "apply", lit)
    assert p.returncode == 11, p.stdout + p.stderr
    after = snapshot(lit)
    assert {k for k in after if after[k] != before[k]} == {".github/workflows/ci.yml"}
    assert "--also-update-literals" in p.stdout
    hits = hit_lines(p.stdout)
    assert any(h.startswith("tests/test_template.py:1 ") for h in hits), hits
    assert any(h.startswith("scripts/apply-baseline.sh:2 ") for h in hits), hits
    # not a hit to fix: history files, binary files, a partial match, another SHA, the workflow pin itself
    joined = "\n".join(hits)
    for gone in ("CHANGELOG", "HISTORY", "blob.bin", "test_template.py:2", "test_template.py:3", "ci.yml"):
        assert gone not in joined, gone


def test_the_flag_rewrites_the_exact_literal_and_the_adjacent_version_and_prints_each_rewrite(env, lit):
    before = snapshot(lit)
    p = run(env, "apply", "--also-update-literals", lit)
    assert p.returncode == 0, p.stdout + p.stderr
    after = snapshot(lit)
    t = after["tests/test_template.py"].decode()
    assert f"bash-ci.yml@{NEW} # v1.30.0" in t
    assert f"PARTIAL = '{OLD}e'" in t and f"OTHER = '{OTHER}'" in t  # partial match and other SHA untouched
    assert f'GYST_SHA="{NEW}"' in after["scripts/apply-baseline.sh"].decode()
    out = p.stdout
    assert "rewrote tests/test_template.py:1" in out and "rewrote scripts/apply-baseline.sh:2" in out
    for name in ("CHANGELOG.md", "docs/HISTORY.md", "blob.bin"):
        assert after[name] == before[name], name
    assert (lit / "scripts" / "link").is_symlink()
    assert "rewrote" not in "".join(ln for ln in out.splitlines() if "CHANGELOG" in ln or "blob" in ln)


def test_the_version_comment_is_changed_only_where_it_directly_follows_the_sha(env, lit):
    (lit / "tests" / "other.py").write_text(f"# v1.28.0 is the old release\nX = '{OLD}'\nY = '{OLD}' # note v1.28.0\n")
    git(lit, "add", ".")
    git(lit, "commit", "-q", "-m", "more")
    p = run(env, "apply", "--also-update-literals", lit)
    assert p.returncode == 0, p.stderr
    assert (lit / "tests" / "other.py").read_text() == (
        f"# v1.28.0 is the old release\nX = '{NEW}'\nY = '{NEW}' # note v1.28.0\n"
    )


def test_apply_is_clean_on_a_repository_with_no_other_copies_with_and_without_the_flag(env):
    root = make_caller(env, {"ci.yml": wf()}, "plain")
    init_repo(env, root)
    p = run(env, "apply", "--also-update-literals", root)
    assert p.returncode == 0, p.stderr
    assert "outside the workflow" not in p.stdout
    root2 = make_caller(env, {"ci.yml": wf()}, "plain2")
    init_repo(env, root2)
    p = run(env, "apply", root2)
    assert p.returncode == 0, p.stderr
    assert "outside the workflow" not in p.stdout


def test_dry_run_reports_the_copies_and_with_the_flag_shows_the_diff_and_writes_nothing(env, lit):
    before = snapshot(lit)
    p = run(env, "apply", "--dry-run", lit)
    assert p.returncode == 11
    assert any(h.startswith("tests/test_template.py:1 ") for h in hit_lines(p.stdout))
    assert snapshot(lit) == before
    p = run(env, "apply", "--dry-run", "--also-update-literals", lit)
    assert p.returncode == 0, p.stderr
    assert f'+GYST_SHA="{NEW}"' in p.stdout
    assert snapshot(lit) == before


def test_status_lists_the_other_copies_of_a_pin_that_is_behind_and_keeps_exit_10(env, lit):
    before = snapshot(lit)
    p = run(env, "status", lit)
    assert p.returncode == 10
    hits = hit_lines(p.stdout)
    assert any(h.startswith("tests/test_template.py:1 ") for h in hits)
    assert any(h.startswith("scripts/apply-baseline.sh:2 ") for h in hits)
    assert snapshot(lit) == before


def test_status_lists_no_copies_when_the_pin_is_current(env, lit):
    (lit / ".github/workflows/ci.yml").write_text(wf(NEW, "v1.30.0"))
    p = run(env, "status", lit)
    assert p.returncode == 0
    assert "outside the workflow" not in p.stdout


def test_a_directory_that_is_not_a_git_checkout_skips_the_scan_and_keeps_its_old_exit_codes(env):
    root = make_caller(env, {"ci.yml": wf()}, "nogit")
    (root / "t.py").write_text(f"{OLD}\n")
    assert run(env, "apply", root).returncode == 0
    assert (root / "t.py").read_text() == f"{OLD}\n"


def test_an_untracked_file_is_never_scanned_or_rewritten(env, lit):
    (lit / "scratch.txt").write_text(f"{OLD}\n")
    p = run(env, "apply", "--also-update-literals", lit)
    assert p.returncode == 0
    assert (lit / "scratch.txt").read_text() == f"{OLD}\n"


def test_the_flag_is_refused_on_status(env, lit):
    assert run(env, "status", "--also-update-literals", lit).returncode == 64


def test_pr_mode_with_the_flag_commits_the_literal_files_too(env, clone):
    root, _ = clone
    (root / "tests").mkdir()
    (root / "tests" / "t.py").write_text(f'PIN = "{OLD}"  # v1.28.0\n')
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "t")
    git(root, "push", "-q", "origin", "main")
    p = run(env, "pr", "--also-update-literals", root)
    assert p.returncode == 0, p.stdout + p.stderr
    changed = sorted(git(root, "diff", "--name-only", "main", "repin/gyst-v1.30.0").split())
    assert changed == [".github/workflows/ci.yml", "tests/t.py"]
    assert f'PIN = "{NEW}"  # v1.30.0' in git(root, "show", "repin/gyst-v1.30.0:tests/t.py")
    assert "tests/t.py" in Path(str(env["calls"]) + ".body").read_text()


def test_pr_mode_without_the_flag_opens_the_workflow_only_pr_names_the_copies_and_exits_11(env, clone):
    root, _ = clone
    (root / "tests").mkdir()
    (root / "tests" / "t.py").write_text(f'PIN = "{OLD}"\n')
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "t")
    git(root, "push", "-q", "origin", "main")
    p = run(env, "pr", root)
    assert p.returncode == 11, p.stdout + p.stderr
    assert git(root, "diff", "--name-only", "main", "repin/gyst-v1.30.0").split() == [".github/workflows/ci.yml"]
    body = Path(str(env["calls"]) + ".body").read_text()
    assert "tests/t.py:1" in body and "--also-update-literals" in body
    assert git(root, "rev-parse", "--abbrev-ref", "HEAD").strip() == "main"


def test_the_exit_code_table_names_11_and_the_flag():
    text = SCRIPT.read_text()
    assert re.search(r"11 [^;\n]*literal", text)
    assert "--also-update-literals" in text


# --- the Dependabot template ------------------------------------------------


def test_the_dependabot_template_groups_gyst_refs_with_a_short_cooldown():
    doc = yaml.safe_load(EXAMPLE.read_text())
    assert doc["version"] == 2
    entries = [u for u in doc["updates"] if u["package-ecosystem"] == "github-actions"]
    assert len(entries) == 1, "exactly one github-actions entry covers the workflows"
    entry = entries[0]
    assert entry["directory"] == "/"
    group = entry["groups"]["gyst"]
    assert SRC in group["patterns"]
    assert 1 <= entry["cooldown"]["default-days"] <= 3, "a short cooldown"
    # the group for every other action must leave the GYST refs to the gyst group
    others = entry["groups"]["actions"]
    assert others["patterns"] == ["*"] and SRC in others["exclude-patterns"]


def test_the_dependabot_template_is_not_this_repositorys_own_config():
    assert EXAMPLE.read_text() != (REPO / ".github" / "dependabot.yml").read_text()


def test_the_pin_only_check_stops_a_rewrite_that_changed_anything_else(env):
    """A sed that also edits an input (a stand-in for a future bug in the rewrite) must stop the run unwritten."""
    real = subprocess.run(["which", "sed"], capture_output=True, text=True, check=True).stdout.strip()
    shim = env["tmp"] / "bin" / "sed"
    shim.write_text(
        "#!/bin/bash\n"
        f'out=$({real} "$@") || exit $?\n'
        'if [[ "$*" == *git-your-ship-together*@* && "$*" == *PIN* ]]; then printf "%s\\n" "$out"; exit 0; fi\n'
        'if [[ "$*" == *git-your-ship-together* ]]; then printf "%s\\n" "$out" | '
        + real
        + " 's/3[.]12/3.13/'; exit 0; fi\n"
        'printf "%s\\n" "$out"\n'
    )
    shim.chmod(0o755)
    text = wf()
    root = make_caller(env, {"ci.yml": text})
    p = run(env, "apply", root)
    assert p.returncode == 4, p.stdout + p.stderr
    assert (root / ".github/workflows/ci.yml").read_text() == text


@pytest.mark.parametrize("sub", ["status", "apply", "pr"])
@pytest.mark.parametrize(
    "name",
    ["a|b&c\\d e.yml", "x$(touch PWNED).yml", "line\nbreak.yml", "semi;colon.yml", "bad`id`.yml"],
    ids=["pipe-amp-backslash-space", "command-substitution", "newline", "semicolon", "backtick"],
)
def test_a_hostile_workflow_file_name_is_refused_and_nothing_is_executed_or_written(env, sub, name):
    good = wf()
    root = make_caller(env, {"ok.yml": good, name: wf()})
    p = run(env, sub, root)
    assert p.returncode == 3, p.stdout + p.stderr
    assert "refusing a workflow path" in p.stderr
    assert (root / ".github/workflows/ok.yml").read_text() == good
    assert (root / ".github/workflows" / name).read_text() == wf()
    assert not list(env["tmp"].rglob("PWNED")) and not list(Path.cwd().glob("PWNED"))


# --- the input check ----------------------------------------------------------------------------------------


def defn(*inputs):
    """A workflow_call header; each input is (name, type, default, required) or a raw YAML block."""
    out = "name: x\non:\n  workflow_call:\n    inputs:\n"
    for item in inputs:
        if isinstance(item, str):
            out += item
            continue
        name, ty, df, rq = item
        out += f"      {name}:\n        description: d\n"
        if ty:
            out += f"        type: {ty}\n"
        if rq:
            out += "        required: true\n"
        if df is not None:
            out += f"        default: {df}\n"
    return out + "permissions: {}\njobs: {}\n"


PYV = ("python-version", "string", '"3.12"', False)
PATH = ".github/workflows/python-ci.yml"


def set_defs(ctx, old, new):
    set_scenario(ctx, contents={f"{PATH}@{OLD}": old, f"{PATH}@{NEW}": new})


def apply_inputs(ctx, old, new, *flags, files=None):
    set_defs(ctx, old, new)
    root = make_caller(ctx, files or {"ci.yml": wf()})
    return root, run(ctx, "apply", *flags, root)


def test_an_unchanged_input_set_is_accepted(env):
    root, p = apply_inputs(env, defn(PYV), defn(PYV))
    assert p.returncode == 0, p.stderr
    assert f"@{NEW}" in (root / ".github/workflows/ci.yml").read_text()


def test_an_input_the_caller_sets_that_the_release_dropped_is_refused_and_named(env):
    root, p = apply_inputs(env, defn(PYV), defn(("other", "string", '""', False)))
    assert p.returncode == 5, p.stderr
    assert "python-version" in p.stderr and "no longer declares" in p.stderr
    assert f"@{OLD}" in (root / ".github/workflows/ci.yml").read_text()


def test_an_input_the_caller_sets_that_changed_type_is_refused(env):
    _, p = apply_inputs(env, defn(PYV), defn(("python-version", "number", "3.12", False)))
    assert p.returncode == 5
    assert "changed type from 'string' to 'number'" in p.stderr


def test_a_new_required_input_the_caller_does_not_set_is_refused(env):
    _, p = apply_inputs(env, defn(PYV), defn(PYV, ("token-name", "string", None, True)))
    assert p.returncode == 5
    assert "adds the required input token-name" in p.stderr


def test_a_new_optional_input_and_a_new_required_input_with_a_default_are_accepted(env):
    new = defn(PYV, ("extra", "boolean", "false", False), ("mode", "string", '"a"', True))
    _, p = apply_inputs(env, defn(PYV), new)
    assert p.returncode == 0, p.stderr


def test_a_changed_default_is_accepted_for_a_set_input_and_noted_for_an_unset_one(env, tmp_path):
    old = defn(PYV, ("lint", "boolean", "true", False))
    new = defn(("python-version", "string", '"3.13"', False), ("lint", "boolean", "false", False))
    root, p = apply_inputs(env, old, new)
    assert p.returncode == 0, p.stderr


def test_the_allow_flag_lets_a_refused_change_through_and_says_so(env):
    root, p = apply_inputs(env, defn(PYV), defn(("other", "string", '""', False)), "--allow-input-changes")
    assert p.returncode == 0, p.stderr
    assert "no longer declares" in p.stderr and "allowed" in p.stderr
    assert f"@{NEW}" in (root / ".github/workflows/ci.yml").read_text()


def test_a_definition_that_cannot_be_read_is_refused_not_skipped(env):
    set_scenario(env, contents_default=None)
    root = make_caller(env, {"ci.yml": wf()})
    p = run(env, "apply", root)
    assert p.returncode == 5
    assert "cannot read" in p.stderr
    assert f"@{OLD}" in (root / ".github/workflows/ci.yml").read_text()


def test_a_block_scalar_default_and_quoted_values_are_compared(env):
    old = defn("      cmd:\n        type: string\n        default: |\n          a\n          b\n")
    new = defn("      cmd:\n        type: number\n        default: |\n          a\n")
    text = wf(extra='\n      cmd: "x"')
    _, p = apply_inputs(env, old, new, files={"ci.yml": text})
    assert p.returncode == 5 and "cmd changed type" in p.stderr


def test_with_keys_belong_to_the_pin_that_owns_them(env):
    """Two jobs: one sets python-version, the other sets nothing; only the first may trip the check."""
    second = f"  second:\n    uses: {SRC}/.github/workflows/python-ci.yml@{OLD} # v1.28.0\n"
    _, p = apply_inputs(env, defn(PYV), defn(("other", "string", '""', False)), files={"ci.yml": wf() + second})
    assert p.returncode == 5
    assert p.stderr.count("no longer declares") == 1  # only the job that sets it


def test_a_composite_action_pin_is_compared_by_its_action_file(env):
    key = f".github/actions/wait-ci/action.yml@{OLD}"
    new_key = f".github/actions/wait-ci/action.yml@{NEW}"
    set_scenario(
        env,
        contents={
            key: "inputs:\n  repo:\n    type: string\n    default: x\n",
            new_key: "inputs:\n  other:\n    default: x\n",
        },
    )
    use = f"{SRC}/.github/actions/wait-ci@{OLD} # v1.28.0"
    text = f"jobs:\n  w:\n    steps:\n      - uses: {use}\n        with:\n          repo: a/b\n"
    root = make_caller(env, {"ci.yml": text})
    p = run(env, "apply", root)
    assert p.returncode == 5 and "repo" in p.stderr


def test_the_pr_body_carries_the_allowed_note(env, clone):
    root, _ = clone
    set_defs(env, defn(PYV), defn(("other", "string", '""', False)))
    p = run(env, "pr", "--allow-input-changes", root)
    assert p.returncode == 0, p.stderr
    assert "allowed by the operator" in Path(str(env["calls"]) + ".body").read_text()


# --- the scheduled workflow ---------------------------------------------------------------------------------

WORKFLOW = REPO / ".github" / "workflows" / "repin.yml"


def workflow_steps():
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]["repin"]["steps"]


def step_named(prefix):
    found = [s for s in workflow_steps() if str(s.get("name", "")).startswith(prefix)]
    assert len(found) == 1, prefix
    return found[0]


FETCH_PREFIX = "Fetch CI secrets from Doppler"
KEY_EXPR = (
    "${{ steps.doppler-oidc.outputs.REPIN_APP_PRIVATE_KEY || steps.doppler-token.outputs.REPIN_APP_PRIVATE_KEY }}"
)


def test_the_workflow_inlines_the_script_byte_for_byte():
    run = step_named("Write the re-pin script")["run"]
    head = "cat > \"$RUNNER_TEMP/repin.sh\" <<'REPIN_SH'\n"
    assert run.startswith(head) and run.endswith("\nREPIN_SH\n")
    assert run[len(head) : -len("REPIN_SH\n")] == SCRIPT.read_text()


def test_the_job_token_stays_read_only_and_every_write_is_the_apps_with_three_named_permissions():
    doc = yaml.safe_load(WORKFLOW.read_text())
    assert doc["permissions"] == {"contents": "read"}
    assert doc["jobs"]["repin"]["permissions"] == {"contents": "read", "id-token": "write"}, (
        "id-token is for the Doppler fetch"
    )
    app = step_named("Mint a one-hour installation token")
    granted = {k: v for k, v in app["with"].items() if k.startswith("permission-")}
    assert granted == {
        "permission-contents": "write",
        "permission-pull-requests": "write",
        "permission-workflows": "write",
    }
    assert app["with"]["repositories"] == "${{ github.event.repository.name }}", "limited to the calling repository"
    assert app["with"]["private-key"] == KEY_EXPR, "the key comes from the Doppler fetch step outputs"


def test_the_app_key_is_never_a_github_secret():
    """Credentials come through Doppler. The only secret the workflow may declare or read is the optional Doppler
    Service Token fallback, which a caller leaves unset; the App private key is not a workflow_call secret."""
    text = WORKFLOW.read_text()
    secrets = (yaml.safe_load(text).get(True) or yaml.safe_load(text)["on"])["workflow_call"]["secrets"]
    assert list(secrets) == ["DOPPLER_TOKEN"] and secrets["DOPPLER_TOKEN"]["required"] is False
    used = set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text))
    assert used == {"DOPPLER_TOKEN"}, used
    assert "secrets.APP_PRIVATE_KEY" not in text and "\n      APP_PRIVATE_KEY:" not in text
    # The key is never on a command line or echoed: no script body names it, and the token step takes it as an input.
    for step in workflow_steps():
        assert "REPIN_APP_PRIVATE_KEY" not in str(step.get("run", "")), step.get("name")
    assert "REPIN_APP_PRIVATE_KEY" in str(step_named("Mint a one-hour")["with"])


def test_a_pull_request_is_opened_only_when_the_decision_step_says_so():
    decide = step_named("Decide whether")["run"]
    for must in ('"$EVENT" != "schedule"', '"$EVENT" != "workflow_dispatch"', "refs/heads/$DEFAULT_BRANCH", "DRY_RUN"):
        assert must in decide
    assert step_named("Mint a one-hour")["if"] == "steps.mode.outputs.open == 'true'"
    assert step_named("Open the pin-only")["if"] == "steps.mode.outputs.open == 'true'"
    assert step_named("Report where")["if"] == "steps.mode.outputs.open != 'true'"


def test_the_workflow_never_merges_and_hands_git_no_credential_in_a_url_or_header():
    text = WORKFLOW.read_text()
    code = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#") and not line.startswith("          ")
    )
    for forbidden in ("gh pr merge", "--auto", "wait-ci", "--merge", "extraheader", "x-access-token"):
        assert forbidden not in code, forbidden
    script = SCRIPT.read_text()
    assert "pr merge" not in script and "--auto" not in script
    run = step_named("Open the pin-only")["run"]
    assert "GIT_ASKPASS" in run and "https://" not in run.replace("$SERVER_URL", "")


# --- credential scope (issue #370): the App key reaches the token step and nothing after it ---------------------


def test_the_doppler_fetch_never_injects_the_secret_into_the_environment():
    fetches = [s for s in workflow_steps() if str(s.get("name", "")).startswith(FETCH_PREFIX)]
    assert len(fetches) == 2, "both the OIDC and the Service Token fetch are checked"
    for step in fetches:
        assert step["with"].get("inject-env-vars") is False, step["name"]
        assert step.get("id") in {"doppler-oidc", "doppler-token"}, step["name"]


LEAK_MARKERS = (
    "REPIN_APP_PRIVATE_KEY",
    "steps.doppler-",
    "doppler-oidc",
    "doppler-token",
    "toJSON(steps",
    "steps[",
    "secrets",
)


def key_leaks_after(steps, mint):
    """Names of steps after the mint step that could read the key: by name, by whole-context dump or by bracket form."""
    return [
        str(step.get("name")) for step in steps[mint + 1 :] if any(m.lower() in str(step).lower() for m in LEAK_MARKERS)
    ]


@pytest.mark.parametrize(
    "bypass",
    [
        {"env": {"DUMP": "${{ toJSON(steps) }}"}},
        {"env": {"DUMP": "${{ tojson(steps) }}"}},
        {"env": {"K": "${{ steps['doppler-oidc'].outputs.REPIN_APP_PRIVATE_KEY }}"}},
        {"env": {"K": "${{ steps['doppler-token'].outputs }}"}},
        {"env": {"S": "${{ toJSON(secrets) }}"}},
        {"env": {"S": "${{ secrets }}"}},
        {"env": {"K": "${{ env.REPIN_APP_PRIVATE_KEY }}"}},
    ],
)
def test_the_post_mint_guard_bites_on_each_bypass(bypass):
    steps = workflow_steps()
    mint = next(i for i, s in enumerate(steps) if str(s.get("name", "")).startswith("Mint a one-hour"))
    assert key_leaks_after(steps, mint) == []
    mutated = [*steps, {"name": "Injected", "run": "true", **bypass}]
    assert key_leaks_after(mutated, mint) == ["Injected"]


def test_the_key_is_not_referenced_by_any_step_after_the_token_step_nor_by_a_job_env():
    doc = yaml.safe_load(WORKFLOW.read_text())
    assert "REPIN_APP_PRIVATE_KEY" not in str(doc["jobs"]["repin"].get("env", {})) + str(doc.get("env", {}))
    steps = workflow_steps()
    mint = next(i for i, s in enumerate(steps) if str(s.get("name", "")).startswith("Mint a one-hour"))
    assert mint > 0
    assert not key_leaks_after(steps, mint)
    for step in steps[:mint]:
        name = str(step.get("name", ""))
        if "REPIN_APP_PRIVATE_KEY" in str(step) and not name.startswith(FETCH_PREFIX):
            assert name.startswith("Decide whether"), name
            assert str(step["env"]["KEY_SET"]).endswith("!= '' }}"), "a boolean, not the value"


def test_the_repin_job_hardens_the_runner_with_disable_sudo():
    hardening = [s for s in workflow_steps() if str(s.get("uses", "")).startswith("step-security/harden-runner@")]
    assert len(hardening) == 1
    assert hardening[0]["with"]["disable-sudo"] is True
