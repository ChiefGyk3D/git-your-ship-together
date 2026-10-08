"""Version and pin facts in the wiki are generated from git, never typed into a hand page.

On 2026-10-08 the hand pages still pinned v1.14.0 after v1.15.0 shipped, because no release step touched them.
Held still here: the placeholders render from a temp repository's tags (the newest tag by version, the commit
SHA peeled from an annotated tag, the date, the first-parent merges since); an escaped placeholder stays
literal; and no hand page under docs/wiki/ carries a literal 40-hex SHA or a `# vX.Y.Z` pin comment.
The bite was proved by putting one back in a scratch copy of Getting-started.md.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "docs" / "wiki"

spec = importlib.util.spec_from_file_location("gen_wiki", REPO / "scripts" / "gen_wiki.py")
gen = importlib.util.module_from_spec(spec)
sys.modules.setdefault("gen_wiki", gen)
spec.loader.exec_module(gen)

HEX40 = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{40}(?![0-9a-fA-F])")
PIN_COMMENT = re.compile(r"(?<!#)#\s*v\d+\.\d+\.\d+\b")

# Pages may name a pin literally only where the text is about the past, never as an example to copy.
# Keep this empty unless a real historical context needs it; each entry is "page name: why".
ALLOWED_LITERAL_PINS: dict[str, str] = {}


def git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    base = {
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null", "PATH": "/usr/bin:/bin:/usr/local/bin",
    }
    out = subprocess.run(["git", *args], cwd=repo, env={**base, **(env or {})}, capture_output=True, text=True, check=True)
    return out.stdout.strip()


def commit(repo: Path, message: str, date: str) -> str:
    (repo / "f.txt").write_text(message)
    git(repo, "add", "f.txt")
    git(repo, "commit", "-q", "-m", message, env={"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def tagged_repo(tmp_path, monkeypatch):
    """A repository with v1.9.0 (lightweight) and v1.10.0 (annotated), then two merges after v1.10.0."""
    repo = tmp_path / "r"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    commit(repo, "first", "2026-09-01T12:00:00+0000")
    git(repo, "tag", "v1.9.0")
    release = commit(repo, "second", "2026-10-02T12:00:00+0000")
    git(repo, "tag", "-a", "v1.10.0", "-m", "release")
    git(repo, "tag", "not-a-release")
    commit(repo, "dast: signed-in https (#131)", "2026-10-08T12:00:00+0000")
    commit(repo, "a change with no pull request number", "2026-10-08T13:00:00+0000")
    monkeypatch.setattr(gen, "REPO_ROOT", repo)
    return repo, release


def test_the_facts_come_from_the_newest_version_tag_and_its_commit(tagged_repo):
    repo, release = tagged_repo
    facts = gen.release_facts()
    assert facts["latest_release"] == "v1.10.0", "1.10.0 is newer than 1.9.0 (version order, not text order)"
    assert facts["latest_pin"] == release, "the pin is the commit, peeled from the annotated tag"
    assert facts["latest_pin"] != git(repo, "rev-parse", "v1.10.0"), "the tag object's own SHA is not a pin"
    assert facts["latest_release_date"] == "2026-10-02"


def test_unreleased_is_one_bullet_per_merge_since_the_tag_with_its_pr(tagged_repo):
    facts = gen.release_facts()
    lines = facts["unreleased"].splitlines()
    assert lines == [
        "- a change with no pull request number",
        f"- dast: signed-in https ([#131]({gen.REPO_URL}/pull/131))",
    ]


def test_unreleased_with_nothing_since_the_tag(tagged_repo):
    repo, _ = tagged_repo
    git(repo, "tag", "-a", "v1.11.0", "-m", "release")
    facts = gen.release_facts()
    assert facts["latest_release"] == "v1.11.0"
    assert facts["unreleased"] == "Nothing yet: `main` is at v1.11.0."


def test_placeholders_are_filled_and_an_escaped_one_is_literal(tagged_repo):
    facts = gen.release_facts()
    text = "uses: x/y.yml@{{latest_pin}} # {{latest_release}} ({{latest_release_date}})\nwrite \\{{latest_release}}\n{{unreleased}}"
    out = gen.fill_placeholders(text, facts)
    assert f"@{facts['latest_pin']} # v1.10.0 (2026-10-02)" in out
    assert "write {{latest_release}}" in out
    assert "- a change with no pull request number" in out


def test_no_reachable_release_tag_is_an_error_that_says_how_to_fix_it(tmp_path, monkeypatch):
    repo = tmp_path / "r"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    commit(repo, "only", "2026-09-01T12:00:00+0000")
    git(repo, "tag", "nightly")
    monkeypatch.setattr(gen, "REPO_ROOT", repo)
    with pytest.raises(gen.WikiError, match="fetch --tags"):
        gen.release_facts()


def test_a_tag_not_reachable_from_head_is_ignored(tagged_repo):
    repo, _ = tagged_repo
    git(repo, "checkout", "-q", "-b", "side", "v1.9.0")
    commit(repo, "side", "2026-10-09T12:00:00+0000")
    git(repo, "tag", "v9.9.9")
    git(repo, "checkout", "-q", "main")
    assert gen.release_facts()["latest_release"] == "v1.10.0"


# --- no hand page types a version fact ----------------------------------------


def literal_pins(text: str) -> list[str]:
    return HEX40.findall(text) + PIN_COMMENT.findall(text)


@pytest.mark.parametrize("path", sorted(SOURCE.glob("*.md")), ids=lambda p: p.name)
def test_no_hand_page_types_a_sha_or_a_pin_comment(path):
    if path.name in ALLOWED_LITERAL_PINS:
        pytest.skip(ALLOWED_LITERAL_PINS[path.name])
    found = literal_pins(path.read_text())
    assert not found, (
        f"{path.name} types {found[:3]}: a pin or a version-in-a-pin goes stale at the next release. "
        "Write {{latest_pin}} and # {{latest_release}} instead (see Maintaining-this-wiki)"
    )


def test_the_check_bites_on_a_typed_pin():
    """The same check, run on the stale text the pages had on 2026-10-08."""
    stale = "uses: o/r/.github/workflows/python-ci.yml@a5b834a6e03e0bf7187eeebfa84685498d73b139 # v1.14.0"
    assert len(literal_pins(stale)) == 2
    assert literal_pins("@{{latest_pin}} # {{latest_release}} since v1.10.0, the v1.3.x tag story") == []


def test_getting_started_uses_the_placeholders():
    text = (SOURCE / "Getting-started.md").read_text()
    assert "@{{latest_pin}} # {{latest_release}}" in text


def test_the_rendered_pin_example_is_the_real_latest_release_commit():
    """The generated Getting-started names a commit that exists and is the latest tag's."""
    files = gen.render("0" * 40)
    facts = gen.release_facts()
    assert f"@{facts['latest_pin']} # {facts['latest_release']}" in files["Getting-started.md"]
    assert "{{" not in files["Roadmap.md"].replace("${{", "")
    assert facts["latest_release"] in files["Home.md"]
