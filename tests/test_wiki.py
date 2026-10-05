"""The wiki is a mirror of wiki/, and these keep it true to the repository.

A test cannot tell whether a sentence is still correct, but it can tell when
something exists that the wiki never mentions, and when a link would 404. That
is what rots first: a new workflow nobody wrote up, a page renamed under its
links. So the repository's own inventory (workflows, scripts, audit checks,
tests, baseline files) is compared with the wiki's text, and the generator that
publishes it is run against the real pages and against broken ones.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
WIKI = REPO / "wiki"
WORKFLOWS = REPO / ".github" / "workflows"

spec = importlib.util.spec_from_file_location("gen_wiki", REPO / "scripts" / "gen_wiki.py")
gen_wiki = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_wiki)

# Audit checks that exist today; the regex below also finds any added later.
AUDIT_CHECKS = {
    "collaborators",
    "required-check",
    "pull-request-required",
    "history-protected",
    "auto-merge-enabled",
    "tag-ruleset",
    "doppler-identity",
    "workflows-pinned",
    "uses-shared-workflows",
    "dependabot-config",
    "dependabot-ecosystem",
    "workflow-token-read-only",
    "fork-pr-approval",
    "actions-allowlist",
    "secret-scanning",
    "push-protection",
    "dependabot-security-updates",
    "private-vulnerability-reporting",
    "risk-exceptions",
}


def wiki_text() -> str:
    return "\n".join(p.read_text() for p in sorted(WIKI.glob("*.md")))


def tracked(pattern: str, base: Path) -> list[str]:
    return sorted(p.name for p in base.glob(pattern) if p.is_file())


# --- the generator, on the real wiki ---------------------------------------


def test_the_wiki_builds_with_no_problems():
    assert gen_wiki.problems(WIKI) == []


def test_the_build_writes_every_page_and_stamps_the_commit(tmp_path):
    sha = "0123456789abcdef0123456789abcdef01234567"
    assert gen_wiki.build(tmp_path / "out", sha, WIKI) == []
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == sorted(p.name for p in WIKI.iterdir())
    footer = (tmp_path / "out" / "_Footer.md").read_text()
    assert "0123456" in footer and sha in footer and "{{" not in footer
    assert (tmp_path / "out" / "Home.md").read_text() == (WIKI / "Home.md").read_text(), "only the footer is rewritten"


def test_every_page_has_a_title_and_is_reachable_from_home_or_the_sidebar():
    for page in WIKI.glob("[!_]*.md"):
        first = page.read_text().lstrip().splitlines()[0]
        assert first.startswith("# "), f"{page.name} does not open with a level-one heading"
    assert (WIKI / "Home.md").is_file() and (WIKI / "_Sidebar.md").is_file() and (WIKI / "_Footer.md").is_file()


def test_the_wiki_carries_no_secret_shaped_text():
    text = wiki_text()
    assert not re.search(r"gh[pousr]_[A-Za-z0-9]{20,}", text), "a GitHub token shape"
    assert not re.search(r"AKIA[0-9A-Z]{16}", text), "an AWS key shape"
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text), "a UUID"


# --- the generator, on broken wikis ----------------------------------------


def make(tmp_path: Path, pages: dict[str, str]) -> Path:
    src = tmp_path / "src"
    src.mkdir(parents=True)
    for name, body in pages.items():
        (src / name).write_text(body)
    return src


GOOD = {
    "Home.md": "# Home\n\n[Other](Other) and [part](Other#a-heading)\n",
    "Other.md": "# Other\n\n## A heading\n\n[home](Home)\n",
    "_Sidebar.md": "* [Home](Home)\n* [Other](Other)\n",
}


def test_a_good_wiki_is_accepted(tmp_path):
    assert gen_wiki.problems(make(tmp_path, GOOD)) == []


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"Home.md": "# Home\n\n[x](Nowhere)\n"}, "names no page"),
        ({"Home.md": "# Home\n\n[x](Other#no-such-heading)\n"}, "no heading"),
        ({"Home.md": "# Home\n\n[x](#no-such-heading)\n"}, "no heading"),
        ({"_Sidebar.md": "* [Home](Home)\n"}, "not in _Sidebar.md"),
        ({"notes.txt": "x"}, "only Markdown"),
    ],
)
def test_a_broken_wiki_is_refused_with_the_reason(tmp_path, change, expected):
    errors = gen_wiki.problems(make(tmp_path, {**GOOD, **change}))
    assert any(expected in e for e in errors), errors


def test_a_wiki_without_home_or_with_a_subdirectory_is_refused(tmp_path):
    no_home = {k: v for k, v in GOOD.items() if k != "Home.md"}
    assert any("Home.md is missing" in e for e in gen_wiki.problems(make(tmp_path, no_home)))
    nested = make(tmp_path / "n", GOOD)
    (nested / "sub").mkdir()
    assert any("no subdirectories" in e for e in gen_wiki.problems(nested))


def test_links_in_code_are_not_checked_and_external_links_are_not_followed(tmp_path):
    body = "# Home\n\n`[x](Nowhere)`\n\n```\n[y](AlsoNowhere)\n```\n\n[ext](https://example.com/Nowhere)\n"
    assert gen_wiki.problems(make(tmp_path, {**GOOD, "Home.md": body})) == []


def test_a_refused_build_writes_nothing(tmp_path):
    src = make(tmp_path, {**GOOD, "Home.md": "# Home\n\n[x](Nowhere)\n"})
    assert gen_wiki.build(tmp_path / "out", "abc", src)
    assert not (tmp_path / "out").exists()


def test_the_anchor_rule_matches_githubs_for_the_headings_used_here():
    assert gen_wiki.slug("`CI green`") == "ci-green"
    assert gen_wiki.slug("Required review count is zero (on single-maintainer repositories)") == (
        "required-review-count-is-zero-on-single-maintainer-repositories"
    )
    assert gen_wiki.slug("1. Pin a commit, with the version in a comment") == (
        "1-pin-a-commit-with-the-version-in-a-comment"
    )


# --- the drift guard: what exists must be mentioned ------------------------


@pytest.mark.parametrize("name", tracked("*.yml", WORKFLOWS))
def test_every_workflow_is_mentioned(name):
    assert name in wiki_text(), f"{name} exists but no wiki page mentions it: add it to the right page"


@pytest.mark.parametrize("name", tracked("*", REPO / "scripts"))
def test_every_script_is_mentioned(name):
    assert name in wiki_text(), f"scripts/{name} exists but no wiki page mentions it"


@pytest.mark.parametrize("name", sorted(p.name for p in (REPO / ".github" / "actions").iterdir()))
def test_every_composite_action_is_mentioned(name):
    assert name in wiki_text(), f"the {name} action exists but no wiki page mentions it"


@pytest.mark.parametrize("name", tracked("test_*.py", REPO / "tests"))
def test_every_test_file_is_mentioned(name):
    assert name in wiki_text(), f"tests/{name} exists but the Testing and the Contract page never mentions it"


@pytest.mark.parametrize("name", tracked("*", REPO / "baseline"))
def test_every_baseline_file_is_mentioned(name):
    assert name in wiki_text(), f"baseline/{name} exists but no wiki page mentions it"


def audit_checks_in_the_script() -> set[str]:
    source = (REPO / "scripts" / "audit_baseline.py").read_text()
    return set(re.findall(r'Result\(\s*\w+,\s*"([a-z][a-z-]+)"', source))


# `repository` and `branch-protection` are the audit's own bookkeeping rows, not settings.
CHECKS = sorted(AUDIT_CHECKS | (audit_checks_in_the_script() - {"repository", "branch-protection"}))


@pytest.mark.parametrize("check", CHECKS)
def test_every_audit_check_is_explained(check):
    assert f"`{check}`" in wiki_text(), f"audit check {check} is not explained on the Repository Baseline page"


def test_every_reusable_workflow_is_in_the_catalog_and_the_architecture_map():
    reusable = []
    for p in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(p.read_text())
        if "workflow_call" in ((doc.get("on") or doc.get(True)) or {}):  # `on:` parses as True under YAML 1.1
            reusable.append(p.name)
    assert reusable, "no reusable workflow found: the check itself is broken"
    for page in ("Workflow-Catalog.md", "Architecture-Overview.md"):
        text = (WIKI / page).read_text()
        missing = [name for name in reusable if name not in text]
        assert not missing, f"{page} does not list {missing}"


# --- the publishing workflow ----------------------------------------------


def test_the_wiki_workflow_calls_the_publisher_and_generates_with_the_script():
    doc = yaml.safe_load((WORKFLOWS / "wiki.yml").read_text())
    triggers = doc.get("on") or doc.get(True)
    assert "pull_request" in triggers, "the generator must run on a pull request so a broken link fails review"
    assert "pull_request_target" not in triggers
    job = doc["jobs"]["wiki"]
    assert job["uses"].startswith("./.github/workflows/wiki-publish.yml")
    assert "scripts/gen_wiki.py" in job["with"]["generate-command"]
    assert '"$OUT_DIR"' in job["with"]["generate-command"] and '"$SOURCE_SHA"' in job["with"]["generate-command"]
    assert job["permissions"] == {"contents": "write"}
    assert doc["permissions"] == {"contents": "read"}
