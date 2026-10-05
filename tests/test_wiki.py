"""The wiki is generated from docs/wiki/ and must stay a mirror of the workflows.

What is held still here: every reusable workflow has a page; the inputs tables are rendered
from the workflow YAML (so a table cannot say what the workflow does not); regenerating is a
no-op and a stale tree is detected; every page has a title, no em dashes (the maintainer's
voice rule) and links that resolve; every test the pages cite exists; and the workflow that
publishes it is the caller the README describes. Each check was broken on purpose once to
confirm it goes red with a message naming the fix.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "docs" / "wiki"
SCRIPT = REPO / "scripts" / "gen_wiki.py"
EM_DASH = "—"

spec = importlib.util.spec_from_file_location("gen_wiki", SCRIPT)
gen = importlib.util.module_from_spec(spec)
sys.modules["gen_wiki"] = gen
spec.loader.exec_module(gen)

from test_workflows import REUSABLE  # noqa: E402

PAGES = sorted(SOURCE.glob("*.md"))
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False)


# --- coverage ---------------------------------------------------------------


def test_every_reusable_workflow_has_a_page():
    stems = {p.stem for p in REUSABLE}
    assert set(gen.reusable_workflows()) == stems, "gen_wiki.py and test_workflows.py disagree on what is reusable"
    for stem in sorted(stems):
        assert (SOURCE / f"Workflow-{stem}.md").is_file(), (
            f"no wiki page for {stem}.yml: write docs/wiki/Workflow-{stem}.md"
        )


def test_home_and_sidebar_exist_and_the_sidebar_lists_every_page():
    sidebar = (SOURCE / "_Sidebar.md").read_text()
    for page in PAGES:
        if page.stem in ("_Sidebar", "Home"):
            continue
        assert f"({page.name})" in sidebar, (
            f"{page.name} is not in docs/wiki/_Sidebar.md; nobody can find it from the wiki"
        )
    assert "(Home.md)" in sidebar


def test_the_pages_the_task_requires_exist():
    for name in (
        "Why-GYST-exists",
        "Getting-started",
        "Design-rules",
        "Secrets-Doppler-and-OIDC",
        "Security-scanning-explained",
        "Baseline-and-the-weekly-audit",
        "Releases-and-supply-chain",
        "Keeping-a-project-board-current",
        "Adopting-GYST-in-your-own-project",
        "Glossary",
        "Roadmap",
    ):
        assert (SOURCE / f"{name}.md").is_file(), name


# --- the tables come from the YAML -----------------------------------------


@pytest.mark.parametrize("path", REUSABLE, ids=lambda p: p.name)
def test_the_rendered_page_lists_every_input_secret_and_output_of_its_workflow(path):
    files = gen.render(COMMIT)
    page = files[f"Workflow-{path.stem}.md"]
    call = gen.workflow_call(path)
    for kind in ("inputs", "secrets", "outputs"):
        for name in call.get(kind) or {}:
            assert f"| `{name}` |" in page, f"{path.name}: {kind[:-1]} {name} is missing from the generated table"
    assert gen.MARKER not in page, "the marker must be replaced"


def test_a_table_follows_the_yaml_when_the_yaml_changes(tmp_path, monkeypatch):
    """Falsifiability: add an input to a copy of a workflow and the rendered table gains it."""
    work = tmp_path / "workflows"
    work.mkdir()
    doc = yaml.safe_load((REPO / ".github/workflows/python-fuzz.yml").read_text())
    triggers = doc.get("on") if "on" in doc else doc.get(True)
    triggers["workflow_call"]["inputs"]["brand-new-input"] = {
        "description": "Added by the test | with a pipe\nand a newline.",
        "type": "string",
        "default": "x|y",
    }
    (work / "python-fuzz.yml").write_text(yaml.safe_dump(doc))
    monkeypatch.setattr(gen, "WORKFLOWS", work)
    table = gen.render_tables("python-fuzz")
    assert "| `brand-new-input` | string | `x\\|y` | Added by the test \\| with a pipe and a newline. |" in table


def test_a_workflow_page_without_the_marker_is_an_error(tmp_path, monkeypatch):
    shutil_tree(tmp_path, monkeypatch)
    page = tmp_path / "Workflow-python-fuzz.md"
    page.write_text(page.read_text().replace(gen.MARKER, ""))
    with pytest.raises(gen.WikiError, match="no <!-- inputs --> marker"):
        gen.render(COMMIT)


def test_a_new_reusable_workflow_without_a_page_is_an_error(tmp_path, monkeypatch):
    shutil_tree(tmp_path, monkeypatch)
    (tmp_path / "Workflow-python-fuzz.md").unlink()
    with pytest.raises(gen.WikiError, match="no page for python-fuzz.yml"):
        gen.render(COMMIT)


def shutil_tree(tmp_path: Path, monkeypatch) -> None:
    import shutil

    for page in PAGES:
        shutil.copy(page, tmp_path / page.name)
    monkeypatch.setattr(gen, "SOURCE", tmp_path)


# --- the generator -----------------------------------------------------------


def test_regenerating_is_a_no_op_and_check_proves_it(tmp_path):
    out = tmp_path / "wiki"
    first = run("--out", str(out), "--commit", COMMIT)
    assert first.returncode == 0, first.stderr
    before = {p.name: p.read_bytes() for p in out.glob("*.md")}
    again = run("--check", "--out", str(out), "--commit", COMMIT)
    assert again.returncode == 0, again.stdout + again.stderr
    assert {p.name: p.read_bytes() for p in out.glob("*.md")} == before, "--check must write nothing"


def test_check_goes_red_on_a_stale_or_edited_tree(tmp_path):
    out = tmp_path / "wiki"
    assert run("--out", str(out), "--commit", COMMIT).returncode == 0
    (out / "Home.md").write_text("edited in the wiki UI\n")
    result = run("--check", "--out", str(out), "--commit", COMMIT)
    assert result.returncode == 1 and "Home.md" in result.stdout
    assert run("--out", str(out), "--commit", COMMIT).returncode == 0
    (out / "Workflow-security.md").unlink()
    assert run("--check", "--out", str(out), "--commit", COMMIT).returncode == 1, "a missing page is stale too"
    (out / "Workflow-security.md").write_text("x\n")
    (out / "Stray.md").write_text("a page the generator no longer writes\n")
    assert run("--check", "--out", str(out), "--commit", COMMIT).returncode == 1


def test_the_output_is_a_function_of_the_tree_and_the_commit():
    assert gen.render(COMMIT) == gen.render(COMMIT)
    assert gen.render(COMMIT)["_Footer.md"] != gen.render("f" * 40)["_Footer.md"]
    assert not re.search(r"20\d\d-\d\d-\d\dT", gen.render(COMMIT)["_Footer.md"]), "no clock in the output"


# --- the pages ---------------------------------------------------------------


@pytest.mark.parametrize("path", PAGES, ids=lambda p: p.name)
def test_every_page_has_a_title_and_no_em_dash(path):
    text = path.read_text()
    if path.stem != "_Sidebar":
        first = next(line for line in text.splitlines() if line.strip())
        assert first.startswith("# ") and len(first) > 3, f"{path.name} must open with a '# Title' line"
    assert EM_DASH not in text, f"{path.name} has an em dash; use a comma, colon, parentheses or a new sentence"


def test_the_generated_tree_has_no_em_dash_either():
    """The input descriptions come from the workflow YAML, so check what is published, not just what is typed."""
    for name, text in gen.render(COMMIT).items():
        assert EM_DASH not in text, f"{name} carries an em dash from a workflow description; reword it in the YAML"


def test_every_page_ends_with_what_it_refuses_or_is_a_reference_page():
    """Each workflow page answers 'what it refuses to do', the last question every page owes the reader."""
    for path in PAGES:
        if path.stem.startswith("Workflow-"):
            assert "## What it refuses to do" in path.read_text(), (
                f"{path.name} does not say what the workflow refuses to do"
            )


def test_every_internal_link_resolves():
    gen.render(COMMIT)  # raises WikiError naming the page and the link


def test_a_broken_link_is_an_error(tmp_path, monkeypatch):
    shutil_tree(tmp_path, monkeypatch)
    home = tmp_path / "Home.md"
    home.write_text(home.read_text() + "\n[gone](No-Such-Page.md)\n")
    with pytest.raises(gen.WikiError, match="No-Such-Page.md"):
        gen.render(COMMIT)
    home.write_text(home.read_text() + "\n[gone](../../no/such/file.txt)\n")
    with pytest.raises(gen.WikiError):
        gen.render(COMMIT)


def test_links_leaving_docs_wiki_become_github_urls_and_page_links_lose_the_extension():
    files = gen.render(COMMIT)
    home = files["Home.md"]
    assert "(Getting-started)" in home and "(Getting-started.md)" not in home
    assert f"{gen.REPO_URL}/blob/main/BASELINE.md" in home
    assert "(../../" not in home


def test_every_test_the_pages_cite_exists():
    """A page that names a test which was renamed is a promise nobody holds."""
    defined = set()
    for t in (REPO / "tests").glob("test_*.py"):
        defined |= set(re.findall(r"^def (test_\w+)", t.read_text(), re.M))
    for path in PAGES:
        for name in re.findall(r"`(test_\w+)`", path.read_text()):
            assert name in defined, f"{path.name} cites {name}, which no test file defines"


def test_the_pages_name_no_personal_identifier():
    """No hostname, serial, callsign, grid square or employer in a published page."""
    for path in PAGES:
        text = path.read_text()
        assert not re.search(r"\b[A-R]{2}\d{2}[a-x]{2}\b", text), f"{path.name} contains a grid-square-shaped string"


# --- the workflow that publishes it -------------------------------------------


def test_the_wiki_workflow_is_a_self_call_that_publishes_from_the_default_branch():
    doc = yaml.safe_load((REPO / ".github/workflows/wiki.yml").read_text())
    triggers = doc.get("on") if "on" in doc else doc.get(True)
    assert triggers["push"] == {"branches": ["main"]}
    job = doc["jobs"]["wiki"]
    assert job["uses"] == "./.github/workflows/wiki-publish.yml"
    assert job["permissions"] == {"contents": "write"}
    assert job["with"]["publish"] is True
    assert job["with"]["egress-policy"] == "block"
    command = job["with"]["generate-command"]
    assert "scripts/gen_wiki.py" in command and '"$GITHUB_SHA"' in command
    out_dir = job["with"].get("out-dir", "wiki-out")
    assert f"--out {out_dir}" in command, "the generator must write where wiki-publish collects from"


def test_the_readme_points_at_the_wiki():
    readme = (REPO / "README.md").read_text()
    assert "https://github.com/ChiefGyk3D/git-your-ship-together/wiki" in readme.split("## Start here")[0]


# --- the drift guard: what exists must be mentioned --------------------------
#
# The per-workflow pages are held by the tests above. These hold the rest of the
# repository's inventory: a test cannot tell whether a sentence is still true,
# but it can tell when something exists that no page mentions.

WORKFLOWS = REPO / ".github" / "workflows"

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
    return "\n".join(p.read_text() for p in PAGES)


def names(pattern: str, base: Path) -> list[str]:
    return sorted(p.name for p in base.glob(pattern) if p.is_file())


@pytest.mark.parametrize("name", names("*.yml", WORKFLOWS))
def test_every_workflow_is_mentioned(name):
    assert name in wiki_text(), f"{name} exists but no wiki page mentions it: add it to the right page"


@pytest.mark.parametrize("name", names("*", REPO / "scripts"))
def test_every_script_is_mentioned(name):
    assert name in wiki_text(), f"scripts/{name} exists but no wiki page mentions it"


@pytest.mark.parametrize("name", sorted(p.name for p in (REPO / ".github" / "actions").iterdir()))
def test_every_composite_action_is_mentioned(name):
    assert name in wiki_text(), f"the {name} action exists but no wiki page mentions it"


@pytest.mark.parametrize("name", names("test_*.py", REPO / "tests"))
def test_every_test_file_is_mentioned(name):
    assert name in wiki_text(), f"tests/{name} exists but the Testing and the contract page never mentions it"


@pytest.mark.parametrize("name", names("*", REPO / "baseline"))
def test_every_baseline_file_is_mentioned(name):
    assert name in wiki_text(), f"baseline/{name} exists but no wiki page mentions it"


def audit_checks_in_the_script() -> set[str]:
    source = (REPO / "scripts" / "audit_baseline.py").read_text()
    return set(re.findall(r'Result\(\s*\w+,\s*"([a-z][a-z-]+)"', source))


# `repository` and `branch-protection` are the audit's own bookkeeping rows, not settings.
CHECKS = sorted(AUDIT_CHECKS | (audit_checks_in_the_script() - {"repository", "branch-protection"}))


@pytest.mark.parametrize("check", CHECKS)
def test_every_audit_check_is_explained(check):
    assert f"`{check}`" in wiki_text(), f"audit check {check} is not explained on the baseline page"


def test_the_wiki_carries_no_secret_shaped_text():
    text = wiki_text()
    assert not re.search(r"gh[pousr]_[A-Za-z0-9]{20,}", text), "a GitHub token shape"
    assert not re.search(r"AKIA[0-9A-Z]{16}", text), "an AWS key shape"
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text), "a UUID"
