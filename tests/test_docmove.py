"""docmove moves documentation inside a git repo; this is the check on it.

Every test builds a throwaway git repository in a temp directory (documentation
address ranges and example.com only) and runs the real script in a subprocess
with `python3 -I`, so exit codes and the "tree untouched on failure" promise are
what is asserted. The scanner tests call the module directly.

Review focus covered here: a link inside a fenced block, inline code or an
indented code block is never rewritten; a real link (including a reference
definition continued over two lines, and a wiki-style [[Name]] link) always is.
"""

from __future__ import annotations

import collections
import importlib.util
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "docmove.py"
SPLITCHECK = REPO / "scripts" / "splitcheck.py"

spec = importlib.util.spec_from_file_location("docmove", TOOL)
docmove = importlib.util.module_from_spec(spec)
sys.modules["docmove"] = docmove
spec.loader.exec_module(docmove)

HEADER = "repo_path,section,page,action,order"

GIT_ENV = {
    **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}


def sh(*args, cwd=None):
    r = subprocess.run(args, cwd=cwd, capture_output=True, env=GIT_ENV)
    if r.returncode:
        raise RuntimeError(f"{args}: {r.stderr!r}")
    return r.stdout


def git(repo, *args):
    return sh("git", "-C", str(repo), *args)


def make_repo(base: Path, files, symlinks=None, ignored=None, gitignore=None):
    """A throwaway repository with one commit. `ignored` files exist on disk but are untracked and ignored."""
    repo = base / "work"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.name", "test")
    git(repo, "config", "user.email", "test@example.com")
    git(repo, "config", "commit.gpgsign", "false")
    for p, data in files.items():
        full = repo / p
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(data.encode() if isinstance(data, str) else data)
    for p, target in (symlinks or {}).items():
        full = repo / p
        full.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, full)
    if gitignore:
        (repo / ".gitignore").write_text(gitignore)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "init")
    for p, data in (ignored or {}).items():
        full = repo / p
        full.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, tuple):  # ("symlink", target)
            os.symlink(data[1], full)
        else:
            full.write_text(data)
    return repo


def read(repo, p):
    return (Path(repo) / p).read_bytes()


def text(repo, p):
    return read(repo, p).decode()


def row(src, page="", action="move", order="", section="", notes=None):
    base = f"{src},{section},{page},{action},{order}"
    return base if notes is None else f'{base},"{notes}"'


NOTES_HEADER = HEADER + ",notes"


def run_tool(repo, rows, *extra, header=HEADER, raw=None, mapfile=None, env=None, timeout=None):
    mp = Path(repo).parent / "map.csv" if mapfile is None else Path(repo) / mapfile
    mp.parent.mkdir(parents=True, exist_ok=True)
    mp.write_bytes(raw if raw is not None else (header + "\n" + "\n".join(rows) + ("\n" if rows else "")).encode())
    if mapfile is not None:  # a map kept in the repo is tracked, as the migration keeps it
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "plan files")
    r = subprocess.run(
        [sys.executable, "-I", str(TOOL), "--repo", str(repo), "--map", str(mp), *extra],
        capture_output=True,
        env=env,
        timeout=timeout,
    )
    return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")


def porcelain(repo):
    return git(repo, "status", "--porcelain").decode()


def snapshot(repo):
    """Every path on disk (outside .git) with its bytes: proves a failed run touched nothing."""
    snap = {}
    root = Path(repo)
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in fns:
            p = Path(dp) / fn
            rel = p.relative_to(root).as_posix()
            snap[rel] = os.readlink(p) if p.is_symlink() else p.read_bytes()
    return snap, git(repo, "ls-files", "-s")


BASE = {
    "README.md": "# Proj\nSee [setup](docs/setup.md#install) and [arch](docs/arch/design.md?plain=1#x).\n"
    "![diagram](docs/img/d.png)\n",
    "docs/setup.md": "# Setup\n"
    + "".join(f"Plain prose line {i} about installing the thing.\n" for i in range(12))
    + "## Install\nBack to [readme](../README.md) and [code](../src/main.py) and [design](arch/design.md).\n",
    "docs/arch/design.md": '# Design\nSee [setup](../setup.md#install "Setup title") and <../setup.md> '
    "and [s](<../setup.md#install>).\n",
    "docs/img/d.png": b"\x89PNG\x00\x01binary",
    "src/main.py": "# docs live in docs/setup.md\nPATH = 'docs/setup.md'\n",
    "scripts/run.sh": "#!/bin/sh\ncat docs/setup.md\ncat mydocs/docs/setup.md\n"
    "cat docs/setup.md.bak\ncat ./docs/setup.md\n",
    ".github/workflows/ci.yml": "paths:\n  - docs/setup.md\n",
}


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path, BASE)


# --------------------------------------------------------------------------- scanner
def spans(t):
    return [t[r.start : r.end] for r in docmove.scan(t)]


def test_scan_inline_forms():
    t = "[a](x.md) ![i](p.png \"T\") [b](<sp ace.md> 't') [c](y.md#h?q=1) [d](z.md (title)) [e](w(1).md)"
    assert spans(t) == ["x.md", "p.png", "sp ace.md", "y.md#h?q=1", "z.md", "w(1).md"]


def test_scan_fenced_tilde_and_unclosed():
    t = "[a](1.md)\n```\n[b](2.md)\n```\n~~~~\n[c](3.md)\n~~~~\n[d](4.md)\n````\n[e](5.md)\n"
    assert spans(t) == ["1.md", "4.md"]


def test_scan_fence_nested_in_list_and_quote():
    t = "1. x\n   ```sh\n   [b](2.md)\n   ```\n> ```\n> [c](3.md)\n> ```\n[d](4.md)\n"
    assert spans(t) == ["4.md"]


def test_scan_inline_code():
    t = "`[a](1.md)` and ``x ` [b](2.md) ``, [c](3.md) `unclosed [d](4.md)"
    assert spans(t) == ["3.md", "4.md"]


def test_scan_reference_definitions():
    t = '[a][r1] [b]\n\n[r1]: docs/a.md "T"\n[b]: <docs/b c.md>\n[^1]: footnote.md\n'
    assert spans(t) == ["docs/a.md", "docs/b c.md"]


def test_scan_html_attrs():
    t = '<img src="a.png" alt="x"> <a href=\'b.md\'>t</a> <http://x.example/y.md>'
    assert spans(t) == ["a.png", "b.md"]


def test_scan_escaped_and_unbalanced():
    t = r"\[a](1.md) [b]\(2.md) a](3.md) [c](4.md"
    assert spans(t) == []


def test_scan_crlf():
    t = "[a](1.md)\r\n```\r\n[b](2.md)\r\n```\r\n[c](3.md)\r\n[r]: 4.md\r\n"
    assert spans(t) == ["1.md", "3.md", "4.md"]


def test_scan_linear_time():
    worst = [
        "[](" * 60000,
        "](" * 100000,
        "`a" * 100000 + "``" * 50000,
        "[" * 100000 + "](" * 50000,
        "[a](" + "<" * 100000,
        '[a](x "' * 30000,
        "<a " * 60000,
        "[x]: <" * 30000,
        "[x]:\n" * 60000,
        "[[" * 100000,
        '[x]: a\n"t\n' * 30000,
    ]
    t0 = time.time()
    for w in worst:
        docmove.scan(w)
    assert time.time() - t0 < 8


def test_scan_indented_code_block_is_not_scanned():
    # Review focus 2: the spike rewrote links in 4-space code blocks.
    t = "[a](1.md)\n\n    [b](2.md)\n    [c](3.md)\n\n[d](4.md)\n\n\t[e](5.md)\n"
    assert spans(t) == ["1.md", "4.md"]


def test_scan_indented_line_continuing_a_paragraph_is_text():
    t = "para start\n    [a](1.md) continues\n"
    assert spans(t) == ["1.md"]


def test_scan_indented_after_heading_is_code_after_list_is_text():
    assert spans("# H [a](1.md)\n    [b](2.md)\n") == ["1.md"]
    # a paragraph inside a list item is indented relative to the marker, not code
    assert spans("- item\n\n    [a](1.md)\n") == ["1.md"]
    assert spans("1. item\n\n   [a](1.md)\n\n        [b](2.md)\n") == ["1.md"]


def test_scan_indented_code_inside_blockquote():
    assert spans("> [a](1.md)\n>\n>     [b](2.md)\n") == ["1.md"]


def test_scan_reference_definition_continued_over_two_lines():
    # Review focus 2: destination on the next line.
    t = "[r]:\n    docs/a.md\n\n[s]: <docs/b c.md>\n  'Title'\n\n[t]: docs/c.md\n  (T)\n"
    assert spans(t) == ["docs/a.md", "docs/b c.md", "docs/c.md"]


def test_scan_reference_definition_title_on_second_line_is_consumed():
    t = '[r]: docs/a.md\n  "Title with [x](not-a-link.md)"\n[z](k.md)\n'
    assert spans(t) == ["docs/a.md", "k.md"]
    t = "[r]: docs/a.md 'multi\nline title'\n[z](k.md)\n"
    assert spans(t) == ["docs/a.md", "k.md"]


def test_scan_wiki_links():
    refs = docmove.scan("a [[Page-Name]] and [[text|Other Page#h]] and `[[no]]` and [x](y.md)\n")
    assert [
        (r.kind, "a [[Page-Name]] and [[text|Other Page#h]] and `[[no]]` and [x](y.md)\n"[r.start : r.end])
        for r in refs
    ] == [
        ("wiki", "Page-Name"),
        ("wiki", "text|Other Page#h"),
        ("link", "y.md"),
    ]


# --------------------------------------------------------------------------- map format
def test_map_extra_column_is_exit_64(repo):
    before = snapshot(repo)
    rc, _, err = run_tool(repo, [], raw=(HEADER + ",notes,surprise\ndocs/setup.md,,Setup.md,move,,n,x\n").encode())
    assert rc == 64, err
    assert snapshot(repo) == before


def test_map_notes_column_is_accepted_and_ignored(repo):
    rc, out, err = run_tool(
        repo, [], raw=(HEADER + ',notes\ndocs/setup.md,,Setup.md,move,,"ledger: a, b ""quoted"""\n').encode()
    )
    assert rc == 0, (out, err)
    assert (repo / "Setup.md").exists()


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"repo_path,section,page,action,order\n",
        b"repo_path,page\ndocs/setup.md,Foo.md\n",
        b"repo_path,new_path,action,order\ndocs/setup.md,Foo.md,move,\n",
        b"repo_path,section,page,action,order\ndocs/setup.md,,Foo.md,move,,extra\n",
        b"repo_path,section,page,action,order\n\xff\xfe,,Foo.md,move,\n",
        b'repo_path,section,page,action,order\n"docs/setup.md,,Foo.md,move,\n',
        b"repo_path,section,page,action,order\x00\n",
        b"repo_path,section,page,action,order,repo_path\n",
    ],
)
def test_malformed_map_is_exit_64_and_tree_untouched(repo, raw):
    before = snapshot(repo)
    rc, _, err = run_tool(repo, [], raw=raw)
    assert rc == 64, err
    assert snapshot(repo) == before


# --------------------------------------------------------------------------- validation
def fails(repo, rows, *extra, code=2, **kw):
    before = snapshot(repo)
    rc, out, err = run_tool(repo, rows, *extra, **kw)
    assert rc == code, (out, err)
    assert porcelain(repo) == ""
    assert snapshot(repo) == before  # nothing moved, nothing written
    return err


def test_unknown_action(repo):
    fails(repo, [row("docs/setup.md", "Foo.md", "delete")])


def test_traversal_and_absolute_paths(repo):
    fails(repo, [row("../etc/passwd", "Foo.md")])
    fails(repo, [row("docs/../docs/setup.md", "Foo.md")])
    fails(repo, [row("docs/setup.md", "../Foo.md")])
    fails(repo, [row("docs/setup.md", "..")])
    fails(repo, [row("docs/setup.md", "a/../../Foo.md")])
    fails(repo, [row("/docs/setup.md", "Foo.md")])
    fails(repo, [row("docs/setup.md", "/tmp/Foo.md")])
    fails(repo, [row("docs\\setup.md", "Foo.md")])
    fails(repo, [row("docs/./setup.md", "Foo.md")])
    fails(repo, [row("docs/setup.md", "Foo.md")], "--report", "../report.md")
    fails(repo, [row("docs/setup.md", "Foo.md")], "--report", "/tmp/report.md")


def test_symlinked_source(tmp_path):
    repo = make_repo(tmp_path, BASE, symlinks={"docs/link.md": "setup.md"})
    err = fails(repo, [row("docs/link.md", "Link.md")])
    assert "symlink" in err


def test_symlink_pointing_at_source(tmp_path):
    repo = make_repo(tmp_path, BASE, symlinks={"docs/link.md": "setup.md"})
    err = fails(repo, [row("docs/setup.md", "Setup.md")])
    assert "symlink" in err


def test_symlink_pointing_outside_the_repo_as_source(tmp_path):
    repo = make_repo(tmp_path, BASE, symlinks={"docs/ext.md": "/etc/hostname"})
    fails(repo, [row("docs/ext.md", "Ext.md")])


def test_destination_is_an_ignored_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    repo = make_repo(tmp_path, BASE, gitignore="Foo.md\nwiki\n", ignored={"Foo.md": ("symlink", str(outside / "t.md"))})
    fails(repo, [row("docs/setup.md", "Foo.md")])
    assert not (outside / "t.md").exists()


def test_subfolder_is_an_ignored_symlink_to_elsewhere(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    repo = make_repo(tmp_path, BASE, gitignore="wiki\n", ignored={"wiki": ("symlink", str(outside))})
    fails(repo, [row("docs/setup.md", "Setup.md")], "--subfolder", "wiki")
    assert list(outside.iterdir()) == []


def test_destination_outside_subfolder(repo):
    fails(repo, [row("docs/setup.md", "other/Setup.md")], "--subfolder", "wiki")
    fails(repo, [row("docs/setup.md", "wiki/deep/Setup.md")], "--subfolder", "wiki")
    fails(repo, [row("docs/setup.md", "wiki2/Setup.md")], "--subfolder", "wiki")
    fails(repo, [row("docs/setup.md", "wiki/Setup.md")])  # no --subfolder given
    fails(repo, [row("docs/setup.md", "Setup.md")], "--subfolder", "../wiki")


def test_untracked_source_exit_2_even_when_ignored(tmp_path):
    repo = make_repo(tmp_path, BASE, gitignore="docs/new.md\n", ignored={"docs/new.md": "x\n"})
    err = fails(repo, [row("docs/new.md", "New.md")])
    assert "not a tracked file" in err


def test_untracked_dirty_tree_fails_closed(repo):
    (repo / "docs" / "new.md").write_text("x\n")
    rc, _, err = run_tool(repo, [row("docs/new.md", "New.md")])
    assert rc == 2
    assert (repo / "docs" / "new.md").read_text() == "x\n"


def test_missing_source_and_directory_source(repo):
    fails(repo, [row("docs/nope.md", "Nope.md")])
    fails(repo, [row("docs", "Docs.md")])


def test_case_colliding_destinations_move_nothing(repo):
    err = fails(repo, [row("docs/setup.md", "Foo.md"), row("docs/arch/design.md", "foo.md")])
    assert "case" in err.lower()


def test_destination_collides_with_tracked_file_case_insensitively(repo):
    fails(repo, [row("docs/setup.md", "readme.md")])
    fails(repo, [row("docs/setup.md", "README.md")])


def test_two_sources_one_destination_without_merge(repo):
    fails(repo, [row("docs/setup.md", "Foo.md"), row("docs/arch/design.md", "Foo.md")])


def test_duplicate_source_row(repo):
    fails(repo, [row("docs/setup.md", "Foo.md"), row("docs/setup.md", "Bar.md")])
    fails(repo, [row("docs/setup.md", "Foo.md"), row("docs/setup.md", "Foo.md")])
    err = fails(
        repo, [row("docs/setup.md", "M.md", "merge-into", "1"), row("docs/setup.md", "M.md", "merge-into", "2")]
    )
    assert "duplicate source" in err


def test_destination_not_a_flat_name(repo):
    fails(repo, [row("docs/setup.md", "Foo bar.md")])
    fails(repo, [row("docs/setup.md", "Foo.txt")])
    fails(repo, [row("docs/setup.md", ".Foo.md")])
    fails(repo, [row("docs/setup.md", "Foo|Bar.md")])


def test_report_collision(repo):
    fails(repo, [row("docs/setup.md", "Foo.md")], "--report", "foo.md")


def test_merge_needs_unique_integer_order(repo):
    fails(repo, [row("docs/setup.md", "M.md", "merge-into"), row("docs/arch/design.md", "M.md", "merge-into")])
    fails(
        repo,
        [row("docs/setup.md", "M.md", "merge-into", "1"), row("docs/arch/design.md", "M.md", "merge-into", "1")],
    )
    fails(repo, [row("docs/setup.md", "M.md", "merge-into", "1"), row("docs/arch/design.md", "M.md", "move", "2")])


def test_keep_must_not_rename(repo):
    fails(repo, [row("docs/setup.md", "Foo.md", "keep")])


def test_only_markdown_can_be_merged(repo):
    fails(repo, [row("docs/img/d.png", "M.md", "merge-into", "1")])


# --------------------------------------------------------------------------- move
def test_move_rewrites_links_and_keeps_history(repo):
    rows = [
        row("docs/setup.md", "Setup.md"),
        row("docs/arch/design.md", "Design.md"),
        row("docs/img/d.png", "Diagram.png"),
    ]
    rc, out, err = run_tool(repo, rows)
    assert rc == 0, (out, err)
    st = porcelain(repo)
    assert "R  docs/setup.md -> Setup.md" in st
    assert "R  docs/img/d.png -> Diagram.png" in st
    assert read(repo, "Diagram.png") == BASE["docs/img/d.png"]
    readme = text(repo, "README.md")
    assert "[setup](Setup.md#install)" in readme
    assert "[arch](Design.md?plain=1#x)" in readme
    assert "![diagram](Diagram.png)" in readme
    setup = text(repo, "Setup.md")
    assert "[readme](README.md)" in setup and "[code](src/main.py)" in setup and "[design](Design.md)" in setup
    assert '[setup](Setup.md#install "Setup title")' in text(repo, "Design.md")
    assert "[s](<Setup.md#install>)" in text(repo, "Design.md")
    rep = text(repo, "where-did-it-go.md")
    assert "docs/setup.md" in rep and "Files in: 3. Accounted for: 3" in rep
    for line in st.splitlines():  # staged, nothing unstaged or untracked
        assert line[1] == " ", line


def test_subfolder_places_bare_names_and_accepts_prefixed(repo):
    rc, out, err = run_tool(
        repo, [row("docs/setup.md", "Setup.md"), row("docs/arch/design.md", "wiki/Design.md")], "--subfolder", "wiki"
    )
    assert rc == 0, (out, err)
    assert (repo / "wiki" / "Setup.md").exists() and (repo / "wiki" / "Design.md").exists()
    assert "(wiki/Setup.md#install)" in text(repo, "README.md")
    assert (repo / "wiki" / "where-did-it-go.md").exists()
    assert "[readme](../README.md)" in text(repo, "wiki/Setup.md")


def test_bare_page_name_without_extension_takes_the_source_extension(repo):
    rc, out, err = run_tool(repo, [row("docs/setup.md", "Setup"), row("docs/img/d.png", "Diagram.png")])
    assert rc == 0, (out, err)
    assert (repo / "Setup.md").exists()


def test_nonmd_literal_rewrites(repo):
    rc, out, err = run_tool(repo, [row("docs/setup.md", "Setup.md")])
    assert rc == 0, err
    sh_txt = text(repo, "scripts/run.sh")
    assert "cat Setup.md\n" in sh_txt
    assert "cat mydocs/docs/setup.md\n" in sh_txt  # not a boundary match
    assert "cat docs/setup.md.bak\n" in sh_txt  # not a boundary match
    assert "cat ./Setup.md\n" in sh_txt
    assert "- Setup.md" in text(repo, ".github/workflows/ci.yml")
    assert "PATH = 'Setup.md'" in text(repo, "src/main.py")
    assert "scripts/run.sh" in out
    assert "PATH =" not in out  # lines are never echoed


def test_code_regions_untouched(tmp_path):
    files = dict(BASE)
    files["README.md"] = (
        "[ok](docs/setup.md)\n```\n[no](docs/setup.md)\n```\n"
        "inline `[no](docs/setup.md)` end\n\n    [no](docs/setup.md)\n\n~~~md\n[no](docs/setup.md)\n~~~\n"
        "\n- list\n\n    [yes](docs/setup.md)\n"
    )
    repo = make_repo(tmp_path, files)
    rc, out, err = run_tool(repo, [row("docs/setup.md", "Setup.md")])
    assert rc == 0, err
    txt = text(repo, "README.md")
    assert txt.count("[no](docs/setup.md)") == 4  # fenced, inline, indented, tilde
    assert txt.count("[ok](Setup.md)") == 1
    assert "[yes](Setup.md)" in txt  # a paragraph inside a list item is a real link


def test_reference_style_links(tmp_path):
    files = dict(BASE)
    files["README.md"] = 'See [setup][s] and [d].\n\n[s]: docs/setup.md#install "T"\n[d]: <docs/arch/design.md>\n'
    repo = make_repo(tmp_path, files)
    rc, _, err = run_tool(repo, [row("docs/setup.md", "Setup.md"), row("docs/arch/design.md", "Design.md")])
    assert rc == 0, err
    txt = text(repo, "README.md")
    assert '[s]: Setup.md#install "T"' in txt and "[d]: <Design.md>" in txt


def test_reference_definition_continued_over_two_lines_is_rewritten(tmp_path):
    files = dict(BASE)
    files["README.md"] = (
        "See [setup][s], [d] and [t].\n\n"
        "[s]:\n    docs/setup.md#install\n\n"
        "[d]: <docs/arch/design.md>\n    'Design title'\n\n"
        '[t]: docs/setup.md\n  "A title line with [not](docs/setup.md)"\n'
    )
    repo = make_repo(tmp_path, files)
    rc, out, err = run_tool(repo, [row("docs/setup.md", "Setup.md"), row("docs/arch/design.md", "Design.md")])
    assert rc == 0, (out, err)
    assert text(repo, "README.md") == (
        "See [setup][s], [d] and [t].\n\n"
        "[s]:\n    Setup.md#install\n\n"
        "[d]: <Design.md>\n    'Design title'\n\n"
        '[t]: Setup.md\n  "A title line with [not](docs/setup.md)"\n'
    )


def test_wiki_style_links_follow_the_page(tmp_path):
    files = {
        "docs/Old-Setup.md": "# Setup\nbody\n",
        "docs/Other.md": "# Other\nx\n",
        "docs/Home.md": (
            "See [[Old-Setup]], [[the setup|old setup#install]], [[Other]], [[Missing Page]] and `[[Old-Setup]]`.\n"
            "```\n[[Old-Setup]]\n```\n"
        ),
    }
    repo = make_repo(tmp_path, files)
    rc, out, err = run_tool(
        repo, [row("docs/Old-Setup.md", "Install-Setup.md"), row("docs/Home.md", "Home.md")], "--subfolder", "wiki"
    )
    assert rc == 0, (out, err)
    assert text(repo, "wiki/Home.md") == (
        "See [[Install-Setup]], [[the setup|Install-Setup#install]], [[Other]], [[Missing Page]] and `[[Old-Setup]]`.\n"
        "```\n[[Old-Setup]]\n```\n"
    )


def test_wiki_link_with_ambiguous_stem_exits_2(tmp_path):
    files = {"a/Setup.md": "# A\n", "b/Setup.md": "# B\n", "Home.md": "See [[Setup]].\n"}
    repo = make_repo(tmp_path, files)
    err = fails(repo, [row("a/Setup.md", "A-Setup.md")])
    assert "ambiguous" in err.lower()


def test_crlf_and_non_utf8_preserved(tmp_path):
    files = dict(BASE)
    files["README.md"] = b"# T\r\n[a](docs/setup.md)\r\n\xff\xfe latin \xe9\r\nlast"
    repo = make_repo(tmp_path, files)
    rc, _, err = run_tool(repo, [row("docs/setup.md", "Setup.md")])
    assert rc == 0, err
    assert read(repo, "README.md") == b"# T\r\n[a](Setup.md)\r\n\xff\xfe latin \xe9\r\nlast"


def test_html_attrs_rewritten(tmp_path):
    files = dict(BASE)
    files["README.md"] = '<img src="docs/img/d.png"> <a href="docs/setup.md">x</a>\n'
    repo = make_repo(tmp_path, files)
    rc, _, err = run_tool(repo, [row("docs/setup.md", "Setup.md"), row("docs/img/d.png", "D.png")])
    assert rc == 0, err
    assert text(repo, "README.md") == '<img src="D.png"> <a href="Setup.md">x</a>\n'


def test_preexisting_broken_link_is_warning_unless_strict(tmp_path):
    files = dict(BASE)
    files["README.md"] += "[gone](docs/missing.md)\n"
    repo = make_repo(tmp_path, files)
    rc, out, err = run_tool(repo, [row("docs/setup.md", "Setup.md")], "--dry-run")
    assert rc == 0, err
    assert "pre-existing unresolved links: 1" in out
    rc, _, _ = run_tool(repo, [row("docs/setup.md", "Setup.md")], "--dry-run", "--strict")
    assert rc == 2


def test_dry_run_writes_nothing(repo):
    before = snapshot(repo)
    rc, out, err = run_tool(repo, [row("docs/setup.md", "Setup.md")], "--dry-run")
    assert rc == 0, err
    assert "docs/setup.md" in out and "Setup.md" in out
    assert snapshot(repo) == before
    assert porcelain(repo) == ""


def test_link_to_unmoved_file_from_moved_file_and_dir(tmp_path):
    files = dict(BASE)
    files["docs/arch/design.md"] += "[dir](../img/) [up](../../src/main.py)\n"
    repo = make_repo(tmp_path, files)
    rc, _, err = run_tool(repo, [row("docs/arch/design.md", "Design.md")])
    assert rc == 0, err
    txt = text(repo, "Design.md")
    assert "[dir](docs/img/)" in txt and "[up](src/main.py)" in txt
    assert '[setup](docs/setup.md#install "Setup title")' in txt


# --------------------------------------------------------------------------- merge, archive, keep
def test_merge_order_provenance_and_no_loss(tmp_path):
    files = dict(BASE)
    files["docs/a.md"] = "# A\nalpha [s](setup.md#install)\n"
    files["docs/b.md"] = "# B\nbeta no trailing newline [a](a.md)"
    repo = make_repo(tmp_path, files)
    rc, out, err = run_tool(
        repo, [row("docs/b.md", "Merged.md", "merge-into", "2"), row("docs/a.md", "Merged.md", "merge-into", "1")]
    )
    assert rc == 0, (out, err)
    m = text(repo, "Merged.md")
    assert m.index("docs/a.md -->") < m.index("docs/b.md -->")
    assert "<!-- docmove: merged from docs/a.md -->\n# A\nalpha [s](docs/setup.md#install)\n" in m
    assert "# B\nbeta no trailing newline [a](Merged.md)\n" in m
    assert not (repo / "docs/a.md").exists()
    rep = text(repo, "where-did-it-go.md")
    assert "Files in: 2. Accounted for: 2" in rep and "merge-into" in rep


def test_archive_into_and_keep(tmp_path):
    files = dict(BASE)
    files["docs/old1.md"] = "# Old1\nx\n"
    files["docs/old2.md"] = "# Old2\ny\n"
    repo = make_repo(tmp_path, files)
    rows = [
        row("docs/old1.md", "Archive-Old.md", "archive-into"),
        row("docs/old2.md", "Archive-Old.md", "archive-into"),
        row("docs/setup.md", "", "keep"),
    ]
    rc, out, err = run_tool(repo, rows)
    assert rc == 0, (out, err)
    a = text(repo, "Archive-Old.md")
    assert a.index("# Old1") < a.index("# Old2")
    assert (repo / "docs/setup.md").exists()
    rep = text(repo, "where-did-it-go.md")
    assert "Files in: 3. Accounted for: 3" in rep and "archive-into" in rep and "keep" in rep


# --------------------------------------------------------------------------- split and stub
BIG = (
    "# Big guide\n"  # 1
    "intro line\n"  # 2
    "\n"  # 3
    "## Part A\n"  # 4
    "a body see [setup](setup.md#install)\n"  # 5
    "\n"  # 6
    "## Part B\n"  # 7
    "b body\n"  # 8
    "b body\n"  # 9
)


def split_repo(tmp_path, extra=None):
    files = dict(BASE)
    files["docs/big.md"] = BIG
    files.update(extra or {})
    return make_repo(tmp_path, files)


SPLIT_ROWS = [
    row("docs/big.md", "Part-One.md", "split-into", "1", "L1-L6"),
    row("docs/big.md", "Part-Two.md", "split-into", "1", "L7-L9"),
]


def test_split_into_pages_with_provenance_and_rewritten_links(tmp_path):
    repo = split_repo(tmp_path)
    rc, out, err = run_tool(repo, SPLIT_ROWS, "--subfolder", "wiki")
    assert rc == 0, (out, err)
    one, two = text(repo, "wiki/Part-One.md"), text(repo, "wiki/Part-Two.md")
    assert one == "<!-- docmove: split from docs/big.md L1-L6 -->\n" + "".join(BIG.splitlines(True)[:6]).replace(
        "(setup.md#install)", "(../docs/setup.md#install)"
    )
    assert two == "<!-- docmove: split from docs/big.md L7-L9 -->\n## Part B\nb body\nb body\n"
    assert not (repo / "docs/big.md").exists()
    rep = text(repo, "wiki/where-did-it-go.md")
    assert "split-into" in rep and "L7-L9" in rep


def test_splitcheck_agrees_with_docmove_split(tmp_path):
    repo = split_repo(tmp_path)
    src = tmp_path / "big.orig.md"
    src.write_text(BIG)
    rc, out, err = run_tool(repo, SPLIT_ROWS)
    assert rc == 0, (out, err)
    r = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SPLITCHECK),
            "--source",
            str(src),
            "--source-name",
            "docs/big.md",
            "--out",
            str(repo / "Part-One.md"),
            str(repo / "Part-Two.md"),
        ],
        capture_output=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_split_pages_may_share_a_destination_in_order(tmp_path):
    repo = split_repo(tmp_path)
    rows = [
        row("docs/big.md", "All.md", "split-into", "2", "L7-L9"),
        row("docs/big.md", "All.md", "split-into", "1", "L1-L6"),
    ]
    rc, out, err = run_tool(repo, rows)
    assert rc == 0, (out, err)
    txt = text(repo, "All.md")
    assert txt.index("L1-L6") < txt.index("L7-L9")
    assert txt.count("b body") == 2


def test_split_errors(tmp_path):
    repo = split_repo(tmp_path)
    fails(repo, [row("docs/big.md", "A.md", "split-into", "1", "L1-L6")])  # lines 7-9 uncovered
    fails(
        repo,
        [
            row("docs/big.md", "A.md", "split-into", "1", "L1-L9"),
            row("docs/big.md", "B.md", "split-into", "1", "L5-L7"),
        ],
    )
    fails(repo, [row("docs/big.md", "A.md", "split-into", "1", "L1-L99")])
    fails(repo, [row("docs/big.md", "A.md", "split-into", "1", "L0-L9")])
    fails(repo, [row("docs/big.md", "A.md", "split-into", "1", "L9-L1")])
    fails(repo, [row("docs/big.md", "A.md", "split-into", "1", "1-9")])
    fails(repo, [row("docs/big.md", "A.md", "split-into", "1", "")])
    fails(repo, [row("docs/setup.md", "A.md", "move", "", "L1-L3")])
    fails(repo, [row("docs/big.md", "A.md", "split-into", "1", "L1-L9"), row("docs/big.md", "B.md", "move")])
    fails(repo, [row("docs/img/d.png", "A.md", "split-into", "1", "L1-L1")])


def test_uncovered_blank_lines_are_fine(tmp_path):
    repo = split_repo(tmp_path)
    rows = [
        row("docs/big.md", "A.md", "split-into", "1", "L1-L2"),
        row("docs/big.md", "B.md", "split-into", "1", "L4-L9"),
    ]
    rc, out, err = run_tool(repo, rows)
    assert rc == 0, (out, err)  # line 3 is blank


def test_link_to_a_split_source_resolves_to_the_first_section_and_is_reported(tmp_path):
    repo = split_repo(tmp_path, {"docs/other.md": "intro\nsee [big](big.md) and [part](big.md#part-b)\n"})
    before = snapshot(repo)
    rc, out, err = run_tool(repo, SPLIT_ROWS, "--dry-run")
    assert rc == 0, (out, err)
    assert "approximate link: docs/other.md:2" in out
    assert snapshot(repo) == before
    rc, out, err = run_tool(repo, SPLIT_ROWS)
    assert rc == 0, (out, err)
    # the fragment-less link goes to the first section's page; the anchored one to the page holding its heading
    assert "[big](../Part-One.md) and [part](../Part-Two.md#part-b)" in text(repo, "docs/other.md")
    assert "approximate link: docs/other.md:2" in text(repo, "where-did-it-go.md")


def test_literal_reference_to_a_split_source_is_reported_and_strict_fails(tmp_path):
    repo = split_repo(tmp_path, {"scripts/show.sh": "cat docs/big.md\n"})
    rc, out, err = run_tool(repo, SPLIT_ROWS, "--dry-run")
    assert rc == 0, err
    assert "scripts/show.sh:1" in out and "ambiguous" in out
    fails(repo, SPLIT_ROWS, "--strict")


def test_stub_points_old_name_at_new_home(tmp_path):
    repo = split_repo(tmp_path)
    rows = [row("docs/setup.md", "Install-Setup.md"), row("docs/setup.md", "Old-Setup.md", "stub")]
    rc, out, err = run_tool(repo, rows, "--subfolder", "wiki")
    assert rc == 0, (out, err)
    stub = text(repo, "wiki/Old-Setup.md")
    assert "(Install-Setup.md)" in stub
    rep = text(repo, "wiki/where-did-it-go.md")
    assert "Old-Setup" in rep and "stub" in rep
    assert "Files in: 1. Accounted for: 1" in rep


def test_stub_needs_a_destination_row_and_a_free_name(repo):
    fails(repo, [row("docs/setup.md", "Old.md", "stub")])
    fails(repo, [row("docs/setup.md", "Setup.md"), row("docs/setup.md", "readme.md", "stub")])


# --------------------------------------------------------------------------- copy-into
def test_copy_range_leaves_source_byte_identical_and_rewrites_links(tmp_path):
    repo = split_repo(tmp_path)
    before = read(repo, "docs/big.md")
    rc, out, err = run_tool(repo, [row("docs/big.md", "Part-A.md", "copy-into", "", "L4-L6")], "--subfolder", "wiki")
    assert rc == 0, (out, err)
    assert read(repo, "docs/big.md") == before
    page = text(repo, "wiki/Part-A.md")
    assert page == (
        "<!-- docmove: copied from docs/big.md L4-L6 -->\n## Part A\na body see [setup](../docs/setup.md#install)\n\n"
    )
    assert "copy-into" in text(repo, "wiki/where-did-it-go.md")
    assert "docs/big.md" not in porcelain(repo)  # the source is neither staged nor modified


def test_copy_whole_file_coexists_with_keep(tmp_path):
    repo = split_repo(tmp_path)
    before = read(repo, "docs/big.md")
    rows = [row("docs/big.md", "", "keep"), row("docs/big.md", "Big-Copy.md", "copy-into")]
    rc, out, err = run_tool(repo, rows)
    assert rc == 0, (out, err)
    assert read(repo, "docs/big.md") == before
    page = text(repo, "Big-Copy.md")
    assert page.startswith("<!-- docmove: copied from docs/big.md -->\n# Big guide\n")
    assert "(docs/setup.md#install)" in page
    assert page.count("b body") == 2
    assert "Files in: 1. Accounted for: 1" in text(repo, "where-did-it-go.md")
    assert (repo / "docs/big.md").exists()


def test_two_ranged_copies_may_not_overlap(tmp_path):
    repo = split_repo(tmp_path)
    fails(
        repo,
        [row("docs/big.md", "A.md", "copy-into", "", "L1-L5"), row("docs/big.md", "B.md", "copy-into", "", "L5-L9")],
    )
    rc, out, err = run_tool(
        repo,
        [row("docs/big.md", "A.md", "copy-into", "", "L1-L4"), row("docs/big.md", "B.md", "copy-into", "", "L5-L9")],
    )
    assert rc == 0, (out, err)


def test_copy_cannot_share_a_source_with_a_move_or_bad_section(tmp_path):
    repo = split_repo(tmp_path)
    fails(repo, [row("docs/big.md", "A.md", "copy-into"), row("docs/big.md", "B.md", "move")])
    fails(repo, [row("docs/big.md", "A.md", "copy-into", "", "L1-L99")])
    fails(repo, [row("docs/big.md", "A.md", "copy-into", "", "1-3")])
    fails(repo, [row("docs/big.md", "A.md", "copy-into"), row("docs/big.md", "A.md", "copy-into")])
    fails(repo, [row("docs/img/d.png", "A.md", "copy-into")])


def test_copied_text_is_checked_by_splitcheck_in_copy_mode(tmp_path):
    repo = split_repo(tmp_path)
    rc, out, err = run_tool(repo, [row("docs/big.md", "Part-A.md", "copy-into", "", "L4-L6")])
    assert rc == 0, (out, err)
    r = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SPLITCHECK),
            "--copy",
            "--lines",
            "L4-L6",
            "--source",
            str(repo / "docs/big.md"),
            "--out",
            str(repo / "Part-A.md"),
        ],
        capture_output=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr


# --------------------------------------------------------------------------- real-registry slice
# A small synthetic slice shaped like the pfsense migration registry (docs-migration/registry.csv
# plus stubs.csv, concatenated under one header): mixed split/merge/archive sources, pages that
# already live in wiki/, a keep row beside copy-into rows, and stubs whose notes say where they point.
SLICE_FILES = {
    "README.md": (
        "# Proj\n"  # 1
        "front door, see [part B](docs/guide.md#part-b)\n"  # 2
        "see [guide](docs/guide.md) and [dir](docs/pfsense/)\n"  # 3
        "## Docs\n"  # 4
        "doc link one [changes](CHANGELOG.md)\n"  # 5
        "doc link two [notes](docs/pfsense/NOTES.md)\n"  # 6
    ),
    "CHANGELOG.md": "# Changelog\n- first entry\n- second entry\n",
    "wiki/Home.md": "# Home\nlanding text\n",
    "docs/INDEX.md": "# Index\nindex one\nindex two\n## Tree\ntree a\ntree b\n",
    "wiki/Glossary.md": "# Glossary\nterm [notes](../docs/pfsense/NOTES.md)\n",
    "wiki/_Sidebar.md": "* [Home](Home.md)\n* [Guide](../docs/guide.md)\n",
    "wiki/New-Start.md": "# New start\nbegin here\n",
    "wiki/faq.md": "# FAQ\nq and a\n",
    "docs/guide.md": (
        "# Guide\n"  # 1
        "intro\n"  # 2
        "```\n"  # 3
        "code line\n"  # 4
        "```\n"  # 5
        "## Part B\n"  # 6
        "b one\n"  # 7
        "```\n"  # 8
        "other code\n"  # 9
        "```\n"  # 10
    ),
    "docs/pfsense/NOTES.md": "# Notes\nnote body\n",
    "docs/old.md": "# Old\nold body\n",
    "scripts/run.sh": "#!/bin/sh\ncat docs/old.md\n",
    ".gitleaksignore": "docs/old.md:generic-api-key:2\n",
}

SLICE_ROWS = [
    row("wiki/Home.md", "Home", "merge-into", "1", notes="landing page: hand-written, best content"),
    row("docs/INDEX.md", "Home", "merge-into", "2", "L1-L3", "index retired; L1-L3 feed the intro"),
    row("docs/INDEX.md", "Archive-Index", "archive-into", "1", "L4-L6", "tree is archive only"),
    row("README.md", "", "keep", "1", notes="front door stays"),
    row("README.md", "Home", "copy-into", "3", "L4-L6", "README documentation links"),
    row("CHANGELOG.md", "", "keep", "1", notes="release tool reads root"),
    row("CHANGELOG.md", "Project-Changelog", "copy-into", "1", notes="derived by copy"),
    row("wiki/Glossary.md", "Glossary", "move", "1", notes="already in place"),
    row("wiki/_Sidebar.md", "_Sidebar", "move", "1", notes="rewrite later"),
    row("wiki/New-Start.md", "Start-Here", "move", "1", notes="renamed to the landing name"),
    row("wiki/faq.md", "FAQ", "move", "1", notes="case-only rename"),
    row("docs/guide.md", "Install-Guide", "split-into", "1", "L1-L5", "first part"),
    row("docs/guide.md", "Operate-Guide", "split-into", "1", "L6-L10", "second part"),
    row("docs/pfsense/NOTES.md", "Reference-Notes", "move", "1"),
    row("docs/old.md", "Reference-Old", "move", "1"),
]
SLICE_STUBS = [
    row("wiki/New-Start.md", "New-Start", "stub", "1", notes="old wiki name for one release; points to Start-Here"),
    row("CHANGELOG.md", "Changelog", "stub", "1", notes="old wiki name for one release; points to Project-Changelog"),
    row("docs/guide.md", "Guide", "stub", "1", notes="old wiki name; points to Install-Guide and Operate-Guide"),
    row("scripts/run.sh", "Run-Script", "stub", "1", notes="old wiki name; points to repo file scripts/run.sh"),
]


def slice_repo(tmp_path):
    return make_repo(tmp_path, SLICE_FILES)


def run_slice(repo, *extra, stubs=True):
    return run_tool(
        repo,
        SLICE_ROWS + (SLICE_STUBS if stubs else []),
        "--subfolder",
        "wiki",
        *extra,
        header=NOTES_HEADER,
    )


def test_slice_dry_run_is_exit_0_and_lists_what_needs_review(tmp_path):
    repo = slice_repo(tmp_path)
    before = snapshot(repo)
    rc, out, err = run_slice(repo, "--dry-run")
    assert rc == 0, (out, err)
    assert "approximate link: README.md:3" in out  # [guide](docs/guide.md#part-b)
    assert "dangling directory link" in out and "README.md:3" in out  # [dir](docs/pfsense/)
    assert snapshot(repo) == before


def test_slice_strict_exits_2_on_approximate_and_dangling_links(tmp_path):
    repo = slice_repo(tmp_path)
    err = fails(repo, SLICE_ROWS + SLICE_STUBS, "--subfolder", "wiki", "--strict", header=NOTES_HEADER)
    assert "approximate" in err or "dangling" in err


def test_slice_apply_pages_in_order_in_place_and_without_provenance_on_the_in_place_file(tmp_path):
    repo = slice_repo(tmp_path)
    rc, out, err = run_slice(repo)
    assert rc == 0, (out, err)
    home = text(repo, "wiki/Home.md")
    assert home == (
        "# Home\nlanding text\n"  # the in-place page keeps its text, no provenance comment
        "\n<!-- docmove: merged from docs/INDEX.md L1-L3 -->\n# Index\nindex one\nindex two\n"
        "\n<!-- docmove: copied from README.md L4-L6 -->\n## Docs\n"
        "doc link one [changes](../CHANGELOG.md)\ndoc link two [notes](Reference-Notes.md)\n"
    )
    assert text(repo, "wiki/Archive-Index.md") == (
        "<!-- docmove: archived from docs/INDEX.md L4-L6 -->\n## Tree\ntree a\ntree b\n"
    )
    assert not (repo / "docs/INDEX.md").exists()
    assert text(repo, "wiki/Glossary.md") == "# Glossary\nterm [notes](Reference-Notes.md)\n"
    assert read(repo, "wiki/_Sidebar.md") == b"* [Home](Home.md)\n* [Guide](Install-Guide.md)\n"
    assert (repo / "wiki/FAQ.md").read_text() == "# FAQ\nq and a\n"
    assert "faq.md" not in git(repo, "ls-files").decode().replace("FAQ.md", "")
    # the keep rows left the sources byte-identical apart from link fixes
    assert read(repo, "CHANGELOG.md") == SLICE_FILES["CHANGELOG.md"].encode()
    assert text(repo, "wiki/Project-Changelog.md").startswith("<!-- docmove: copied from CHANGELOG.md -->\n# Changelog")


def test_slice_stub_reuses_the_path_a_move_vacated(tmp_path):
    repo = slice_repo(tmp_path)
    rc, out, err = run_slice(repo)
    assert rc == 0, (out, err)
    assert text(repo, "wiki/Start-Here.md") == "# New start\nbegin here\n"
    stub = text(repo, "wiki/New-Start.md")
    assert "[Start-Here](Start-Here.md)" in stub and "../" not in stub


def test_slice_stub_notes_name_the_targets(tmp_path):
    repo = slice_repo(tmp_path)
    rc, out, err = run_slice(repo, "--repo-url", "https://github.com/example/proj")
    assert rc == 0, (out, err)
    # a copy-into page, not the page that holds the source's first section
    assert "[Project-Changelog](Project-Changelog.md)" in text(repo, "wiki/Changelog.md")
    two = text(repo, "wiki/Guide.md")
    assert "[Install-Guide](Install-Guide.md)" in two and "[Operate-Guide](Operate-Guide.md)" in two
    assert "../" not in two
    run = text(repo, "wiki/Run-Script.md")
    assert "https://github.com/example/proj/blob/main/scripts/run.sh" in run and "../" not in run


def test_slice_repo_file_stub_without_repo_url_is_plain_text_and_bad_url_is_64(tmp_path):
    repo = slice_repo(tmp_path)
    rc, out, err = run_slice(repo)
    assert rc == 0, (out, err)
    run = text(repo, "wiki/Run-Script.md")
    assert "`scripts/run.sh`" in run and "http" not in run
    (tmp_path / "again").mkdir()
    fails(
        make_repo(tmp_path / "again", SLICE_FILES),
        SLICE_ROWS + SLICE_STUBS,
        "--subfolder",
        "wiki",
        "--repo-url",
        "javascript:alert(1)",
        header=NOTES_HEADER,
        code=64,
    )


def test_stub_without_points_to_falls_back_and_says_so(tmp_path):
    repo = slice_repo(tmp_path)
    rows = [row("docs/old.md", "Reference-Old", "move"), row("docs/old.md", "Old", "stub", notes="no target named")]
    rc, out, err = run_tool(repo, rows, "--subfolder", "wiki", header=NOTES_HEADER)
    assert rc == 0, (out, err)
    assert "stub fallback: wiki/Old.md" in out
    assert "[Reference-Old](Reference-Old.md)" in text(repo, "wiki/Old.md")
    assert "stub fallback: wiki/Old.md" in text(repo, "wiki/where-did-it-go.md")


def test_stub_pointing_at_an_unknown_page_exits_2(tmp_path):
    repo = slice_repo(tmp_path)
    rows = [row("docs/old.md", "Reference-Old", "move"), row("docs/old.md", "Old", "stub", notes="points to Nowhere")]
    err = fails(repo, rows, "--subfolder", "wiki", header=NOTES_HEADER)
    assert "points to 'Nowhere', which is not a page in this run" in err


def test_link_map_overrides_the_default_page_for_a_split_source(tmp_path):
    repo = slice_repo(tmp_path)
    lm = tmp_path / "links.csv"
    lm.write_text("source,page\ndocs/guide.md,Operate-Guide\n")
    rc, out, err = run_slice(repo, "--link-map", str(lm), "--strict", "--dry-run")
    assert "approximate link: README.md" not in out
    # the directory link still dangles, so strict still stops; without it the override is what is rewritten
    assert rc == 2
    rc, out, err = run_slice(repo, "--link-map", str(lm))
    assert rc == 0, (out, err)
    assert "[guide](wiki/Operate-Guide.md)" in text(repo, "README.md")
    assert "[part B](wiki/Operate-Guide.md#part-b)" in text(repo, "README.md")
    assert "approximate link: README.md" not in out


def test_link_map_errors(tmp_path):
    repo = slice_repo(tmp_path)
    bad = tmp_path / "bad.csv"
    bad.write_text("source,page,extra\ndocs/guide.md,Operate-Guide,x\n")
    fails(repo, SLICE_ROWS, "--subfolder", "wiki", "--link-map", str(bad), header=NOTES_HEADER, code=64)
    bad.write_text("source,page\ndocs/guide.md,Reference-Notes\n")  # not one of the source's pages
    fails(repo, SLICE_ROWS, "--subfolder", "wiki", "--link-map", str(bad), header=NOTES_HEADER)
    bad.write_text("source,page\ndocs/unknown.md,Operate-Guide\n")
    fails(repo, SLICE_ROWS, "--subfolder", "wiki", "--link-map", str(bad), header=NOTES_HEADER)


def test_exclude_defaults_leave_gitleaks_fingerprints_and_the_map_alone(tmp_path):
    files = dict(SLICE_FILES)
    files["docs-migration/registry.csv"] = "docs/old.md,,Reference-Old,move\n"
    files["plan/links.csv"] = "source,page\ndocs/guide.md,Install-Guide\n"
    repo = make_repo(tmp_path, files)
    lm = repo / "plan" / "links.csv"
    rc, out, err = run_tool(
        repo, SLICE_ROWS, "--subfolder", "wiki", "--link-map", str(lm), header=NOTES_HEADER, mapfile="plan/map.csv"
    )
    assert rc == 0, (out, err)
    assert text(repo, ".gitleaksignore") == "docs/old.md:generic-api-key:2\n"  # a fingerprint, not a path
    assert text(repo, "docs-migration/registry.csv") == "docs/old.md,,Reference-Old,move\n"
    assert "docs/old.md,,Reference-Old,move,1" in text(repo, "plan/map.csv")  # the map names the old path
    assert text(repo, "plan/links.csv") == "source,page\ndocs/guide.md,Install-Guide\n"
    assert "wiki/Reference-Old.md" in text(repo, "scripts/run.sh")  # ordinary files are still rewritten


def test_explicit_exclude_glob_keeps_matching_files_unrewritten(tmp_path):
    repo = slice_repo(tmp_path)
    rc, out, err = run_slice(repo, "--exclude", "scripts/*")
    assert rc == 0, (out, err)
    assert text(repo, "scripts/run.sh") == "#!/bin/sh\ncat docs/old.md\n"


def test_reference_definition_inside_a_blockquote_or_list_item_is_rewritten(tmp_path):
    files = {
        "docs/old.md": "# Old\n",
        "README.md": '> quote [r][a]\n>\n> [a]: docs/old.md\n\n- item [r][b]\n\n  [b]: docs/old.md "T"\n',
    }
    repo = make_repo(tmp_path, files)
    rc, out, err = run_tool(repo, [row("docs/old.md", "Old.md")])
    assert rc == 0, (out, err)
    assert text(repo, "README.md") == '> quote [r][a]\n>\n> [a]: Old.md\n\n- item [r][b]\n\n  [b]: Old.md "T"\n'


def test_links_inside_html_comments_are_rewritten(tmp_path):
    files = {"docs/old.md": "# Old\n", "README.md": "text\n<!-- see [old](docs/old.md) later -->\n"}
    repo = make_repo(tmp_path, files)
    rc, out, err = run_tool(repo, [row("docs/old.md", "Old.md")])
    assert rc == 0, (out, err)
    assert text(repo, "README.md") == "text\n<!-- see [old](Old.md) later -->\n"


def test_merging_chunks_normalizes_line_endings_and_interior_bom(tmp_path):
    files = {"a.md": b"# A\r\nalpha\r\n", "b.md": b"\xef\xbb\xbf# B\nbeta\n", "c.md": b"# C\r\ngamma\r\n"}
    repo = make_repo(tmp_path, files)
    rows = [row(f"{n}.md", "All.md", "merge-into", str(i)) for i, n in enumerate("abc", 1)]
    rc, out, err = run_tool(repo, rows)
    assert rc == 0, (out, err)
    data = read(repo, "All.md")
    assert data.count(b"\r\n") == data.count(b"\n")  # first chunk is CRLF, so every line ending is
    assert data.count(b"\xef\xbb\xbf") == 0
    assert b"# B\r\nbeta\r\n" in data and b"# C\r\ngamma\r\n" in data


def test_underscore_landing_pages_and_noop_move_are_valid(tmp_path):
    files = {"wiki/_Sidebar.md": "* [Home](Home.md)\n", "wiki/_Footer.md": "footer\n", "wiki/Home.md": "# Home\n"}
    repo = make_repo(tmp_path, files)
    rows = [row("wiki/_Sidebar.md", "_Sidebar"), row("wiki/_Footer.md", "_Footer"), row("wiki/Home.md", "Home")]
    rc, out, err = run_tool(repo, rows, "--subfolder", "wiki")
    assert rc == 0, (out, err)
    assert text(repo, "wiki/_Footer.md") == "footer\n"
    repo2 = make_repo(tmp_path / "again", files) if (tmp_path / "again").mkdir() is None else None
    fails(repo2, [row("wiki/Home.md", "_Other")], "--subfolder", "wiki")


def test_a_destination_that_is_an_existing_file_outside_the_map_is_still_a_collision(tmp_path):
    files = {"wiki/Home.md": "# Home\n", "docs/a.md": "# A\n"}
    repo = make_repo(tmp_path, files)
    fails(repo, [row("docs/a.md", "Home")], "--subfolder", "wiki")
    fails(repo, [row("docs/a.md", "Home"), row("wiki/Home.md", "", "keep")], "--subfolder", "wiki")


def test_a_source_mixing_split_merge_and_archive_rows_must_cover_every_line(tmp_path):
    files = {"docs/x.md": "a\nb\nc\nd\n", "wiki/Home.md": "# Home\n"}
    repo = make_repo(tmp_path, files)
    rows = [
        row("docs/x.md", "Home", "merge-into", "1", "L1-L2"),
        row("docs/x.md", "Archive-X", "archive-into", "1", "L3-L3"),
    ]
    fails(repo, rows, "--subfolder", "wiki")  # line 4 is in no row
    rows.append(row("docs/x.md", "Operate-X", "split-into", "1", "L4-L4"))
    rows.append(row("wiki/Home.md", "Home", "merge-into", "0"))
    rc, out, err = run_tool(repo, rows, "--subfolder", "wiki")
    assert rc == 0, (out, err)


# --------------------------------------------------------------------------- anchors
GUIDE = (
    "# Guide\n"  # 1
    "intro\n"  # 2
    "## Setup\n"  # 3
    "setup text\n"  # 4
    "## Usage\n"  # 5
    "usage text, back to [setup](#setup) and on to [usage](#usage) and [again](#usage-1)\n"  # 6
    "```\n"  # 7
    "# Not a heading\n"  # 8
    "```\n"  # 9
    "## Usage\n"  # 10
    "more usage\n"  # 11
)
GUIDE_ROWS = [
    row("docs/guide.md", "Install-Guide", "split-into", "1", "L1-L4"),
    row("docs/guide.md", "Operate-Guide", "split-into", "1", "L5-L11"),
]


def anchor_repo(tmp_path):
    return make_repo(
        tmp_path,
        {
            "docs/guide.md": GUIDE,
            "docs/a.md": "# A\n## Notes\nnote a\n",
            "docs/b.md": "# B\n## Notes\nnote b\n",
            "docs/other.md": (
                "[s](guide.md#setup) [u](guide.md#usage) [u1](guide.md#usage-1) [g](guide.md)\n"  # 1
                "[fenced](guide.md#not-a-heading) [gone](guide.md#nope)\n"  # 2
                "[na](a.md#notes) [nb](b.md#notes)\n"  # 3
                "[[Guide#setup]] and [[Guide#usage-1]] and [[Guide]]\n"  # 4
            ),
        },
    )


MERGE_ROWS = [
    row("docs/a.md", "Reference-All", "merge-into", "1"),
    row("docs/b.md", "Reference-All", "merge-into", "2"),
]


def test_anchor_links_follow_the_heading_to_the_page_that_now_holds_it(tmp_path):
    repo = anchor_repo(tmp_path)
    rc, out, err = run_tool(repo, GUIDE_ROWS + MERGE_ROWS, "--subfolder", "wiki")
    assert rc == 0, (out, err)
    other = text(repo, "docs/other.md").split("\n")
    assert "[s](../wiki/Install-Guide.md#setup)" in other[0]
    assert "[u](../wiki/Operate-Guide.md#usage)" in other[0]
    assert "[u1](../wiki/Operate-Guide.md#usage-1)" in other[0]
    assert "[g](../wiki/Install-Guide.md)" in other[0]  # no fragment: the first section's page
    # a heading inside a fence is not a heading; a missing one stays as it was
    assert "[fenced](../wiki/Install-Guide.md#not-a-heading) [gone](../wiki/Install-Guide.md#nope)" in other[1]
    # two merged sources both have "## Notes": the second gets GitHub's -1 suffix on the merged page
    assert "[na](../wiki/Reference-All.md#notes) [nb](../wiki/Reference-All.md#notes-1)" in other[2]


def test_wiki_style_links_with_a_fragment_follow_the_heading(tmp_path):
    repo = anchor_repo(tmp_path)
    rc, out, err = run_tool(repo, GUIDE_ROWS + MERGE_ROWS, "--subfolder", "wiki")
    assert rc == 0, (out, err)
    line4 = text(repo, "docs/other.md").split("\n")[3]
    assert line4 == "[[Install-Guide#setup]] and [[Operate-Guide#usage-1]] and [[Install-Guide]]"


def test_same_page_toc_anchors_are_rewritten_only_when_the_heading_moved_page(tmp_path):
    repo = anchor_repo(tmp_path)
    rc, out, err = run_tool(repo, GUIDE_ROWS + MERGE_ROWS, "--subfolder", "wiki")
    assert rc == 0, (out, err)
    page = text(repo, "wiki/Operate-Guide.md")
    assert "back to [setup](Install-Guide.md#setup) and on to [usage](#usage) and [again](#usage-1)" in page


def test_anchors_are_counted_and_pre_existing_broken_ones_reported_not_fatal(tmp_path):
    repo = anchor_repo(tmp_path)
    rc, out, err = run_tool(repo, GUIDE_ROWS + MERGE_ROWS, "--subfolder", "wiki", "--dry-run")
    assert rc == 0, (out, err)
    assert "pre-existing broken anchor: docs/other.md:2" in out
    assert "anchors: 8 rewritten, 0 unresolved, 2 pre-existing broken" in out
    # the exact anchors are not "approximate"; only the fragment-less links are
    assert "approximate link: docs/other.md:1 -> guide.md now points" in out
    assert "approximate link: docs/other.md:1 -> guide.md#setup" not in out
    rc, out, err = run_tool(repo, GUIDE_ROWS + MERGE_ROWS, "--subfolder", "wiki", "--dry-run", "--strict")
    assert rc == 2  # the fragment-less links are still approximate
    assert "anchor unresolved" not in out


def test_pre_existing_broken_anchors_inside_a_split_source_are_reported_with_their_own_line(tmp_path):
    text_ = "# Top\nintro\n## Mid\nsee [dead](#nowhere) and [dead2](other.md#nope) and [ok](#mid)\n## End\nend\n"
    repo = make_repo(tmp_path, {"docs/s.md": text_, "docs/other.md": "# Other\n"})
    rows = [
        row("docs/s.md", "Part-A", "split-into", "1", "L1-L2"),
        row("docs/s.md", "Part-B", "split-into", "1", "L3-L6"),
    ]
    rc, out, err = run_tool(repo, rows, "--subfolder", "wiki", "--dry-run", "--strict")
    assert rc == 0, (out, err)  # already broken before the move: reported, never fatal
    assert "pre-existing broken anchor: docs/s.md:4 -> #nowhere" in out
    assert (
        "pre-existing broken anchor: docs/s.md:4 -> Other.md#nope" in out
        or "docs/s.md:4 -> ../docs/other.md#nope" in out
    )
    assert "anchors: 0 rewritten, 0 unresolved, 2 pre-existing broken" in out


def test_anchor_check_on_the_final_pages_finds_a_broken_fragment():
    pages = {"A.md": "# A\n## Real\n[ok](#real) [bad](#gone) [x](B.md#top) [y](B.md#nowhere)\n", "B.md": "# Top\n"}
    pre = collections.Counter()
    bad = docmove.unresolved_anchors(pages, set(pages), pre)
    assert [(f, ln, raw) for f, ln, raw in bad] == [("A.md", 3, "#gone"), ("A.md", 3, "B.md#nowhere")]
    pre[("A.md", "#gone")] += 1  # already broken before the move
    assert [raw for _, _, raw in docmove.unresolved_anchors(pages, set(pages), pre)] == ["B.md#nowhere"]


def test_heading_slugs_follow_githubs_rules():
    text = (
        "# Hello, World! (v2)\n## Setup\n## Setup\n## Setup\n### 🚀 Launch\n"
        "```\n# in fence\n```\n    # indented code\nSetext\n======\n## Under_score & `code`\n"
    )
    slugs = [h["slug"] for h in docmove.headings(text)]
    assert slugs == ["hello-world-v2", "setup", "setup-1", "setup-2", "-launch", "setext", "under_score--code"]


def test_strict_stops_on_an_unresolved_anchor_and_lists_it(tmp_path, monkeypatch):
    import io

    repo = anchor_repo(tmp_path)
    mp = tmp_path / "map.csv"
    mp.write_text(HEADER + "\n" + "\n".join(MERGE_ROWS) + "\n")
    monkeypatch.setattr(docmove, "unresolved_anchors", lambda *a: [("wiki/Reference-All.md", 4, "#gone")])
    out = io.StringIO()
    docmove.run(repo, str(mp), dry_run=True, subfolder="wiki", out=out)  # not strict: listed, exit 0
    assert "anchor unresolved: wiki/Reference-All.md:4 -> #gone" in out.getvalue()
    assert "1 unresolved" in out.getvalue()
    with pytest.raises(docmove.DocmoveError, match="anchors that no longer resolve"):
        docmove.run(repo, str(mp), dry_run=True, subfolder="wiki", strict=True, out=io.StringIO())


# --------------------------------------------------------------------------- recovery and findings
def make_git_shim(tmp_path, fail_from):
    """A `git` ahead of the real one in PATH that fails every `git mv` from the `fail_from`-th on."""
    import shutil

    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git").write_text(
        "#!/bin/sh\n"
        'case " $* " in *" mv "*)\n'
        '  n=$(cat "$SHIM_COUNT" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$SHIM_COUNT"\n'
        f'  if [ "$n" -ge {fail_from} ]; then echo "shim: git mv refused" >&2; exit 1; fi;;\n'
        "esac\n"
        f'exec {shutil.which("git")} "$@"\n'
    )
    (shim / "git").chmod(0o755)
    return {**os.environ, "PATH": f"{shim}{os.pathsep}{os.environ['PATH']}", "SHIM_COUNT": str(tmp_path / "count")}


def test_a_failure_inside_apply_prints_the_recovery_hint_and_exits_nonzero(tmp_path):
    files = {f"docs/{n}.md": f"# {n}\n" for n in "abcd"}
    repo = make_repo(tmp_path, files)
    rows = [row(f"docs/{n}.md", f"Page-{n}.md") for n in "abcd"]
    rc, out, err = run_tool(repo, rows, env=make_git_shim(tmp_path, 3))
    assert rc != 0 and rc != 64
    assert "git reset --hard HEAD && git clean -fd" in err
    assert "shim: git mv refused" in err
    assert "post-check failed" not in err  # it was apply() that stopped, after the post-check passed


def test_a_destination_that_is_an_ignored_file_outside_the_map_exits_2(tmp_path):
    repo = make_repo(tmp_path, BASE, gitignore="Foo.md\n", ignored={"Foo.md": "local scratch\n"})
    err = fails(repo, [row("docs/setup.md", "Foo.md")])
    assert "collides with an existing path" in err
    assert (repo / "Foo.md").read_text() == "local scratch\n"


def test_wiki_links_rewrite_only_the_page_side_in_githubs_form(tmp_path):
    files = {
        "docs/b.md": "# B\n",
        "docs/label.md": "# Label\n",
        "docs/Home.md": "[[b|label]] [[label|b]] [[b]] [[b#x|b]]\n",
    }
    repo = make_repo(tmp_path, files)
    rows = [
        row("docs/b.md", "Reference-B.md"),
        row("docs/label.md", "Reference-Label.md"),
        row("docs/Home.md", "Home.md"),
    ]
    rc, out, err = run_tool(repo, rows, "--subfolder", "wiki")
    assert rc == 0, (out, err)
    # [[text|page]]: the left side is display text and is never a page, even if a page has that name
    assert (
        text(repo, "wiki/Home.md")
        == "[[b|Reference-Label]] [[label|Reference-B]] [[Reference-B]] [[b#x|Reference-B]]\n"
    )


def test_the_report_suggests_home_for_a_dangling_directory_link(tmp_path):
    repo = slice_repo(tmp_path)
    rc, out, err = run_slice(repo)
    assert rc == 0, (out, err)
    rep = text(repo, "wiki/where-did-it-go.md")
    line = next(ln for ln in rep.splitlines() if "dangling directory link" in ln)
    assert "README.md:3" in line and "docs/pfsense/" in line and "`Home`" in line


# --------------------------------------------------------------------------- Codex findings
def test_a_hardlinked_file_that_would_be_moved_or_rewritten_is_refused(tmp_path):
    repo = make_repo(tmp_path, BASE)
    for n, victim in enumerate(("docs/setup.md", "README.md", "src/main.py")):
        outside = tmp_path / f"outside{n}.txt"
        os.link(repo / victim, outside)
        before = outside.read_bytes()
        # setup.md is moved; README.md links to it (a markdown rewrite); main.py names it (a literal rewrite)
        err = fails(repo, [row("docs/setup.md", "Setup.md")])
        assert "hard link" in err and victim in err
        assert outside.read_bytes() == before
        os.unlink(outside)
        assert os.stat(repo / victim).st_nlink == 1


def make_swap_shim(tmp_path, repo, outside):
    """A `git` that, on the first `git mv`, swaps README.md for a symlink to `outside` (a swap after validation)."""
    import shutil

    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git").write_text(
        "#!/bin/sh\n"
        'case " $* " in *" mv "*)\n'
        '  if [ ! -e "$SHIM_DONE" ]; then : > "$SHIM_DONE"; rm -f "$SHIM_REPO/README.md"; '
        'ln -s "$SHIM_OUTSIDE" "$SHIM_REPO/README.md"; fi;;\n'
        "esac\n"
        f'exec {shutil.which("git")} "$@"\n'
    )
    (shim / "git").chmod(0o755)
    return {
        **os.environ,
        "PATH": f"{shim}{os.pathsep}{os.environ['PATH']}",
        "SHIM_DONE": str(tmp_path / "done"),
        "SHIM_REPO": str(repo),
        "SHIM_OUTSIDE": str(outside),
    }


def test_a_file_swapped_for_a_symlink_after_validation_is_never_written_through(tmp_path):
    repo = make_repo(tmp_path, BASE)
    outside = tmp_path / "outside.txt"
    outside.write_text("do not touch\n")
    rc, out, err = run_tool(repo, [row("docs/setup.md", "Setup.md")], env=make_swap_shim(tmp_path, repo, outside))
    assert rc == 2, (out, err)
    assert "git reset --hard HEAD && git clean -fd" in err and "README.md" in err
    assert outside.read_text() == "do not touch\n"


def test_rewritten_files_are_replaced_not_truncated_and_keep_their_mode(tmp_path):
    repo = make_repo(tmp_path, {**BASE, "scripts/tool.sh": "#!/bin/sh\ncat docs/setup.md\n"})
    os.chmod(repo / "scripts/tool.sh", 0o755)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "mode")
    inode = os.stat(repo / "scripts/tool.sh").st_ino
    rc, out, err = run_tool(repo, [row("docs/setup.md", "Setup.md")])
    assert rc == 0, (out, err)
    st = os.stat(repo / "scripts/tool.sh")
    assert st.st_mode & 0o777 == 0o755 and "Setup.md" in text(repo, "scripts/tool.sh")
    assert st.st_ino != inode  # a new file took the name; a shared inode would have been truncated
    assert not [p for p in os.listdir(repo / "scripts") if p.startswith(".docmove")]


def test_a_stub_target_with_markup_in_its_file_name_is_refused(tmp_path):
    evil = "x`<img src=x onerror=alert(1)>.txt"
    repo = make_repo(tmp_path, {**BASE, evil: "payload\n"})
    rows = [
        row("docs/setup.md", "Setup.md"),
        row("docs/setup.md", "Old-Setup", "stub", notes=f"points to repo file {evil}"),
    ]
    err = fails(repo, rows, header=NOTES_HEADER)
    assert "unsafe" in err


@pytest.mark.parametrize(
    "name,line,probe",
    [("big.txt", "x docs/old.md\n", "x Old.md\n"), ("big.md", "[a](docs/old.md)\n", "[a](Old.md)\n")],
)
def test_sixty_thousand_matches_do_not_make_the_rewrite_quadratic(tmp_path, name, line, probe):
    repo = make_repo(tmp_path, {"docs/old.md": "# Old\n", name: line * 60000})
    t0 = time.time()
    rc, out, err = run_tool(repo, [row("docs/old.md", "Old.md")], timeout=120)
    took = time.time() - t0
    assert rc == 0, (out, err)
    assert text(repo, name).count(probe) == 60000
    assert took < 5, took  # the quadratic version took 15 s or more


# --------------------------------------------------------------------------- post-check guards
def test_line_loss_detected():
    lost, extra = docmove.line_multiset_diff({"a.md": "one\ntwo\n\nthree\n"}, {"A.md": "one\nthree\n"}, [])
    assert (len(lost), len(extra)) == (1, 0)


def test_line_injection_and_comment_exclusion():
    before = {"a.md": "one\n"}
    c = "<!-- docmove: merged from a.md -->"
    assert [len(x) for x in docmove.line_multiset_diff(before, {"A.md": c + "\none\n"}, [c])] == [0, 0]
    _, extra = docmove.line_multiset_diff(before, {"A.md": "one\nsurprise\n"}, [])
    assert len(extra) == 1


def test_link_edits_are_masked_but_text_is_not():
    before = {"a.md": "see [x](old.md) now\n"}
    assert [len(x) for x in docmove.line_multiset_diff(before, {"a.md": "see [x](New.md) now\n"}, [])] == [0, 0]
    assert [len(x) for x in docmove.line_multiset_diff(before, {"a.md": "see [y](New.md) now\n"}, [])] == [1, 1]


def test_verify_reports_loss_and_unaccounted():
    v = {
        "entries": [{"src": "a.md", "dest": "A.md", "action": "move", "section": ""}],
        "before_md": {"a.md": "x\ny\n"},
        "before_broken": [],
        "comments": [],
        "report": "R.md",
        "nonmd_before": {},
        "nonmd_lines": {},
    }
    errs, _, acc = docmove.verify(v, {"A.md"}, {"A.md": "x\n"}, {})
    assert acc == 1 and any("content lost" in e for e in errs)
    errs, _, acc = docmove.verify(v, {"a.md"}, {"a.md": "x\ny\n"}, {})
    assert acc == 0 and any("not accounted" in e for e in errs)
    errs, _, acc = docmove.verify(v, {"A.md"}, {"A.md": "x\ny\n[z](gone.md)\n"}, {})
    assert any("broken by the move" in e for e in errs)


def test_unresolved_links_found():
    bad = docmove.unresolved_links({"a.md": "[x](b.md) [y](nope.md) [z](https://example.com/q)\n"}, {"a.md", "b.md"})
    assert bad == [("a.md", "nope.md")]
