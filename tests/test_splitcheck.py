"""splitcheck proves a split dropped and duplicated nothing; this is the check on it.

Each case writes a source and its output pages in a temp dir and runs the real script with
`python3 -I`. The guard bites in both directions: a deleted line and a duplicated line must
come back exit 1 with the line number, and a clean split (including a link-only edit and
provenance comments) must come back exit 0.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "scripts" / "splitcheck.py"

SOURCE = (
    "# Guide\n"  # 1
    "intro line\n"  # 2
    "\n"  # 3
    "## One\n"  # 4
    "see [setup](docs/setup.md#install) for details\n"  # 5
    "step one\n"  # 6
    "\n"  # 7
    "## Two\n"  # 8
    "step two\n"  # 9
    "step two\n"  # 10
)
PAGE1 = "# Guide\nintro line\n\n## One\nsee [setup](Setup.md#install) for details\nstep one\n"
PAGE2 = "## Two\nstep two\nstep two\n"


def run(tmp_path, source, *pages, extra=()):
    src = tmp_path / "source.md"
    src.write_text(source)
    outs = []
    for k, text in enumerate(pages):
        p = tmp_path / f"Page-{k}.md"
        p.write_text(text)
        outs.append(str(p))
    r = subprocess.run(
        [sys.executable, "-I", str(TOOL), *extra, "--source", str(src), "--out", *outs], capture_output=True, text=True
    )
    return r.returncode, r.stdout, r.stderr


def test_clean_split_passes(tmp_path):
    rc, out, err = run(tmp_path, SOURCE, PAGE1, PAGE2)
    assert rc == 0, (out, err)


def test_deleted_line_fails_and_is_listed_by_number(tmp_path):
    rc, out, _ = run(tmp_path, SOURCE, PAGE1.replace("step one\n", ""), PAGE2)
    assert rc == 1
    assert "source line 6" in out
    assert "step one" not in out  # lines are never echoed


def test_deleted_repeated_line_fails(tmp_path):
    rc, out, _ = run(tmp_path, SOURCE, PAGE1, "## Two\nstep two\n")
    assert rc == 1
    assert "source line 9" in out and "source line 10" in out


def test_duplicated_line_fails_and_is_listed_by_page_and_number(tmp_path):
    rc, out, _ = run(tmp_path, SOURCE, PAGE1, PAGE2 + "step one\n")
    assert rc == 1
    assert "duplicated: " in out and "Page-1.md line 4" in out


def test_link_only_edit_passes_but_a_text_edit_fails(tmp_path):
    rc, out, _ = run(tmp_path, SOURCE, PAGE1.replace("Setup.md#install", "other/Elsewhere.md"), PAGE2)
    assert rc == 0, out
    rc, out, _ = run(tmp_path, SOURCE, PAGE1.replace("[setup]", "[set up]"), PAGE2)
    assert rc == 1


def test_wiki_link_edit_passes(tmp_path):
    rc, _, _ = run(tmp_path, "See [[Old-Page]] now\n", "See [[New-Page]] now\n")
    assert rc == 0


def test_provenance_comments_are_ignored(tmp_path):
    p1 = "<!-- from: docs/guide.md L1-L7 -->\n" + PAGE1
    p2 = "<!-- docmove: split from docs/guide.md L8-L10 -->\n" + PAGE2
    rc, out, _ = run(tmp_path, SOURCE, p1, p2)
    assert rc == 0, out
    # a provenance comment cannot stand in for a missing line
    rc, _, _ = run(tmp_path, "<!-- note -->\nkeep\n", "<!-- from: x -->\nkeep\n")
    assert rc == 1


def test_blank_lines_are_ignored(tmp_path):
    rc, out, _ = run(tmp_path, SOURCE, PAGE1.replace("\n\n", "\n"), "\n\n" + PAGE2 + "\n\n")
    assert rc == 0, out


def test_new_lines_in_the_pages_are_allowed(tmp_path):
    rc, out, _ = run(tmp_path, SOURCE, "## Learn it\n" + PAGE1, PAGE2 + "See also the first page.\n")
    assert rc == 0, out


def test_a_line_moved_to_the_other_page_still_passes(tmp_path):
    p1 = PAGE1.replace("step one\n", "")
    p2 = PAGE2 + "step one\n"
    rc, out, _ = run(tmp_path, SOURCE, p1, p2)
    assert rc == 0, out


def test_a_page_may_be_empty_of_source_lines_but_the_union_must_cover(tmp_path):
    rc, _, _ = run(tmp_path, SOURCE, PAGE1 + PAGE2, "")
    assert rc == 0
    rc, _, _ = run(tmp_path, SOURCE, "", "")
    assert rc == 1


def test_code_fence_lines_count_and_links_in_them_are_not_masked(tmp_path):
    src = "```\n[x](old.md)\n```\n"
    rc, _, _ = run(tmp_path, src, "```\n[x](new.md)\n```\n")
    assert rc == 1  # inside a fence the link text is content, not a link edit
    rc, _, _ = run(tmp_path, src, src)
    assert rc == 0


def test_crlf_does_not_matter(tmp_path):
    rc, out, _ = run(tmp_path, SOURCE.replace("\n", "\r\n"), PAGE1, PAGE2)
    assert rc == 0, out


def test_unreadable_input_is_exit_2_not_a_verdict(tmp_path):
    r = subprocess.run(
        [sys.executable, "-I", str(TOOL), "--source", str(tmp_path / "missing.md"), "--out", str(tmp_path / "x.md")],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 2
    r = subprocess.run([sys.executable, "-I", str(TOOL), "--source", "a"], capture_output=True, text=True)
    assert r.returncode == 2  # argparse usage error


def test_copy_mode_needs_the_copied_lines_only(tmp_path):
    rc, out, _ = run(tmp_path, SOURCE, "## Two\nstep two\nstep two\n", extra=["--copy", "--lines", "L8-L10"])
    assert rc == 0, out
    rc, out, _ = run(tmp_path, SOURCE, "## Two\nstep two\n", extra=["--copy", "--lines", "L8-L10"])
    assert rc == 1 and "source line 10" in out
    # extra copies of a line are not a failure in copy mode, but are in split mode
    rc, _, _ = run(tmp_path, SOURCE, PAGE1 + PAGE2, PAGE2, extra=["--copy"])
    assert rc == 0
    rc, _, _ = run(tmp_path, SOURCE, PAGE1 + PAGE2, PAGE2)
    assert rc == 1


def test_bad_lines_range_is_exit_2(tmp_path):
    rc, _, err = run(tmp_path, SOURCE, PAGE1, PAGE2, extra=["--copy", "--lines", "4-9"])
    assert rc == 2


# --- provenance chunks: shared pages and common lines must not give false duplicates -----------
CODE_SOURCE = (
    "# Guide\n"  # 1
    "intro\n"  # 2
    "```\n"  # 3
    "code line\n"  # 4
    "```\n"  # 5
    "| a | b |\n"  # 6
    "|---|---|\n"  # 7
    "## Part B\n"  # 8
    "```\n"  # 9
    "other code\n"  # 10
    "```\n"  # 11
    "|---|---|\n"  # 12
)
OTHER_SOURCE_CHUNK = (
    "<!-- docmove: merged from docs/other.md -->\n```\nunrelated\n```\n|---|---|\n"  # shares fence and separator lines
)
CH1 = "<!-- docmove: split from docs/guide.md L1-L7 -->\n" + "".join(CODE_SOURCE.splitlines(True)[:7])
CH2 = "<!-- docmove: archived from docs/guide.md L8-L12 -->\n" + "".join(CODE_SOURCE.splitlines(True)[7:])


def run_chunks(tmp_path, source, *pages, extra=("--source-name", "docs/guide.md")):
    return run(tmp_path, source, *pages, extra=extra)


def test_chunk_mode_ignores_other_sources_and_common_lines_on_shared_pages(tmp_path):
    rc, out, _ = run_chunks(tmp_path, CODE_SOURCE, OTHER_SOURCE_CHUNK + CH1, CH2)
    assert rc == 0, out
    # the same pages in whole-page mode count the shared fence and separator lines twice
    rc, _, _ = run(tmp_path, CODE_SOURCE, OTHER_SOURCE_CHUNK + CH1, CH2)
    assert rc == 1


def test_chunk_mode_source_name_defaults_to_a_path_suffix_match(tmp_path):
    src = tmp_path / "docs" / "guide.md"
    src.parent.mkdir()
    src.write_text(CODE_SOURCE)
    pages = []
    for k, t in enumerate((OTHER_SOURCE_CHUNK + CH1, CH2)):
        p = tmp_path / f"P{k}.md"
        p.write_text(t)
        pages.append(str(p))
    r = subprocess.run(
        [sys.executable, "-I", str(TOOL), "--source", str(src), "--out", *pages], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout


def test_chunk_mode_still_sees_a_deleted_line_in_the_chunk(tmp_path):
    rc, out, _ = run_chunks(tmp_path, CODE_SOURCE, OTHER_SOURCE_CHUNK + CH1.replace("code line\n", ""), CH2)
    assert rc == 1 and "source line 4" in out
    assert "code line" not in out


def test_chunk_mode_still_sees_a_duplicated_line_in_the_chunk(tmp_path):
    rc, out, _ = run_chunks(tmp_path, CODE_SOURCE, OTHER_SOURCE_CHUNK + CH1, CH2 + "other code\n")
    assert rc == 1 and "duplicated" in out


def test_chunk_mode_sees_lines_in_no_chunk_range_and_overlapping_ranges(tmp_path):
    gap = CH2.replace("L8-L12", "L9-L12").replace("## Part B\n", "")
    rc, out, _ = run_chunks(tmp_path, CODE_SOURCE, CH1, gap)
    assert rc == 1 and "source line 8" in out
    overlap = CH2.replace("L8-L12", "L7-L12") + "|---|---|\n"
    rc, out, _ = run_chunks(tmp_path, CODE_SOURCE, CH1, overlap)
    assert rc == 1 and "duplicated" in out


def test_chunk_mode_copy_comments_belong_to_copy_mode_only(tmp_path):
    copy = "<!-- docmove: copied from docs/guide.md L1-L7 -->\n" + "".join(CODE_SOURCE.splitlines(True)[:7])
    rc, out, _ = run_chunks(tmp_path, CODE_SOURCE, CH1, CH2, copy)
    assert rc == 0, out  # a copy elsewhere is not a duplicate of the split
    rc, out, _ = run_chunks(
        tmp_path, CODE_SOURCE, copy, extra=("--copy", "--lines", "L1-L7", "--source-name", "docs/guide.md")
    )
    assert rc == 0, out


def test_bom_does_not_matter(tmp_path):
    rc, out, _ = run(tmp_path, "﻿# Guide\nbody\n", "# Guide\nbody\n")
    assert rc == 0, out
