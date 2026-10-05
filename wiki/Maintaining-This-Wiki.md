# Maintaining This Wiki

## The wiki is a mirror, not a place to write

**Do not edit pages on github.com.** The next publish replaces every page, so a web edit is lost and a page that
is not in the source is deleted. The source of truth is the **`wiki/` directory in the repository**, reviewed in pull
requests like everything else.

```
wiki/*.md  ──▶ scripts/gen_wiki.py ──▶ wiki-out/ ──▶ wiki-publish.yml ──▶ the GitHub wiki
 (source)      (checks + stamps)        (artifact)     (default branch only)
```

- **`wiki/`**: flat Markdown files, the way a GitHub wiki stores them. `Home.md` is the front page,
  `_Sidebar.md` the navigation, `_Footer.md` the footer. File name `Foo-Bar.md` is the page "Foo Bar" and is linked as `[text](Foo-Bar)`.
- **`scripts/gen_wiki.py`**: standard library only. Refuses missing `Home.md`, subdirectories, links that point at no page,
  and pages missing from the sidebar. It substitutes `{{commit}}` and `{{commit_short}}` in `_Footer.md` (and nowhere else) with the commit being published.
- **`.github/workflows/wiki.yml`**: calls the repository's own [`wiki-publish.yml`](Automation-Workflows#wiki-publish).
  It **generates on every pull request** touching the wiki (so a broken link fails review) and **publishes only from `main`**.
- **`tests/test_wiki.py`**: the drift guard (below).

## How it is kept up to date

Documentation rots when nothing fails. Three things make this one fail loudly:

1. **A drift test.** `tests/test_wiki.py` fails if any of these exist in the repository but are never mentioned in the wiki:
   a workflow under `.github/workflows/`, a script under `scripts/`, a composite action, an audit check ID, a test file, or a
   file in `baseline/`. Add a workflow, forget the wiki, and CI says which page needs a line.
2. **A link check.** A renamed or deleted page with links to it fails the build.
3. **A habit, written down.** The pull-request template has a checkbox ("does this change what the wiki says?") and
   [Contributing and Developing](Contributing-and-Developing) lists the wiki in the checklist for adding a workflow.

A test can only prove a page *mentions* a thing, not that what it says is still true. So the rule for authors is:

> **If your change alters what a person would read, change the wiki page in the same pull request.**

Wiki pages deliberately **link to the README for input tables and defaults instead of copying them**. Duplicated tables are the
first thing to rot, and the README's tables are already tested. Copy ideas into the wiki, not reference data.

## One-time setup (the owner's)

GitHub creates a wiki's git repository only when its first page is made in the UI, and offers nothing else for it:

1. Enable **Wikis** in the repository's Settings (it is on by default).
2. Make sure at least one page exists. (This repository's wiki already has `Home`.)
3. Merge a change under `wiki/`. The `wiki` workflow publishes it; if the wiki has no first page yet, the publish job fails with
   a message naming this step.

The first publish **replaces** the placeholder `Home` page with the real one.

## Adding or changing a page

1. Edit or add `wiki/Some-Page.md`.
2. Add it to `wiki/_Sidebar.md` (the generator insists) and link it from a related page.
3. Run the generator locally; it prints what is wrong:
   ```sh
   python scripts/gen_wiki.py --out /tmp/wiki-preview
   pytest tests/test_wiki.py
   ```
4. Open a pull request. The `wiki` workflow generates (and does not publish) on the PR; the merge publishes.

## Writing guidance

- **Explain why before how.** This wiki's reader is often learning; the reasoning is the point.
- **Link, don't copy** reference data (input tables, defaults, commands that change). Say what a thing is for; link to the authority.
- **No numbers that rot** ("14 workflows"): say "every reusable workflow" and let the tables count.
- **Nothing secret, ever.** No tokens, no private hostnames, no UUIDs. Use placeholders (`OWNER/REPO`, `<sha>`).
- Use absolute `https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/...` links for repository files: a wiki cannot link relatively into the repo.
