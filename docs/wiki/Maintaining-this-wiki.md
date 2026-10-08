# Maintaining this wiki

## The wiki is a mirror, not a place to write

**Do not edit pages on github.com.** Every publish replaces every page, so a web edit is lost and
a page that is not in the source is deleted. The source of truth is **`docs/wiki/`**, reviewed in pull
requests like everything else.

```
docs/wiki/*.md ──▶ scripts/gen_wiki.py ──▶ wiki-out/ ──▶ wiki-publish.yml ──▶ the GitHub wiki
   (source)        (links, tables, footer)  (artifact)    (default branch only)
```

- **`docs/wiki/`**: Markdown files, one per page. `Home.md` is the front page, `_Sidebar.md` the navigation.
  A page's name is its file name, and links between pages are written as ordinary relative links
  (`[Glossary](Glossary.md)`); the generator rewrites them for a flat wiki.
- **`scripts/gen_wiki.py`**: rewrites links (a link to nothing is an error; a link to anything else in the
  repository becomes a link to that file on `main`), writes `_Footer.md` naming the commit, and **renders the inputs,
  secrets and outputs tables of every reusable workflow from its `workflow_call` block**. `--check` writes nothing and
  exits 1 if the tree it is pointed at is stale.
- **`.github/workflows/wiki.yml`**: calls the repository's own [`wiki-publish.yml`](Workflow-wiki-publish.md) on every push to `main`.
- **`tests/test_wiki.py`**: the guard, below.

## How it is kept up to date

Documentation rots when nothing fails. Five things make this one fail loudly:

1. **Tables are generated, not typed.** A workflow page holds one inputs marker (an HTML comment, copy it from any existing
   `Workflow-*.md` page) and the generator fills it from the YAML. Add an input and the page gains it on the next publish; a table cannot say what the workflow does not.
2. **A new reusable workflow without a page fails the build**, and so does a page without its marker.
3. **A drift test.** `tests/test_wiki.py` also fails if any of these exist in the repository but are never mentioned in
   the wiki: a workflow under `.github/workflows/`, a script under `scripts/`, a composite action, an audit check, a test file, or
   a file in `baseline/`. Add one, forget the wiki, and CI says which page needs a line.
4. **Release facts are generated, not typed.** A hand page that needs the current version, the pin or a release date writes
   a placeholder, and `scripts/gen_wiki.py` fills it from git at generation time: `\{{latest_release}}` (the newest `vX.Y.Z`
   tag reachable from HEAD), `\{{latest_pin}}` (that tag's commit SHA, not the tag object's) and `\{{latest_release_date}}`.
   The Roadmap's `\{{unreleased}}` becomes one bullet per merge to `main` since that tag. A test fails if a hand page holds
   a literal 40-hex SHA or a `# vX.Y.Z` pin comment, so a release cannot leave a stale pin behind. Historical mentions
   ("since v1.10.0") stay literal; to show a placeholder's own name in prose, put a backslash before it.
   The generator reads tags, so a checkout that runs it needs them (`fetch-depth: 0`); `wiki-publish.yml` and the test job fetch them.
5. **A habit, written down.** The pull-request template has a checkbox ("does this change what the wiki says?") and
   [Contributing and developing](Contributing-and-developing.md) lists the wiki in the checklist for adding a workflow.

A test can only prove a page *mentions* a thing, not that what it says is still true. So the rule for authors is:

> **If your change alters what a person would read, change the wiki page in the same pull request.**

Generated tables carry reference data. Prose pages should explain what a thing is *for* and link to the authority rather than
copying values that change.

## At a release

The version, pin and date everywhere are already right: they follow the tag. One manual step remains, in the pull request or
commit that follows the tag: **move the Roadmap's generated "Unreleased" list into a dated block** under "Released"
(`### vX.Y.Z (YYYY-MM-DD)`), written from the release notes (`gh release view vX.Y.Z`). Until you do, the Unreleased
section simply reads "Nothing yet" and the new release's contents are missing from the history, which is the only thing a
release can still leave stale.

## One-time setup (the owner's)

GitHub creates a wiki's git repository only when its first page is made in the UI, and offers nothing else for it:

1. Enable **Wikis** in the repository's Settings.
2. Make sure at least one page exists.
3. Merge a change. The `wiki` workflow publishes; if the wiki has no first page yet, the publish job fails with
   a message naming this step.

The first publish **replaces** every existing page, including any placeholder.

## Adding or changing a page

1. Edit or add `docs/wiki/Some-page.md`. It must open with a `# Title` line and contain no em dash.
2. Add it to `docs/wiki/_Sidebar.md` and link it from a related page.
3. Check it generates, and run the wiki tests:
   ```sh
   python scripts/gen_wiki.py --check
   pytest tests/test_wiki.py
   ```
4. Open a pull request. Merging publishes.

A page about a reusable workflow is named `Workflow-<name>.md`, contains that marker once, and ends its argument with a
`## What it refuses to do` section.

## Writing guidance

- **Explain why before how.** The reader is often learning; the reasoning is the point.
- **Link, don't copy** reference data. Say what a thing is for; link to the authority.
- **No numbers that rot** ("14 workflows"): say "every reusable workflow" and let the tables count.
- **Nothing secret, ever.** No tokens, no private hostnames, no UUIDs. Use placeholders (`OWNER/REPO`, `<sha>`).
- Link to repository files with a relative path (`../../README.md`); the generator checks it exists and publishes a link to `main`.
