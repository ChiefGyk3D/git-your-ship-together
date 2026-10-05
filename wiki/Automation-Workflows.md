# Automation Workflows

The workflows that keep the surrounding machinery running: Dependabot merging,
project boards, docs and the wiki. Full input tables are in the README.

## dependabot-auto-merge

`.github/workflows/dependabot-auto-merge.yml`
([README](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#dependabot-auto-merge)).

Three things already stand between a dependency bump and the default branch: the
seven-day cooldown, the `CI green` gate, and a required pull request. What was left
was a human clicking *merge* on a patch bump all three had cleared. This workflow
removes that click and nothing else.

- `max-update-type` (default `minor`) is the largest semver change that may merge on
  its own. A grouped bump is judged by its largest step.
- A **major** bump, or one whose update type Dependabot did not report, is left open
  with a notice. **It fails closed**: an unrecognised type is never merged.
- Two settings must be on or nothing happens: *Allow auto-merge* on the repository, and
  a required status check for the merge to wait on. Both are in the
  [baseline](Repository-Baseline).

**Why `contents: write` on a pull-request trigger is safe here** (normally the shape to
avoid): the job **never checks the pull request out**. It runs two pinned actions and
the `gh` CLI against the API, so none of the proposed code executes beside the grant.
`dependabot/fetch-metadata` verifies the commits are really Dependabot's, the job is
gated on the PR author, and GitHub gives a fork's PR a read-only token regardless.

## project-sync

`.github/workflows/project-sync.yml`
([README](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#keeping-a-project-current)).

Keeps a **GitHub Projects v2 board** in step with issues and pull requests.
**Organization-owned projects only**: its one credential is a GitHub App installation
token, and GitHub Apps have no user-account Projects permission. The script refuses a
`/users/` project URL before making any API call.

| Event | Result |
|---|---|
| Issue opened | Added to the board; status `Backlog` if it has none |
| PR opened / ready / reopened | Added; `In progress`, or `Backlog` while draft |
| Closed or merged | `Done`, with the close date set |
| Weekly schedule, manual run | **Reconcile**: repairs whatever an event missed |

Design points worth studying:

- **It never touches a field it was not told about.** It never calls
  `updateProjectV2Field`: that mutation regenerates option ids and wipes values across the board.
- **An unknown option or field name is refused before anything changes**, with a sentence listing
  the options that do exist.
- **Reconcile is cheap:** it walks the board once and the repository once, in pages of 100,
  with no query per item. It never reopens an item.
- **`pull_request_target` is used safely**: the job has *no checkout*, its one step is a script
  that reads the event payload as JSON data and never expands it into a shell, and the
  PR title/body are never read. The caller must set `doppler-trusted-refs-only: false`
  because that event counts as untrusted for the Doppler gate. **Do not copy that line into a
  caller that checks out the pull request.**
- **The credential is a GitHub App, never a personal token.** The App's private key lives in Doppler
  (`PROJECTS_APP_PRIVATE_KEY`), is fetched over OIDC and traded for a token that lives one hour,
  is scoped to the calling repositories, and names the *App* in the audit log. The README has
  the nine-step App setup and a safe first-run procedure using `dry-run: true`.
- The logic is `scripts/project_sync.py`, standard library only, with recorded API responses in
  `tests/fixtures/project_sync/`. The workflow carries a verbatim inlined copy and a test
  checks the copy.

## docs-pages

`.github/workflows/docs-pages.yml`
([README](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#docs-pages)).

Builds a static site on **every pull request** and deploys to GitHub Pages from the
**default branch only**. Built for MkDocs (`mkdocs build --strict`) but both commands are
inputs, so Sphinx, mdBook or a script work.

- The `build` job runs your commands with `contents: read` and no token. A strict build
  fails the PR, so a broken link is caught in review rather than published as a 404.
- The `deploy` job holds `pages: write` and `id-token: write`, runs none of your commands, and
  uses a fixed concurrency group that queues deployments and never cancels one.
- **One-time owner step:** Settings, Pages, Source: **GitHub Actions**. Until then `deploy` fails
  with a message naming the URL. `deploy: false` builds only.

## wiki-publish

`.github/workflows/wiki-publish.yml`
([README](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#wiki-publish)).

For a repository whose GitHub wiki is a **generated mirror**, never a place to write. Every run
replaces every page, so a page the generator stops writing disappears. **This is how this wiki is
published**; see [Maintaining This Wiki](Maintaining-This-Wiki).

- Two jobs: `generate` (`contents: read`, runs your commands) and `publish` (`contents: write`, runs
  *none* of your code, no checkout of your repository). The write token never sits beside your code.
- An empty tree is refused, because publishing it would empty the wiki.
- `publish` runs only from the default branch and never from a pull request. The commit is by
  `github-actions[bot]` and names the source commit. Nothing is pushed when nothing changed.
- **One-time owner step GitHub only offers in the UI:** a wiki's git repository does not exist until
  its first page is created. Create any page once, then re-run.
