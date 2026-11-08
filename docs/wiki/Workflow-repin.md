# repin

**What it does.** On a schedule, looks at your repository's pins of this repository's reusable workflows and, when they are
behind the latest release, opens ONE pull request that moves them all. The pull request changes the pin SHA and the `# vX.Y.Z`
comment and nothing else, links the release and the changelog, and is never merged by the job. It runs
[`scripts/repin.sh`](Script-repin.md), inlined byte for byte.

**Why it exists.** A release reaches a caller only when the caller re-pins, and the maintainer's rule is that a GYST bump moves
every caller. On 2026-11-07 one caller was two releases behind. The re-pin is mechanical, so a schedule does it and a human
reads the changelog and merges.

<!-- inputs -->

## The credential

Opening this pull request takes a GitHub App, not the job's token: a branch that changes `.github/workflows/` needs the
`workflows` permission, which `GITHUB_TOKEN` can never hold, and a pull request opened with `GITHUB_TOKEN` starts no checks, so
it could never show green. The job mints a one-hour installation token with `actions/create-github-app-token`, limited to the
calling repository and to three permissions, each with its reason in the workflow:

| Permission | Why |
|---|---|
| Contents: write | push the branch `repin/gyst-<tag>` |
| Pull requests: write | open the pull request, and read whether one is already open |
| Workflows: write | the branch changes files under `.github/workflows/` |

The job's own token stays `contents: read`. The App's Client ID is passed as `client-id` (a repository variable, an identifier)
and its private key as the `APP_PRIVATE_KEY` secret. No personal access token is accepted. The token reaches git through an
askpass helper that reads it from the environment, never a URL, a header or the repository's config.

Without the App, on a pull request, off the default branch, or with `dry-run: true`, the job **reports only**: it prints where
each pin stands (the same output as `repin.sh status`) and succeeds.

## Adopting it

Create the App (Contents, Pull requests and Workflows: Read and write, nothing else), install it on the repository, then add:

```yaml
on:
  schedule:
    - cron: "17 6 * * 1"
  workflow_dispatch:

permissions: {}

jobs:
  repin:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/repin.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      client-id: ${{ vars.REPIN_APP_CLIENT_ID }}
    secrets:
      APP_PRIVATE_KEY: ${{ secrets.REPIN_APP_PRIVATE_KEY }}
```

Run it once with `dry-run: true` to see the report. A pin-only pull request that is green may be merged by the maintainer; this
job never does.

## What it checks first

For each pin that moves, it reads the called workflow at the old and the new commit and compares its inputs with the `with:`
keys you set. It stops, opens nothing and fails the job, naming them, when the new release **drops** an input you set,
**changes its type**, or **adds a required input** (no default) you do not set. A changed default of an input you do not set is
listed in the pull request body as a note, not a blocker. A definition it cannot read is a stop, not a pass. To adopt such a
release, adjust the caller by hand.

## How it is tested

`tests/test_repin.py` holds the inlined copy identical to the script, the three permissions and their repository scope, the
decision step (schedule or manual run, default branch, App configured, not a dry run), and that nothing in the workflow merges.
`.github/workflows/ci.yml` runs it from this repository's own ref in report-only mode.

## What it refuses to do

- It does not merge, enable auto-merge or approve.
- It does not change an input, a job, a permission or any line that is not a pin, and it stops when the release changes an input
  you use.
- It does not open a pull request from a pull request, from a branch other than the default, or without the App.
- It does not accept a personal access token.
