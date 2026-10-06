# project-sync

**What it does.** Keeps an **organization-owned** GitHub Projects v2 board current: adds an issue or pull request when it opens, moves it
to Done with a date when it closes or merges, and a weekly reconcile repairs what an event missed. The full explanation, including why it
uses a GitHub App and never a personal token, is on [Keeping a project board current](Keeping-a-project-board-current.md); this is the
reference.

**Why it exists.** A board that depends on someone dragging cards is stale. GitHub's built-ins cannot add every issue from a repository,
set a done date or repair a missed event, and there is no built-in that adds an item from a repository to a user-owned project.

## Jobs and trust boundaries

One job, `sync`, with `contents: read` and `id-token: write` (the Doppler fetch of the App key). Its token is the App installation token,
one hour, scoped to the calling repository's installation. It has **no checkout** and the pull request's title and body are never read, which
is why the caller may react to `pull_request_target`.

## A minimal caller

```yaml
on:
  issues:
    types: [opened, reopened, closed, edited]
  pull_request_target:   # zizmor: ignore[dangerous-triggers] -- no checkout; see the explanation page
    types: [opened, reopened, ready_for_review, converted_to_draft, closed]
  schedule:
    - cron: '17 5 * * 1'
  workflow_dispatch:

jobs:
  sync:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/project-sync.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      id-token: write
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      project-url: https://github.com/orgs/<org>/projects/<n>
      client-id: ${{ vars.PROJECTS_APP_CLIENT_ID }}
      doppler-project: projects
      doppler-config: prd
      doppler-identity-id: ${{ vars.PROJECTS_DOPPLER_IDENTITY_ID }}
      doppler-trusted-refs-only: false   # required for pull_request_target; never copy this beside a checkout
```

A caller whose identity cannot cover a pull-request subject sets `pull-request-events: false` (the job skips on that event) or drops the trigger.
`app-id` is deprecated and accepted for one release; pass `client-id`. These were issues #91, #92 and #93, fixed in #103.

<!-- inputs -->

## What it refuses to do

It refuses a user-owned project URL before any API call, never changes an option or field it cannot find by name (it lists the real
ones instead), never calls `updateProjectV2Field`, and has no personal-token path.
