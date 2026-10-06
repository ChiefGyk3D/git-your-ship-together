# dependabot-auto-merge

**What it does.** On a Dependabot pull request, reads what the bump changes and queues the merge for when the required checks
pass, up to a size the caller chooses (`max-update-type`: patch, minor or major).

**Why it exists.** Three things already stand between a dependency bump and the default branch: the seven-day cooldown in
`dependabot.yml`, the `CI green` gate, and a required pull request. What was left was a human clicking merge on a patch bump that
all three had cleared. This workflow removes that click and nothing else.

## Jobs and trust boundaries

One job, `auto-merge`, with `contents: write` and `pull-requests: write`. A write permission on a pull-request trigger is
normally the shape to avoid. It is safe here because **the job never checks the pull request out**: it runs two pinned actions and
the `gh` CLI against the API, so none of the proposed code executes beside the grant. `dependabot/fetch-metadata` verifies the
commits really are Dependabot's before reporting what they change, the job is gated on the pull request's author, and GitHub gives a
fork's pull request a read-only token whatever the workflow asks for. No `pull_request_target`, no checkout, no code.

A major bump, or a pull request whose update type Dependabot did not report, is left open with a notice. The decision **fails closed**:
an update type the workflow does not recognise is never merged.

## A minimal caller

```yaml
name: Dependabot auto-merge
on: pull_request

permissions:
  contents: read

jobs:
  auto-merge:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/dependabot-auto-merge.yml@<sha> # vX.Y.Z
    permissions:
      contents: write        # enable auto-merge on the pull request
      pull-requests: write   # read its Dependabot metadata
```

Two repository settings must be on or nothing happens: **Allow auto-merge** (`gh api -X PATCH repos/OWNER/REPO -F
allow_auto_merge=true`) and a required status check for the merge to wait on. Both are in the baseline and the audit checks
`auto-merge-enabled`. Squash is the default method because a repository that requires linear history refuses a merge commit. The
default egress list is not measured from a run of this workflow, only taken from the GitHub subset of the CI measurement, so it
defaults to `audit` until a real Dependabot bump confirms it.

<!-- inputs -->

## What it refuses to do

It never merges a major bump by default, never merges something it could not classify, and never checks out or runs a pull request.
