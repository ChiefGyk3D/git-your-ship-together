# base-image-digest

**What it does.** On a schedule, checks each external base image your Dockerfile or Containerfile pins by digest
(`FROM image:tag@sha256:...`) against what that tag points to today. When the tag has moved, it scans the pinned digest and the
current digest with Trivy and fails if the pinned one has a fixable HIGH or CRITICAL finding that the current one does not.

**Why it exists.** A digest pin freezes the build. When the maintainers republish the tag with a fix, nothing tells you until a
release scan fails at tag time (a downstream project's v0.2.1 failed that way). This surfaces it on an ordinary Monday instead.
It is opt-in; nothing existing changes.

## How the verdict is reached

For each pinned external image:

1. Resolve the tag's current digest with `docker buildx imagetools inspect`. A failure to resolve fails the job.
2. If it equals the pin, stop: there is nothing newer to move to.
3. Otherwise scan both digests with the Trivy binary pinned by hash in [verify-published](Workflow-verify-published.md), with the flags
   [container-release](Workflow-container-release.md) uses: `trivy-severity` (`CRITICAL,HIGH`), `trivy-ignore-unfixed` (`true`) and
   `trivyignores`.
4. Fail if the pinned report has a finding (advisory ID and package, with a fixed version) that the current report lacks.

A finding both digests share does not fail, since bumping would not help. A finding with no fix does not fail. A Trivy error
fails the job; it is never read as "nothing found". The findings and the line to change are written to the job summary.
`exit-code: "0"` reports without failing.

The Dockerfile is read by `scripts/base_image_digest.py` (inlined byte for byte; `tests/test_base_image_digest.py` holds the copy
identical). It follows `FROM --platform=... image:tag@sha256:... AS name`, line continuations, comments, stages (skipped) and
`scratch`, and resolves `ARG` defaults set before the first `FROM`. It fails on a `FROM` with no digest (unless
`allow-unpinned`), a digest with no tag, a variable it cannot resolve, a reference with anything outside the image grammar,
and a file with no pinned external image.

## Scheduling it

The workflow is `workflow_call` only, so the schedule lives in your caller:

```yaml
on:
  schedule:
    - cron: "23 5 * * 1"   # weekly; choose your own minute
  workflow_dispatch:

permissions:
  contents: read

jobs:
  base-image:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/base-image-digest.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      dockerfile: Containerfile
```

A red scheduled run is what notifies the repository's watchers. The job holds no `issues: write` on purpose (a called workflow's
grants are checked when the caller starts, so asking for one would break every caller that did not give it). A caller that
wants a tracking issue adds a job with `needs: base-image` and `if: failure()` that opens or updates one.

## Limits

Public registries only: no credential is passed. One platform (`platform`). A registry that is not Docker Hub or GHCR needs its
hosts in `extra-allowed-endpoints`. The comparison is by advisory ID and package.

<!-- inputs -->

## What it refuses to do

It never writes to the repository, never opens an issue, holds no secret and passes nothing it could not scan.
