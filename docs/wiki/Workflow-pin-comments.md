# pin-comments

**What it does.** Fails when the `# vX.Y.Z` comment on a SHA-pinned `uses:` line does not name the commit the line is pinned to.
It is read-only, holds no secret beyond the job's own read-only token and checks nothing out but your repository.

**Why it exists.** A pin by commit is only reviewable when its version comment is true. zizmor's `ref-version-mismatch` audit
checks this, but only for callers that run zizmor. This is the same check as a job of its own. It is opt-in; nothing existing
changes.

## What fails the job

1. A `uses: owner/repo@<40 hex>` line with no version comment (`# v1.2.3`, `# v4`).
2. A comment whose tag does not exist in `owner/repo`.
3. A tag that resolves to a different commit than the pin. The message prints both.
4. No workflow or action file at all: nothing checked is not a pass.
5. A lookup that could not be completed (network error, timeout, rate limit, unreadable answer, or the budget of 200 lookups or
   120 seconds used up) is reported `UNVERIFIED` and fails the job. Set `unverified: warn` to print those lines and pass; a real
   mismatch still fails.

Files scanned: `.github/workflows/*.yml|yaml` and `.github/actions/**/action.yml|yaml`. Local `./` and `docker://`
references, and references not pinned to a full commit, are left alone. Every problem is listed before the job fails.

## A minimal caller

```yaml
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  pin-comments:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/pin-comments.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
```

## Running it locally

The script is `scripts/check_pin_comments.py`, standard library only. `GITHUB_TOKEN=... python3 -I
scripts/check_pin_comments.py` runs the same checks (the token is optional and sent only over https). The workflow carries a
byte-identical copy, because a reusable workflow cannot read files from its own repository; `tests/test_pin_comments.py` fails
if the copy differs.

<!-- inputs -->

## What it refuses to do

It never writes anything, never sends its token anywhere but the GitHub API host, and never passes on a lookup it could not make
unless you ask for `unverified: warn`.
