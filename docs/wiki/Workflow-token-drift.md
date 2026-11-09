# token-drift

**What it does.** Fails when a file vendored from another repository (brand design tokens, for example) is not the bytes its
lock pinned and, if you ask, when the lock no longer equals the source repository's file at the commit its ref points to now.
It is read-only and holds no secret.

**Why it exists.** Two sites share brand tokens: the blog owns `brand/tokens.json`, the link page vendors a pinned copy. A
hand edit of the copy, or a change at the source nobody re-vendored, is a visual drift no test of either site notices. The
check is the same for any pair of repositories, so it lives here instead of being copied into both. It reads the same lock file
as [vendored-drift](Workflow-vendored-drift.md); use that workflow when a generator's output must also be checked.

## The lock file

```json
{
  "vendored": "vendor/brand/tokens.json",
  "sha256": "<64 lowercase hex characters>",
  "source": {"repo": "owner/name", "path": "brand/tokens.json", "commit": "<40 hex characters>"}
}
```

Exactly those keys. Paths are relative and must stay inside the repository after symbolic links are followed.

## What fails the job

1. A lock that is missing, unreadable or malformed, or an empty `lock-file`: nothing checked is not a pass.
2. A lock that disagrees with `vendored-path`, `source-repo` or `source-path` when you give them. Put the values in the caller's
   workflow file and an edit of the lock alone cannot point the check at something else.
3. A vendored file that is not a regular file inside the repository (a directory, a FIFO, a symlink out), is larger than 16 MiB,
   or whose SHA-256 differs from the pin. The message names the file and prints both hashes.
4. With `check-live: true`: the source file at the resolved commit differs from the pin. The message names the file, the repository,
   the commit and both hashes.

Every problem is listed before the job fails.

## How the live check resolves the source

`source-ref` (empty means the default branch) is resolved **once** to a commit through `api.github.com`, then the file is
fetched at exactly that commit, so a push between two requests cannot make them disagree. The file's hash is compared, not the
commit id: the source may move on without touching the file, and that is not drift. The commit it checked is printed next to the
lock's own.

A moving ref (or the default branch) is allowed on purpose: noticing that the source changed is the whole point. Pin
`source-ref` to a commit when you only want to prove the lock tells the truth about its own commit. A ref is a plain name
(letters, digits, `.`, `_`, `-`, `/`, no `..`, no leading `-` or `/`); anything else fails before a request is made.

The job token goes to `api.github.com` only, a redirect is refused (never followed), and at most 16 MiB is read. The job token
cannot read another private repository, so the source must be public. `check-live` is off by default so a pull request depends on
nothing outside your repository; run it on a schedule.

## The egress list

`allowed-endpoints` defaults to `api.github.com:443 github.com:443`: `github.com` for the checkout, `api.github.com` for the
commit and the file (the contents API answers the raw bytes directly). No other host is allowed, so a redirect to one fails
instead of leaking a request. The fixture job in this repository's CI runs the live check in `block` mode and goes red if
that list is not enough.

## A minimal caller

```yaml
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 5 * * 1"

permissions:
  contents: read

jobs:
  token-drift:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/token-drift.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      lock-file: vendor/brand/tokens.lock.json
      vendored-path: vendor/brand/tokens.json
      source-repo: owner/name
      source-path: brand/tokens.json
      check-live: ${{ github.event_name == 'schedule' }}
```

To re-vendor: copy the new file, update `sha256` and `source.commit` in the lock, and commit both together.

## Running it locally

`python3 -I scripts/check_token_drift.py --lock vendor/brand/tokens.lock.json [--check-live]` runs the same checks (standard
library only). The workflow carries a byte-identical copy, because a reusable workflow cannot read files from its own
repository; `tests/test_token_drift.py` fails if the copy differs.

## The fixtures prove it can fail

`ci.yml` calls this workflow on `fixture/token-drift/`: a passing pin, a passing live check against this repository's
`LICENSE`, and two planted ones (an edited vendored file; a lock that no longer equals the source) run with `advisory: true`.
`advisory` turns drift, never a malformed input, into a warning. The `drifted` output is `false` on a clean run and `true` on advisory drift, and empty whenever the job fails; `token-drift-control` fails unless
both planted jobs report `drifted=true`. Leave `advisory` off in a real caller.

<!-- inputs -->

## What it refuses to do

It never writes anything, never holds a credential beyond the read-only job token, never follows a redirect, and never passes
when no lock file was given.
