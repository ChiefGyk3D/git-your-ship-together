# vendored-drift

**What it does.** Fails when a file vendored from another repository (design tokens, a schema, a shared configuration) is not
the bytes its lock pinned, or when what is generated from it is stale. It is read-only, holds no secret and checks nothing out
but your repository.

**Why it exists.** Two repositories that share brand tokens each grew their own copy of the same script. The check is generic:
a lock file names the vendored path, the source repository, path and commit, and the SHA-256. It is opt-in; nothing existing
changes.

## The lock file

One JSON object per vendored file, in your repository:

```json
{
  "vendored": "vendor/brand/tokens.css",
  "sha256": "<64 lowercase hex characters>",
  "source": {"repo": "owner/name", "path": "dist/tokens.css", "commit": "<40 hex characters>"}
}
```

Exactly those keys; a typo for one is a failure, not an ignored field. Paths are relative and must stay inside the repository
after symbolic links are followed. Duplicate keys, a short commit, an uppercase hash, a vendored path that is a directory or a
FIFO, and a lock larger than 1 MiB all fail.

## What fails the job

1. A lock that is missing, unreadable or malformed. An empty `lock-files` fails too: nothing checked is not a pass.
2. A vendored file whose SHA-256 differs from the pin. The message prints both hashes.
3. With `generator-command`: that command with `--check` appended exits non-zero. It is split like a shell would split it and
   run **without** one, from the repository root, with only `PATH`, `HOME`, `LANG`, `LC_ALL` and `TMPDIR` in its environment,
   so a secret in the job cannot reach it and `;` or `$(...)` are plain arguments. Its output is printed prefixed and quoted,
   so it cannot forge a workflow command.

Every problem is listed before the job fails, not just the first.

## A minimal caller

```yaml
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  drift:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/vendored-drift.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      lock-files: vendor/brand/tokens.lock.json
      generator-command: python3 scripts/generate_tokens.py
```

To re-vendor: copy the new file, update `sha256` and `source.commit` in the lock, regenerate, and commit all of it together.
The check then passes only if all four agree.

## Running it locally

The script is `scripts/check_vendored_drift.py`, standard library only. `python3 -I scripts/check_vendored_drift.py --lock
vendor/brand/tokens.lock.json` runs the same checks. The workflow carries a byte-identical copy, because a reusable workflow
cannot read files from its own repository; `tests/test_vendored_drift.py` fails if the copy differs.

<!-- inputs -->

## What it refuses to do

It never writes anything, never holds a credential, and never passes when no lock file was given.
