# Calling the Workflows

This page is the pattern every caller follows. Per-workflow examples and the
full input tables are in the README
([Calling the workflows](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#calling-the-workflows)).
The [Workflow Catalog](Workflow-Catalog) helps you choose which to call.

## 1. Pin a commit, with the version in a comment

```yaml
uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@<sha> # vX.Y.Z
```

Never `@main`, never `@v1`. The SHA is what runs; the comment is for humans and
for zizmor, which fails a caller whose comment and SHA disagree.

To resolve a tag to the right SHA:

```sh
git ls-remote --tags https://github.com/ChiefGyk3D/git-your-ship-together 'refs/tags/vX.Y.Z*'
```

Take the line ending in `^{}` (the peeled **commit**) when there is one. Without
it, the tag is lightweight and the single line is already a commit. Dependabot
then moves the pin and the comment together whenever a new tag is cut.

## 2. Pass secrets by name

```yaml
secrets:
  DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}   # optional fallback; unset means OIDC only
```

Never `secrets: inherit`. `DOPPLER_TOKEN` is the Service Token fallback and may
be unset; every adopted repository leaves it unset and uses
[OIDC](Secrets-and-Doppler).

## 3. Grant only what the called workflow declares

A called workflow's jobs run with at most the permissions the **caller grants**.
Each reusable workflow's documentation (and its YAML) says what it needs. For
example `python-ci.yml` needs `id-token: write` for the Doppler fetch and Codecov,
but keeps it off the `test` job itself.

## 4. Put concurrency in the caller

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

## 5. Point branch protection at the gate

Require `ci / CI green` (job name `ci`, calling `python-ci.yml`). A repository
that calls more than one CI workflow names each job differently (`ci`, `shell`)
and requires each gate: `ci / CI green` and `shell / CI green`. The
[audit](Repository-Baseline#the-weekly-audit) derives that set from the caller's
workflow files and fails on a missing one.

## A complete minimal caller

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  ci:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      id-token: write   # Doppler OIDC and Codecov; python-ci keeps it off the test job
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      test-command: pytest
      lint-command: ruff check .
      egress-policy: block
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

Don't write this by hand for a real repository: `scripts/new-repo.sh` reads what
the repository holds and writes the callers for you
([Adopting a Repository](Adopting-a-Repository)).

## How inputs behave

- **Every input is declared, defaulted, used and documented.** A test fails if an
  input is missing from the README table.
- **Commands are inputs** (`test-command`, `lint-command`, `build-command`...).
  They reach the shell as environment variables run by `bash -eo pipefail -c`,
  never by template expansion, so multi-line values work as written and a value
  can only ever be data.
- **`*-continue-on-error` inputs are migration aids**: report a finding without
  failing while a repository cleans up. They are meant to be removed again.
- **`egress-policy`** is `audit` by default and `block` in every adopted
  repository. See [Egress Control](Egress-Control).
- **`doppler-*` inputs** wire up the secret fetch. See
  [Secrets and Doppler](Secrets-and-Doppler).

## Choosing the right workflow

See the [Workflow Catalog](Workflow-Catalog). In short: one CI workflow per
language in the repository, plus the security workflow, plus a release workflow if
you publish something, plus auto-merge for Dependabot.

## Upgrading

You normally don't. Dependabot opens a PR bumping the pin when a new tag is cut,
and (if the repository calls `dependabot-auto-merge.yml`) merges patch and minor
bumps itself once `CI green` passes. A major bump is left for a person.
