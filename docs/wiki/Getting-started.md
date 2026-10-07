# Getting started

**What this is.** The path from "a repository with code in it" to "a repository
whose CI is three small files that call GYST, with a green check you can read".
It assumes you have never written a GitHub Actions workflow. Words in
**bold** are defined in the [Glossary](Glossary.md).

## The idea in four sentences

A **workflow** is a YAML file in `.github/workflows/` that GitHub runs when
something happens (a push, a pull request, a schedule). A **reusable workflow**
is a workflow written so that other repositories can call it, like a function.
The repository that calls it holds a **caller**: a few lines naming the
reusable workflow, a version, and the handful of inputs that differ for that
project. GYST is a set of reusable workflows, so your repository holds callers
and the real work lives here.

## What a caller looks like

This is the whole of a Python project's `ci.yml`, trimmed. Read the comments;
the file is otherwise the same in every repository.

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:
  workflow_dispatch:

permissions:
  contents: read            # the default for every job; jobs widen only what they need

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

jobs:
  ci:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@a5b834a6e03e0bf7187eeebfa84685498d73b139 # v1.14.0
    permissions:
      contents: read
      id-token: write       # the coverage job asks for it; see the note below
    with:
      python-versions: '["3.12", "3.13"]'
      test-command: pytest
      egress-policy: block
```

Three things to notice.

- **`@<sha> # v1.14.0`** is a **pin**: the exact commit of GYST that runs,
  with the version beside it for humans. A tag can be moved, a commit cannot.
  Dependabot opens a pull request to move the pin when a new version is tagged.
- **`with:`** holds inputs. Every workflow page lists every input, its default
  and what it means. Most callers set three or four and take the rest.
- **`id-token: write`** looks odd on a CI job. A called workflow may not use
  a permission its caller did not grant, and GitHub checks this before any job
  starts. Leave it off and the run ends in `startup_failure` with **no check
  run at all**: nothing is red, the required check simply never appears, and a
  merge goes through. This was measured on two callers on 2026-10-03 (issue
  #74). Each workflow page names the grants its caller needs.

## Starting a repository: `scripts/new-repo.sh`

You do not have to write callers by hand. From a checkout of this repository:

```sh
scripts/new-repo.sh OWNER/NAME
```

It reads the repository (a `pyproject.toml`, requirements files, a
`Dockerfile`, shell scripts and their indent, an `ansible/` directory, the
workflows already there), then writes callers for what it found, commits them
on a branch `ci/git-your-ship-together`, pushes, opens the pull request,
applies the repository settings in [BASELINE.md](../../BASELINE.md) through
the API, and appends the repository to `baseline/repos.txt`. Look first
without changing anything:

```sh
scripts/new-repo.sh OWNER/NAME --dry-run --path ./a-checkout --out /tmp/preview
```

For a Python project with a Dockerfile, the files that appear are:

| File | What it is |
|---|---|
| `.github/workflows/ci.yml` | A caller of `python-ci.yml`: lint, tests, smoke test, a container build. One gate job, `CI green` |
| `.github/workflows/security.yml` | A caller of `security.yml`: CodeQL, secret scan, dependency audit, Semgrep and the rest. See [Security scanning explained](Security-scanning-explained.md) |
| `.github/workflows/release.yml` | A caller of `container-release.yml` (or a package or artifact release, if it found one). Publishes only from the default branch or a tag |
| `.github/workflows/dependabot-auto-merge.yml` | A caller that queues safe bumps to merge themselves |
| `.github/dependabot.yml` | Weekly bumps with a seven-day cooldown |

A repository with shell scripts also gets a `shell:` job calling `bash-ci.yml`;
one with a playbook or Terraform gets the matching job. One caller job per
language, each ending in its own `CI green`.

What it cannot do is the Doppler side: the service account and identity are
made in the Doppler dashboard. It prints those steps and takes the identity's
UUID back with `--doppler-identity`. A project that needs no secrets can skip
Doppler entirely. See [Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md).

## What happens on the first push

1. GitHub reads your callers, resolves each `uses:` to the pinned commit of
   GYST and starts the jobs.
2. On a **pull request**, jobs run with `contents: read` and no secret. The
   Doppler step prints a notice that it will not fetch on a pull request and
   moves on. This is deliberate, not an error.
3. On a **push to the default branch**, a **tag** or a **schedule**, the same
   jobs run and the jobs that need a secret may fetch one. The release job
   publishes only here.
4. The last job, `CI green`, needs every other job and fails if any failed.
   You require that one name in branch protection, and a job added later is
   covered without touching the rule.
5. Security results show up under the repository's **Security** tab, in code
   scanning, as **SARIF** from each scanner.

## Reading a red run

Open the run, then the red job, then the first red step. Typical causes:

| You see | It means | Fix |
|---|---|---|
| `domain not allowed: <host>` | `egress-policy: block` refused a host the workflow does not list | Add the host to `extra-allowed-endpoints` on that caller, if you meant to reach it. A new dependency announces itself this way |
| No check at all, run ended `startup_failure` | The caller did not grant a permission the called workflow declares | Add the grant the workflow page names (usually `id-token: write`) |
| `claim "sub" does not match identity auth config` | The Doppler identity does not list the token subject your repository sends | See the subject forms in [Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md) |
| Secret scan red with a finding | gitleaks found a credential shape in history | Rotate the credential first, then fix the history or add an allowlist entry with a reason |
| Lint red on `.github/workflows/*` | actionlint or zizmor found a mistake or an unsafe pattern in your own workflow files | Read the rule name; zizmor's documentation explains each |
| `CI green` red | The gate runs even when an earlier job fails (`if: always()`) and fails if any job it needs failed or was cancelled; a job deliberately skipped is fine | Open the gate job's log; it prints every job's result |

## Then, once

The settings no YAML can set (branch protection, Actions policy, secret
scanning, tag immutability) are applied by `new-repo.sh` and checked every
Monday. See [The baseline and the weekly audit](Baseline-and-the-weekly-audit.md).

## What this refuses to do

It never uses `secrets: inherit`, never runs a pull request's code beside a
secret, never pins an action to a moving tag, and never publishes from a pull
request. If a caller asks for those, the workflow either refuses or the
audit fails the repository.
