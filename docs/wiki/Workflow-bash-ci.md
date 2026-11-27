# bash-ci

**What it does.** Lints and tests the shell in a repository: shellcheck and shfmt over every tracked script, an optional test
command (`bats`, a runner script), an optional configuration lint (yamllint, ansible-lint), the workflow lint, optional
pull-request checks and the same **`CI green`** gate. Holds no token in any job.

**Why it exists.** Every repository carries shell. The nine Python callers alone held 47 scripts that no workflow linted. A
repository that is mostly shell names this job `ci`; one that also calls [python-ci](Workflow-python-ci.md) names it `shell`
and requires both gates, so the composition rule is one caller job per language.

## How it finds scripts

Scripts are found, not listed: every tracked file under `paths` whose name ends in `.sh` or `.bash`, or whose first line is a `sh`
or `bash` shebang. shellcheck and shfmt are **downloaded at a pinned version and checked against a pinned sha256 before they
run**, so no third-party action joins the Actions allow-list for them and what lints today is what lints next year. The download
is cached, and the hash is checked on disk whether it came from the cache or the network.

## Jobs and trust boundaries

Every job has `contents: read` and nothing else, because a lint needs nothing: `shellcheck`, `shfmt`, `test` (a matrix over
`runners`), `distro` (the suite inside other distributions' images), `config-lint`, `workflow-lint`, `fragment-check`,
`commit-claims` and `ci-green`. The `test` job and, in [arduino-ci](Workflow-arduino-ci.md), its host test job keep sudo, because a
caller may legitimately write `sudo apt-get install -y bats`; nothing in the workflow's own steps uses it.

## A minimal caller

```yaml
jobs:
  shell:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/bash-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      shfmt-args: -i 2 -ci
      test-command: ./tests/run.sh
      workflow-lint: false   # python-ci already lints the workflow files
      egress-policy: block
```

Notes: four-space indent is the default because seven of nine callers write it; two pass `-i 2 -ci`. A shell-only repository
also sets `codeql-languages: actions` and `pip-audit-requirements: ""` on [security](Workflow-security.md). The `distro`
job's egress list, its Kali and Parrot pinning and the Fedora caveat are described on the [python-ci](Workflow-python-ci.md)
page.

<!-- inputs -->

**Skipping the tests on a docs-only pull request.** Set `skip-docs-only: true` (off by default) and a pull request that changes only
`*.md` or `docs/**/*.md` leaves the `Test` and `Distro` jobs out; lint and the security scans still run, and `CI green` still fails
on any failed job. A private repository also adds `pull-requests: read` to the caller's `permissions:`, or the classifier fails
closed and every job runs. See [Docs-only fast path](Docs-only-fast-path.md).

## Choosing the runner

`runs-on` is a JSON string that every job reads through `fromJSON(inputs.runs-on)`, because `runs-on` takes a string, an
array or an object: `'"ubuntu-latest"'` (the default), `'["self-hosted","linux"]'` or `'{"group":"my-group","labels":["linux"]}'`.
Invalid JSON fails the job at expression time. `allow-self-hosted` (default `false`) is the caller's attestation that a
self-hosted runner is ephemeral, one job per VM, and isolated from secrets and the network. Without it, a step right after harden-runner in every
job fails on any runner that is not GitHub-hosted. With it, a self-hosted runner still takes only `push`, `schedule`,
`workflow_dispatch`, `release` and same-repository `pull_request` events. The `test` and `distro` jobs keep their runner matrices (`runners` and `distro-runners`) and ignore `runs-on`.

## What it refuses to do

It never fetches a secret, never gives any job more than `contents: read`, and never runs an unpinned linter binary.
