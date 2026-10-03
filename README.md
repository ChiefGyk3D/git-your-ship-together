# git-your-ship-together

> Reusable workflows. Repeatable builds. Less "what the fuck broke?"

One place to fix a pipeline bug or add a scan step, instead of one per
repository. These are the GitHub Actions workflows shared by ChiefGyk3D's
Python projects: Typo Sniper, Stream Daemon, Star Daemon, Boon Tube Daemon,
SolarStorm Scout, NetPulse, jumpcloud-wazuh-bridge, yomama-as-a-service and
penguin-overlord today (`baseline/repos.txt` is the list), and whatever comes
next. Every one of them runs lint, tests, a container build, a signed
multi-arch release and six kinds of scan with three short YAML files that say
only what is specific to that project. Secrets live in Doppler, fetched over
OIDC; there is not one GitHub Actions secret in any of the ten repositories.

It is also written to be read. If you want to see what a hardened CI setup
looks like end to end, with the reasoning and the mistakes left in, start
below.

The Python workflows are what exists today because that is what these nine
projects are. Most of the repository is not language-specific: the baseline
and its audit, the Doppler design, the auto-merge workflow, the pinning,
permission and egress rules and the tests that enforce them apply to any
repository. The container release builds whatever the Dockerfile builds.
[docs/ROADMAP.md](docs/ROADMAP.md) has the plan for the rest, one CI workflow
per language behind the same `CI green` gate, so branch protection is one
rule everywhere.

## Start here

Read in this order. Each one is short.

1. [docs/DESIGN.md](docs/DESIGN.md): why it is built this way, what it
   defends against, and what every product in the chain is for.
2. This file: how to call the workflows, how to wire Doppler, what the
   settings outside YAML are, and the lessons that cost a day each.
3. [BASELINE.md](BASELINE.md): the settings every calling repository must
   meet, with the `gh api` command that sets each one and the audit that
   checks it.
4. `tests/test_workflows.py`: the contract. Every rule in DESIGN.md is a
   test here, so a pull request that breaks one fails before review.
5. `fixture/`: the smallest project that exercises every job, run by this
   repository's own CI. Not an example to copy; the callers are.
6. A caller. [typo-sniper's `.github/workflows`](https://github.com/ChiefGyk3D/typo-sniper/tree/main/.github/workflows)
   are three files of the shape shown below, and that is the whole per-project
   footprint.
7. [docs/ROADMAP.md](docs/ROADMAP.md): what is done, what is next, and what
   the lab's spare compute could carry.

## What is in the repository

Thirteen reusable workflows and one composite action:

| File | What it does |
|---|---|
| `.github/workflows/python-ci.yml` | Lint, workflow lint, test matrix, coverage upload, optional CLI smoke test, single-arch container build with a check, one `CI green` gate job |
| `.github/workflows/bash-ci.yml` | shellcheck and shfmt over every tracked script, an optional test command, an optional configuration lint (yamllint, ansible-lint), workflow lint, the same `CI green` gate. Holds no token |
| `.github/workflows/tofu-ci.yml` | For OpenTofu or Terraform: fmt, validate without a backend, tflint and a Trivy configuration scan on every push and pull request; a plan on the default branch only, with credentials through the Doppler gate; the same `CI green` gate. Nothing applies |
| `.github/workflows/arduino-ci.yml` | For firmware built with arduino-cli: compile every sketch for a board with pinned cores and libraries, keep the binaries as an artifact, host-side tests, workflow lint, the same `CI green` gate. Holds no token; the binaries reach a release through `artifact-release.yml` |
| `.github/workflows/container-release.yml` | Build, test, Trivy-scan, then publish multi-arch to GHCR (and Docker Hub), sign with cosign, attach a syft SBOM, record SLSA provenance. Builds whatever the Dockerfile builds |
| `.github/workflows/python-docker-release.yml` | The old name of the above: a thin caller that forwards every input, the secret and the outputs through a `./` reference at its own commit, so an existing pin keeps working. New callers use `container-release.yml` |
| `.github/workflows/verify-published.yml` | Consumer-side verification of a published image: cosign signature, SPDX SBOM attestation and build provenance verified from outside, then each platform pulled and checked. Read-only, no secret, no token beyond the default one |
| `.github/workflows/python-package-release.yml` | Build the sdist and wheel, `twine check`, refuse a tag that disagrees with the packaged version, smoke-test from the wheel, then publish to PyPI (Trusted Publishing, PEP 740 attestations) and to the GitHub release with SHA256SUMS and build provenance. No secret anywhere |
| `.github/workflows/artifact-release.yml` | For a file rather than an image (a `.deb`, a firmware binary, a bundle): build it with a command, then publish it to the GitHub release with SHA256SUMS, a keyless cosign signature bundle per file and build provenance. No secret anywhere |
| `.github/workflows/docs-pages.yml` | Build a static documentation site with a command you supply (MkDocs strict by default) on every pull request; upload it and deploy it to GitHub Pages from the default branch only. The two Pages writes sit on the deploy job alone |
| `.github/workflows/wiki-publish.yml` | Run a command that generates a wiki tree, then replace the repository's GitHub wiki with it, as `github-actions[bot]`, only when something changed, from the default branch only. The write token sits on a job that runs none of your code |
| `.github/workflows/security.yml` | CodeQL (the `actions` language included by default), gitleaks, a dependency audit (pip-audit, and any other tool by command), Semgrep, dependency review on pull requests (with a licence denylist), optional Snyk, optional OpenSSF Scorecard |
| `.github/workflows/dependabot-auto-merge.yml` | Queues a Dependabot bump to merge itself once the required checks pass, up to a size you choose |
| `.github/actions/doppler-secrets` | Fetches a Doppler config as masked environment variables, over OIDC or a Service Token. The workflows inline a copy of it (see the design rules); this is the source |

This repository's own pipeline, which runs the workflows against a real
project before any caller pins them:

| File | What it does |
|---|---|
| `.github/workflows/ci.yml` | actionlint, zizmor, the pytest contract, then `python-ci.yml`, `bash-ci.yml`, `tofu-ci.yml`, `arduino-ci.yml`, `python-package-release.yml`, `artifact-release.yml`, `docs-pages.yml`, `wiki-publish.yml` and `python-docker-release.yml` called at the pull request's own ref against `fixture/` (bash-ci over the whole repository; bash-ci and the package build in block mode), and a `CI green` gate that needs all of it |
| `.github/workflows/security-self.yml` | `security.yml` called the same way, on push, pull request and a Monday schedule |
| `.github/workflows/dependabot-auto-merge-self.yml` | `dependabot-auto-merge.yml` called the same way, so this repository's own bumps exercise it |
| `.github/workflows/audit.yml` | The weekly audit: `scripts/audit_baseline.py` over every repository in `baseline/repos.txt` on Monday 07:00 UTC, with its own token from its own Doppler project; and an issue here for each risk-register entry about to expire. Not reusable; see [The weekly audit](#the-weekly-audit) |
| `.github/dependabot.yml` | Weekly action and pip bumps with a seven-day cooldown, actions grouped into one pull request |
| `fixture/` | A package with a console script, one test, a non-root Dockerfile, a hash-pinned `requirements.txt`, and one shell script with its own test: one of everything a job needs. `fixture/README.md` says how to regenerate the lock |
| `tests/` | The contract, as pytest, one file per thing it holds still. See [Developing](#developing) |
| `pyproject.toml`, `requirements-dev.txt` | ruff and pytest configuration, and the three pinned tools the tests need |

And what keeps the callers honest:

| Path | What it is |
|---|---|
| `BASELINE.md` | The minimum every calling repository meets: people, branch protection, secrets, workflows, Actions settings, scanning, risk exceptions |
| `baseline/repos.txt` | The repositories the baseline covers, one per line, this one included |
| `baseline/selected-actions.json` | The allowed-actions policy every repository sets: GitHub-owned plus the named third parties these workflows use, subdirectory forms included |
| `baseline/risk-register.yaml` | Every advisory a pipeline is told to ignore, with the reason, the mitigation, an owner and an expiry. See [Risk register](#risk-register) |
| `scripts/audit_baseline.py` | Reads each repository's settings and workflows from the API and reports PASS, FAIL or UNKNOWN per baseline item. Exit 0 only when every check passed |
| `scripts/new-repo.sh` | Adopts a repository, or starts one: reads what it holds, writes the caller workflows and `dependabot.yml` from that, commits on a branch and opens the pull request, applies every BASELINE setting, appends to `baseline/repos.txt`. `--dry-run` writes the files somewhere else and prints the settings instead; that is what its test runs |
| `scripts/doppler-ci-set.sh` | Sets one secret in the shared Doppler `ci` config. The value is typed twice with echo off and never reaches a command line, shell history or the terminal |
| `docs/DESIGN.md` | The reasoning: the threat model, why Doppler, the products, what the tests enforce |
| `docs/ROADMAP.md` | What is done, what is next, and what the lab could carry |

## Design rules

Applied throughout, and each one is a test:

- **Doppler is the single source of truth for secrets, in CI as well as at
  runtime.** A workflow authenticates to Doppler with a short-lived token
  minted from the job's own GitHub OIDC identity. Nothing is duplicated into
  GitHub's encrypted secrets. See [Doppler setup](#doppler-setup).
- **Every third-party action is pinned to a commit SHA** with a version
  comment; Dependabot moves both together. `tests/test_workflows.py` fails
  otherwise, and zizmor fails a caller whose comment and SHA disagree.
- **Permissions are declared per job and every write is on a list** with a
  reason (`ALLOWED_WRITES` in the tests). `contents: read` at the top of every
  file; jobs widen only what they need.
- **Nothing from an untrusted context is interpolated into a shell.** Values
  pass through `env:`. That includes every command a caller supplies.
- **Every job has a timeout**, and every checkout sets
  `persist-credentials: false`.
- **Every job starts with harden-runner.** The input defaults to `audit`,
  which logs every outbound connection; every caller in `baseline/repos.txt`
  runs `block`, which allows only the measured list each workflow carries as
  its default. See [Egress](#egress).
- **The job that runs the caller's code holds no OIDC token.** The test job
  has `contents: read` and nothing else. Coverage goes to Codecov from a
  separate job that only ever touches the report artifact.
- **Secrets are fetched only on a trusted ref.** A push to the default
  branch, a tag or a schedule. A pull request gets a notice and nothing.
- **A publishing build never reads the Actions cache.** Anyone who can open
  a pull request can write to that cache, and a poisoned layer inside a
  signed release is the one outcome the signature cannot undo.
- **The workflows never reference this repository by branch.** A reusable
  workflow cannot name the commit it runs from, so the Doppler steps are
  inlined rather than referenced as `@main`; a test holds the four copies
  identical to `.github/actions/doppler-secrets`.

## Calling the workflows

Callers pin a **commit SHA with the version in a comment**, the same rule
every third-party action is held to here, and Dependabot moves the pin:

```yaml
uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@<sha> # v1.3.1
```

Resolve a tag with `git ls-remote --tags <repo> 'refs/tags/vX.Y.Z*'` and take
the `^{}` (peeled) line when there is one: an annotated tag's own SHA is a tag
object, not a commit. Four pins in the first version of this repository were
tag objects; GitHub happened to resolve them, Dependabot would not have.

Secrets are passed by name, never with `secrets: inherit`, so a called
workflow can only ever see the one secret it declares. `DOPPLER_TOKEN` is
the Service Token fallback and may be unset; every caller here leaves it
unset and uses OIDC.

### Hygiene

Three habits apply to every shared workflow, and tests hold them.

- **`disable-sudo: true`** on every harden-runner step, so a compromised step
  cannot become root on the runner. The two exceptions are the jobs that run a
  caller's own install command, which a caller may legitimately write as
  `sudo apt-get install ...`: the `test` job of `bash-ci.yml` and `arduino-ci.yml`
  (`test-install-command`) and the `build` job of `artifact-release.yml`
  (`build-install-command`). Nothing in a shared workflow's own steps uses sudo.
- **Downloaded tools are cached, and still hash-checked.** `bash-ci.yml`
  (shellcheck, shfmt), `tofu-ci.yml` (OpenTofu, tflint) and `arduino-ci.yml`
  (arduino-cli) cache the downloaded archive with `actions/cache` under the key
  `tool-<name>-<pinned version>-<runner os>-<runner arch>`. The job then checks
  the archive on disk against the pinned SHA-256 whether it came from the cache
  or the network; a cached file that fails is thrown away and fetched again, so
  the cache can save a download but never lower the bar. `arduino-ci.yml` also
  caches arduino-cli's download staging directory, keyed on the arduino-cli
  version and a hash of `cores`, `additional-urls` and `libraries`;
  arduino-cli verifies each package against its index checksum before installing
  it. `python-ci.yml` keeps setup-python's pip cache. The publishing workflows
  cache nothing.
- **Concurrency belongs to the caller.** A reusable workflow cannot carry it:
  a called workflow's `github.workflow` is the caller's name, so the same group
  would cancel the caller itself. Put this in the caller's `ci.yml`, as the
  sample below and `scripts/new-repo.sh` do: a newer push cancels an older
  *pull request* run, but a run on the default branch or a tag is never
  cancelled half way through.

  ```yaml
  concurrency:
    group: ${{ github.workflow }}-${{ github.ref }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

### CI

A real caller, trimmed. The comment at the top of each caller says what is
specific to that project, because the file is otherwise the same everywhere.

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
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@<sha> # v1.3.1
    permissions:
      contents: read
      id-token: write   # Doppler OIDC and Codecov; python-ci keeps it off the test job
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}   # optional fallback, unset means OIDC only
    with:
      python-versions: '["3.10", "3.11", "3.12", "3.13"]'
      install-command: |
        python -m pip install --upgrade pip
        pip install --require-hashes -r requirements-dev.txt
      test-command: pytest --cov=src --cov-report=xml
      lint-install-command: pip install "$(grep -E '^ruff==' requirements-dev.in)"
      lint-command: ruff check src/ tests/
      smoke-command: typo-sniper --version
      dockerfile: docker/Dockerfile
      docker-test-command: |
        docker run --rm "$IMAGE" --version
        test "$(docker run --rm --entrypoint id "$IMAGE" -u)" != "0"
      egress-policy: block
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

Point branch protection at the **CI green** job (`ci / CI green` as a caller
reports it). It needs every other job and fails if any of them failed, so a
job added here can never merge unchecked. A repository with more than one
language calls one shared CI workflow per language from one job each, and
requires each job's gate: `ci / CI green` and `shell / CI green`, say. The
audit derives that set from the caller's workflow files.

The `test` job runs the caller's own code and holds no OIDC token. Coverage is
uploaded to Codecov by a separate `coverage` job that downloads the report
artifact and never runs on a pull request, so nothing the test suite or its
dependencies can execute ever runs beside a secret. Coverage therefore
appears on Codecov per push to the default branch, not per pull request.

Inputs of `python-ci.yml`:

| Input | Default | Meaning |
|---|---|---|
| `python-versions` | `'["3.11", "3.12", "3.13"]'` | JSON array for the test matrix |
| `runners` | `'["ubuntu-24.04"]'` | JSON array of runner labels for the `test` matrix; the first entry also uploads coverage; `ubuntu-24.04-arm` is native arm64, `macos-15` and `windows-2025` also work (commands run under bash) |
| `distros` | `'[]'` (skips the job) | JSON array of container images to run the tests in as well, e.g. `'["debian:13", "kalilinux/kali-rolling"]'`; see [Operating systems](#operating-systems) |
| `distro-runners` | `'["ubuntu-24.04"]'` | Runner labels the `distros` run on; add `ubuntu-24.04-arm` for native arm64 |
| `distro-setup-command` | install python3, venv, pip, git and ca-certificates with `apt-get`, else `dnf` | Shell run as root in each image before the install command |
| `distro-egress-policy` | `block` | harden-runner policy for the `distro` job only; `audit` for a distribution whose mirrors are not on the list |
| `distro-allowed-endpoints` | the measured list | The `distro` job's own allow-list, kept apart from `allowed-endpoints`: Docker Hub's image pull, the Debian, Ubuntu, Kali and Parrot mirrors, and PyPI. `extra-allowed-endpoints` is appended to it |
| `distro-continue-on-error` | `false` | Let a failing distro run leave the gate green, for a suite that assumes a non-root user or a newer Python than the distribution ships. |
| `coverage-python-version` | `3.13` | The matrix leg that uploads coverage |
| `install-command` | upgrade pip, `pip install -r requirements.txt` | Run before tests on every leg |
| `test-command` | `pytest` | The test suite |
| `coverage-file` | `coverage.xml` | Uploaded as an artifact when present |
| `coverage-threshold` | empty (no check) | Minimum total line coverage as a percentage, e.g. `85`. The `test` job fails below it, judged from the `line-rate` of `coverage-file` (Cobertura XML, as coverage.py and pytest-cov write it) on the leg that uploads it; the test command must write that file |
| `codecov` | `false` | Also upload to Codecov over GitHub OIDC; no token, the repository just has to be enabled in the Codecov GitHub App |
| `lint-python-version` | `3.13` | Python for the lint job |
| `lint-install-command` | `pip install ruff` | Installs the linters |
| `lint-command` | `ruff check .` | The lint step |
| `lint-continue-on-error` | `false` | Report lint failures without failing CI. A migration aid; no caller sets it any more |
| `typecheck-install-command` | empty | Installs the type checker, e.g. `pip install mypy==2.4.0`; empty installs nothing |
| `typecheck-command` | empty (skips the job) | Type-checks, e.g. `mypy src`; runs as the `Type check` job on `lint-python-version` and is part of the gate |
| `fragment-check-command` | empty (skips the job) | Pull requests only, full history, `BASE` set to the base branch name: the `Changelog fragment` job. See [Pull-request checks](#pull-request-checks) |
| `commit-claims-command` | empty (skips the job) | Pull requests only, full history, `BASE` and `HEAD` set: the `Commit claims` job. See [Pull-request checks](#pull-request-checks) |
| `smoke-command` | empty (skips the job) | Run after installing the project, e.g. `my-cli --version` |
| `smoke-install-command` | `pip install .` | Installs the project for the smoke test |
| `docker-build` | `true` | Build the image, single platform, never pushed |
| `dockerfile` | `Dockerfile` | Path to the Dockerfile |
| `docker-context` | `.` | Build context |
| `docker-test-command` | empty (skips the check) | Run against the built image; `$IMAGE` names it |
| `workflow-lint` | `true` | actionlint and zizmor over the caller's own `.github/workflows` |
| `zizmor-persona` | `regular` | zizmor strictness: `regular`, `pedantic`, `auditor` |
| `egress-policy` | `audit` | harden-runner on every job except `distro`: `audit` logs outbound connections, `block` allows only `allowed-endpoints` |
| `allowed-endpoints` | the measured list | harden-runner allow-list for `block`, space-separated `host:port`; see [Egress](#egress) |
| `extra-allowed-endpoints` | empty | Appended to the list, for hosts only this repository reaches |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `doppler-trusted-refs-only` | `true` | Fetch CI secrets only on the default branch, a tag or a schedule; never on a pull request. See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `30` | Per-job timeout |

Every command input (`lint-command`, `test-command`, `smoke-command`,
`docker-test-command`, the install commands) reaches the shell as an
environment variable run by `bash -eo pipefail -c`, never by template
expansion into the script. Multi-line values work as written.

#### Operating systems

GitHub-hosted runners come in four kinds: Ubuntu, Ubuntu on arm64
(`ubuntu-24.04-arm`), macOS and Windows. List the ones you want in `runners`
and the `test` job runs every Python version on each. Every other
distribution is tested inside its official container image, on an Ubuntu
runner, with `distros` and `distro-runners`; putting `ubuntu-24.04-arm` in
`distro-runners` runs the same images natively on arm64, with no emulation.

Each image gets the workspace mounted, the install and test commands as
environment variables and a fresh virtual environment, after
`distro-setup-command` has installed Python and git with `apt-get` or `dnf`.

| To cover | Use |
|---|---|
| Ubuntu, Xubuntu, Kubuntu, Pop!_OS | `ubuntu:24.04`. Xubuntu and Kubuntu share Ubuntu's userland and Pop!_OS is Ubuntu with its own packages on top, so this covers anything that does not need a desktop session |
| Debian 12, Debian 13 | `debian:12`, `debian:13` |
| Raspberry Pi OS | Debian 12 or 13 on arm64: `debian:12` or `debian:13` with `ubuntu-24.04-arm` in `distro-runners`. This is the same userland on the same architecture, not a Raspberry Pi |
| Kali | `kalilinux/kali-rolling` |
| Parrot | `parrotsec/core` |
| Qubes | Qubes has no userland of its own; its templates are Debian or Fedora, so `debian:13` and `fedora:42` cover it |

The `distro` job runs in `block` mode with its own list,
`distro-allowed-endpoints`: Docker Hub for the image pull and the package
mirrors of the Debian, Ubuntu (amd64 and arm64), Kali and Parrot images. Fedora
and anything else that uses `dnf` is not on it, because `dnf` picks its mirror
from a metalink answer that differs from run to run, so no fixed host list
stays green. A caller testing `fedora:*` sets `distro-egress-policy: audit`
for that job, or adds the mirrors it observed to `extra-allowed-endpoints`.
A distribution's own extra repository goes in `extra-allowed-endpoints` too.

Kali and Parrot are pinned: the default `distro-setup-command` rewrites `http.kali.org`
in the image's apt sources to `kali.download`, because the official redirector
answers each request with a different mirror and a block list cannot follow
that. `kali.download` is the CDN behind it and is one name, on port 80.
Parrot's package redirector (`director.parrot.sh`) rotates the same way, so
its `deb.parrot.sh/parrot` sources are rewritten to `deb.parrot.sh/direct/parrot`,
which serves the packages itself. A
custom `distro-setup-command` that replaces the default loses the pin.

### Bash CI

For the shell in a repository, which in practice is every repository: the
nine Python callers hold 47 scripts between them. A repository that is
mostly shell names the job `ci`; one that also calls `python-ci.yml` from
`ci:` names this one `shell:` and requires both gates, as
[BASELINE.md](BASELINE.md) §2 says.

```yaml
jobs:
  shell:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/bash-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      shfmt-args: -i 2 -ci
      test-command: ./tests/run.sh
      config-lint-install-command: pip install yamllint ansible-lint
      config-lint-command: |
        yamllint .
        cd ansible && ansible-lint
      workflow-lint: false   # python-ci already lints the workflow files
      egress-policy: block
```

The scripts are found, not listed: every tracked file under `paths` whose
name ends in `.sh` or `.bash`, or whose first line is a `sh` or `bash`
shebang. shellcheck and shfmt are downloaded at a pinned version and checked
against a pinned SHA-256 before they run, so no third-party action joins the
allow-list for them and what lints today is what lints next year. Nothing in
this workflow fetches a secret; no job holds more than `contents: read`.

Inputs of `bash-ci.yml`:

| Input | Default | Meaning |
|---|---|---|
| `paths` | `.` | Space-separated git pathspecs searched for scripts; `:!archive` excludes a directory |
| `shellcheck-version`, `shellcheck-sha256` | `0.11.0` and its tarball's hash | The shellcheck release downloaded from koalaman/shellcheck |
| `shellcheck-severity` | `warning` | Lowest severity that fails: `error`, `warning`, `info`, `style` |
| `shellcheck-args` | `-x` | Extra arguments; `-x` follows `source`d files |
| `shellcheck-continue-on-error` | `false` | Report findings without failing. A migration aid for a repository that runs at `error` today |
| `shfmt` | `true` | Run shfmt and fail on a formatting diff |
| `shfmt-version`, `shfmt-sha256` | `3.14.1` and its binary's hash | The shfmt release downloaded from mvdan/sh |
| `shfmt-args` | `-i 4 -ci` | Style flags. Four-space indent is what seven of nine callers write; Skid-Finder and Hammunition pass `-i 2 -ci` |
| `shfmt-continue-on-error` | `false` | Report a diff without failing. A migration aid |
| `test-install-command` | empty | Run before the tests, e.g. `sudo apt-get install -y bats` |
| `runners` | `'["ubuntu-24.04"]'` | JSON array of runner labels for the `test` job; `ubuntu-24.04-arm` is native arm64, `macos-15` and `windows-2025` also work (commands run under bash) |
| `distros` | `'[]'` (skips the job) | JSON array of container images to run the tests in as well, e.g. `'["debian:13", "kalilinux/kali-rolling"]'`; see [Operating systems](#operating-systems) |
| `distro-runners` | `'["ubuntu-24.04"]'` | Runner labels the `distros` run on; add `ubuntu-24.04-arm` for native arm64 |
| `distro-setup-command` | install bash, git and ca-certificates with `apt-get`, else `dnf` | Shell run as root in each image before the install command |
| `distro-egress-policy` | `block` | harden-runner policy for the `distro` job only; `audit` for a distribution whose mirrors are not on the list |
| `distro-allowed-endpoints` | the measured list | The `distro` job's own allow-list, kept apart from `allowed-endpoints`: Docker Hub's image pull, the Debian, Ubuntu, Kali and Parrot mirrors. `extra-allowed-endpoints` is appended to it |
| `distro-continue-on-error` | `false` | Let a failing distro run leave the gate green, for a suite that assumes a non-root user or a newer Python than the distribution ships. |
| `test-command` | empty (skips the job) | The shell test suite: `bats tests/`, `./tests/run.sh`, whatever the repository has |
| `config-lint-install-command` | `pip install yamllint` | Installs the configuration linters, with Python available |
| `config-lint-command` | empty (skips the job) | Lints the configuration kept beside the scripts: yamllint, ansible-lint |
| `config-lint-python-version` | `3.13` | Python for that job |
| `fragment-check-command` | empty (skips the job) | Pull requests only, full history, `BASE` set to the base branch name: the `Changelog fragment` job. See [Pull-request checks](#pull-request-checks) |
| `commit-claims-command` | empty (skips the job) | Pull requests only, full history, `BASE` and `HEAD` set: the `Commit claims` job. See [Pull-request checks](#pull-request-checks) |
| `workflow-lint` | `true` | actionlint and zizmor over the caller's own `.github/workflows`; turn off on one job when another caller job already runs it |
| `zizmor-persona` | `regular` | zizmor strictness: `regular`, `pedantic`, `auditor` |
| `egress-policy` | `audit` | harden-runner on every job; see [Egress](#egress) |
| `allowed-endpoints` | the measured list | harden-runner allow-list for `block`, space-separated `host:port` |
| `extra-allowed-endpoints` | empty | Appended to the list, for hosts only this repository reaches |
| `timeout-minutes` | `15` | Per-job timeout |

### Tofu CI

For the infrastructure in a repository, which today is typo-sniper's
`infra/terraform`. Everything that runs on a pull request runs without a
cloud credential: `fmt -check`, `validate` with no backend, tflint, and
Trivy's configuration scan. A plan needs a credential, so it runs only on a
push to the default branch, with whatever the Doppler config holds in its
environment, which is the one place the gate lets a secret exist. Nothing
applies from CI.

```yaml
jobs:
  tofu:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/tofu-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      id-token: write   # the plan job's Doppler fetch, off pull requests only
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      directories: infra/terraform/examples/ecs-fargate infra/terraform/examples/eks-cronjob
      plan-command: |
        cd infra/terraform/examples/ecs-fargate
        tofu init -input=false && tofu plan -input=false
      workflow-lint: false   # python-ci already lints the workflow files
      egress-policy: block
      extra-allowed-endpoints: registry.terraform.io:443 sts.amazonaws.com:443
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

The binary is OpenTofu, downloaded at a pinned version and checked against
a pinned hash; `binary: terraform` uses the Terraform the runner image ships
instead. tflint is downloaded the same way. A repository with more than one
root module lists them in `directories`; each is validated and linted on its
own.

Inputs of `tofu-ci.yml`:

| Input | Default | Meaning |
|---|---|---|
| `directories` | `.` | Space-separated root modules, validated and linted one by one |
| `binary` | `tofu` | `tofu` (downloaded) or `terraform` (the runner's) |
| `tofu-version`, `tofu-sha256` | `1.12.6` and its zip's hash | The OpenTofu release downloaded from opentofu/opentofu |
| `tflint` | `true` | Run tflint over every directory |
| `tflint-version`, `tflint-sha256` | `0.64.0` and its zip's hash | The tflint release downloaded from terraform-linters/tflint |
| `trivy` | `true` | Trivy configuration scan over the repository |
| `trivy-severity` | `CRITICAL,HIGH` | Severities the scan reports |
| `trivy-exit-code` | `1` | `1` fails the job on a finding, `0` reports only. A migration aid |
| `plan-command` | empty (skips the job) | The plan, run only on a push to the default branch with the Doppler config's secrets in the environment |
| `workflow-lint` | `true` | actionlint and zizmor over the caller's own `.github/workflows`; turn off when another caller job already runs it |
| `zizmor-persona` | `regular` | zizmor strictness |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, the tool downloads and Trivy's checks bundle, empty | harden-runner, as in `python-ci.yml`. A provider registry or a cloud API the plan reaches goes in `extra-allowed-endpoints` |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup); only the plan job reads them |
| `doppler-trusted-refs-only` | `true` | Fetch only on the default branch, a tag or a schedule; never on a pull request |
| `timeout-minutes` | `20` | Per-job timeout |

### Arduino CI

For firmware, which today is Skid-Finder's ESP32 sensor node. arduino-cli is
downloaded at a pinned version and hash; the cores and libraries are named
with versions by the caller, so the build is the same build next year.
Every sketch is compiled for the board and the binaries are kept as an
artifact; a release signs and attests them through `artifact-release.yml`,
with the same compile as its build command.

```yaml
jobs:
  firmware:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/arduino-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      sketches: nodes/esp32/skidfinder_node
      fqbn: esp32:esp32:esp32
      cores: esp32:esp32@3.3.12
      additional-urls: https://espressif.github.io/arduino-esp32/package_esp32_index.json
      workflow-lint: false   # another caller job already lints the workflow files
      egress-policy: block
      extra-allowed-endpoints: espressif.github.io:443 dl.espressif.com:443
```

Inputs of `arduino-ci.yml`:

| Input | Default | Meaning |
|---|---|---|
| `sketches` | `.` | Space-separated sketch directories, each holding a `.ino` named after it |
| `fqbn` | `arduino:avr:uno` | The board to compile for |
| `cores` | `arduino:avr@1.8.8` | Space-separated cores to install, versioned |
| `additional-urls` | empty | Board manager URLs for cores outside Arduino's index |
| `libraries` | empty | Space-separated libraries from the library manager, versioned |
| `warnings` | `all` | arduino-cli compile warning level |
| `arduino-cli-version`, `arduino-cli-sha256` | `1.5.1` and its tarball's hash | The arduino-cli release downloaded from arduino/arduino-cli |
| `test-install-command` | empty | Run before the host-side tests |
| `test-command` | empty (skips the job) | The host-side unit tests |
| `workflow-lint` | `true` | actionlint and zizmor over the caller's own `.github/workflows` |
| `zizmor-persona` | `regular` | zizmor strictness |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, arduino-cli's download and Arduino's index, empty | harden-runner, as in `python-ci.yml`. A core from another index adds its hosts |
| `timeout-minutes` | `30` | Per-job timeout; a first core install takes minutes |

### Container release

```yaml
name: Release
on:
  push:
    branches: [main]
    tags: ['v*.*.*']
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 5 * * 1'   # weekly rebuild of `latest`, so base-image fixes ship between commits
  workflow_dispatch:

permissions:
  contents: read

jobs:
  container:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/container-release.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
      security-events: write
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      dockerfile: Docker/Dockerfile
      push: ${{ github.event_name != 'pull_request' }}
      dockerhub: true
      docker-test-command: docker run --rm "$IMAGE" python -c "import stream_daemon"
      egress-policy: block
      extra-allowed-endpoints: www.sqlite.org:443   # one project's Dockerfile fetches this; not in the shared list
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

What a push produces, for every platform in `platforms`:

1. The image at `ghcr.io/<owner>/<repo>` with the tags from `tags`, and the
   same at `docker.io/<DOCKERHUB_USERNAME>/<repo>` when `dockerhub` is true and
   the Doppler config carries `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.
2. A **cosign signature** on the image index, keyless: the certificate names
   this workflow's GitHub identity, so there is no signing key to hold or
   rotate.
3. An **SPDX SBOM** from syft, attached as a cosign attestation on the image
   and kept as the `sbom.spdx.json` workflow artifact.
4. **SLSA build provenance** as a GitHub Artifact Attestation.
5. A Trivy scan, uploaded to the Security tab as SARIF (on pull requests too).

Each platform is built and tested natively, on its own runner: `linux/arm64`
on `ubuntu-24.04-arm`, `linux/amd64` on `ubuntu-24.04`. `docker-test-command`
and the Trivy scan therefore run against the real arm64 image, not an emulated
one. QEMU is set up only for a platform with no native runner. When
publishing, each platform job pushes its image under a temporary tag
`ghcr.io/<owner>/<repo>:<sha>-<arch>` (for example `<sha>-linux-arm64`), and a
`merge` job joins them into the index under the real tags. The temporary tags
stay in GHCR beside the index; delete them when you no longer need them.

On a pull request it builds, tests and scans and stops. Nothing is pushed,
signed or attested from a pull request, and a test holds that order.

Verify a published image:

```sh
cosign verify ghcr.io/chiefgyk3d/typo-sniper:latest \
  --certificate-identity-regexp '^https://github.com/ChiefGyk3D/git-your-ship-together/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation --type spdxjson ghcr.io/chiefgyk3d/typo-sniper:latest \
  --certificate-identity-regexp '^https://github.com/ChiefGyk3D/git-your-ship-together/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  | jq -r .payload | base64 -d | jq .predicate

gh attestation verify oci://ghcr.io/chiefgyk3d/typo-sniper:latest --owner ChiefGyk3D
```

The certificate identity is the *reusable* workflow, not the caller. That is
how Sigstore attributes a job that runs inside a reusable workflow, and it is
the point: one identity to trust across every repository that calls it.

A caller pinned to `.github/workflows/python-docker-release.yml@<sha>` sees
no difference: that file forwards every input, the secret and the outputs to
`container-release.yml` at the same commit, and a test holds the two sets of
inputs identical. Move to the new name at the next pin bump. One thing to
know when verifying: the signing job's OIDC identity names the innermost
workflow, so a `--certificate-identity` written out in full says
`container-release.yml`; the `--certificate-identity-regexp` shown above
matches either.

Inputs of `container-release.yml`:

| Input | Default | Meaning |
|---|---|---|
| `dockerfile` | `Dockerfile` | Path to the Dockerfile |
| `context` | `.` | Build context |
| `platforms` | `linux/amd64,linux/arm64` | Platforms of the published image |
| `image-name` | repository name, lower-cased | Name under `ghcr.io/<owner>/` |
| `push` | `false` | Publish. `false` builds, tests and scans only |
| `tags` | branch, pr, semver ×3, sha, `latest` on the default branch | `docker/metadata-action` tag rules |
| `docker-test-command` | empty | Run against the locally built image; `$IMAGE` names it |
| `hadolint` | `true` | Lint the Dockerfile with hadolint before building |
| `hadolint-version` | `2.15.1` | hadolint release, downloaded as a pinned binary and cached |
| `hadolint-sha256-amd64`, `hadolint-sha256-arm64` | the hashes of 2.15.1 | SHA-256 of each Linux binary; the one for the runner's architecture is checked on every run. Change them with the version |
| `hadolint-args` | `--failure-threshold warning` | Arguments before the Dockerfile path |
| `hadolint-continue-on-error` | `false` | Report findings without failing, while a Dockerfile is being cleaned up |
| `require-non-root` | `true` | Fail when `docker run --entrypoint id <image> -u` prints `0`. Fix: a `USER` instruction. Turn off for a distroless or scratch image that has no `id` |
| `probe-read-only` | `false` | Also run the image with `--read-only --tmpfs /tmp` and fail if it breaks. Enable once the image writes only under tmpfs or volumes |
| `probe-command` | empty | Arguments for that probe, given to the image's own entrypoint: `docker run --rm --read-only --tmpfs /tmp "$IMAGE" <probe-command>`. It must exit by itself, such as `--version`; required when `probe-read-only` is true |
| `dockerhub` | `false` | Also publish to Docker Hub, credentials from Doppler |
| `dockerhub-repository` | repository name, lower-cased | Docker Hub repository name |
| `sign` | `true` | cosign keyless signature |
| `sbom` | `true` | syft SPDX SBOM, attached with cosign and kept as an artifact |
| `provenance` | `true` | GitHub Artifact Attestation (SLSA provenance) |
| `trivy` | `true` | Scan the image, upload SARIF |
| `trivy-severity` | `CRITICAL,HIGH` | Severities reported |
| `trivy-exit-code` | `"0"` | `"1"` makes findings fail the job. The default stays advisory until each calling repository's image is known clean; a caller flips it in its own pull request once its image is clean |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, the measured list, empty | harden-runner, as in `python-ci.yml` |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `doppler-trusted-refs-only` | `true` | Fetch CI secrets only on the default branch, a tag or a schedule; never on a pull request. See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `60` | Timeout of each platform's build job; a platform built under QEMU is slow |

Outputs: `digest` and `image` (`ghcr.io/...@sha256:...`) of the published
index, empty when not pushed.

### Verify published

`verify-published.yml` is consumer-side verification (roadmap item 23). The
producer, `container-release.yml`, signs the image, attaches an SBOM and records
provenance; this proves those verify from outside, the way an operator would
run them. It has no secret, no Doppler and no `id-token`: it reads only.

It runs, in order, and stops at the first failure:

```
cosign verify <image> \
  --certificate-identity-regexp '<identity-regexp>' \
  --certificate-oidc-issuer <oidc-issuer>
cosign verify-attestation --type spdxjson <image> \
  --certificate-identity-regexp '<identity-regexp>' \
  --certificate-oidc-issuer <oidc-issuer>
gh attestation verify oci://<image> --owner <owner of the image>
```

then, per platform, `docker pull --platform <platform> <image>` and the
`test-command`, with `$IMAGE` set. A platform that differs from the runner's
(arm64 on the x86 runner) runs under QEMU, which is set up only then. A final
`Verified` job is the gate: it fails unless the verification succeeded.

```yaml
on:
  schedule:
    - cron: "17 5 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  verify:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/verify-published.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      packages: read
    with:
      image: ghcr.io/chiefgyk3d/star-daemon:latest
      test-command: docker run --rm "$IMAGE" --version
```

The certificate identity of an image published through `container-release.yml`
is the reusable workflow's ref, so the default `identity-regexp` (any workflow
in the owner's repositories) matches it. Narrow it to pin one workflow, for
example `^https://github.com/ChiefGyk3D/git-your-ship-together/\.github/workflows/container-release\.yml@refs/tags/v`.

Inputs of `verify-published.yml`:

| Input | Default | Meaning |
|---|---|---|
| `image` | required | Image reference, for example `ghcr.io/chiefgyk3d/star-daemon:latest`; a digest is stronger than a tag |
| `identity-regexp` | `^https://github.com/ChiefGyk3D/` | Regular expression the certificate identity must match |
| `oidc-issuer` | `https://token.actions.githubusercontent.com` | OIDC issuer the certificate must name |
| `verify-sbom` | `true` | `cosign verify-attestation --type spdxjson` |
| `verify-provenance` | `true` | `gh attestation verify oci://<image> --owner <owner>` |
| `test-command` | empty | Run once per platform with `$IMAGE` set; empty skips |
| `platforms` | `linux/amd64,linux/arm64` | Platforms to pull and test |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `block`, the measured list, empty | harden-runner; the list covers the GHCR pull, Sigstore, and GitHub's attestation store |
| `timeout-minutes` | `20` | Job timeout |

### Python package release

For a project that ships to PyPI, or attaches its wheel to a GitHub release,
or both. Four repositories wrote this by hand before it existed here.

```yaml
name: Release
on:
  push: { tags: ['v*'] }
  pull_request:          # builds and checks; never publishes
  workflow_dispatch:

permissions:
  contents: read

jobs:
  package:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-package-release.yml@<sha> # vX.Y.Z
    permissions:
      contents: write      # the GitHub release and its assets
      id-token: write      # PyPI Trusted Publishing, and build provenance
      attestations: write  # the provenance record
    with:
      publish: ${{ startsWith(github.ref, 'refs/tags/v') }}
      verify-command: grep -q "^## \[$VERSION\]" CHANGELOG.md
      smoke-command: my-cli --version
      release-notes-command: python scripts/changelog_section.py "$VERSION"
      egress-policy: block
```

The build job does everything that runs the caller's code, with
`contents: read`: build, `twine check --strict`, read the version off the
sdist's own name (so a static `version =`, a dynamic attribute and a VCS
plugin all answer alike), refuse a tag that disagrees with it, run
`verify-command`, install the wheel into a fresh venv and run
`smoke-command`, write the release notes. The two publishing jobs check
nothing out: `publish-pypi` hands `dist/` to PyPI over the job's OIDC
identity from the `pypi` environment, and `github-release` records build
provenance for every file and attaches them with a `SHA256SUMS` to the
release for the tag, creating it from the notes when it does not exist and
uploading to it when it does (a caller that triggers on `release: published`).
Nothing needs a secret.

PyPI setup, once per project: on the project's *Publishing* page add a
Trusted Publisher naming this owner, the calling repository, the caller's
workflow file name (not this one's) and the environment `pypi`. That is the
whole credential.

Inputs of `python-package-release.yml`:

| Input | Default | Meaning |
|---|---|---|
| `python-version` | `3.13` | Python for the build, the checks and the smoke test |
| `package-directory` | `.` | Where `pyproject.toml` lives |
| `build-install-command` | upgrade pip, install `build` and `twine` | Installs the build tooling |
| `build-command` | `python -m build` | Writes the sdist and wheel to `dist/` |
| `tag-prefix` | `v` | What precedes the version in a tag: `v1.2.3` is version `1.2.3` |
| `verify-command` | empty | Run with `$VERSION` set, to refuse a release whose tree disagrees with it: a CHANGELOG section, a `__version__` |
| `smoke-command` | empty (skips the check) | Run with the built wheel installed in a fresh venv on `PATH`, e.g. `my-cli --version` |
| `release-notes-command` | empty (GitHub generates them) | Prints the release notes to stdout with `$VERSION` set |
| `publish` | `false` | Publish. A pull request never publishes whatever this says |
| `pypi` | `true` | Publish to PyPI |
| `pypi-environment` | `pypi` | The GitHub environment the PyPI job runs in, which the Trusted Publisher names |
| `github-release` | `true` | Attach the files, `SHA256SUMS` and provenance to the GitHub release |
| `release-title` | empty (the tag) | Title of a release this workflow creates |
| `attest` | `true` | Record SLSA build provenance for every file |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, the measured list, empty | harden-runner, as in `python-ci.yml`. The build's hosts were measured in block mode here; the publishing hosts are PyPI's and Sigstore's documented ones |
| `timeout-minutes` | `20` | Per-job timeout |

The workflow outputs `version`, the version the sdist was built as, for a
caller job that needs it.

### Artifact release

For anything that is a file rather than an image: hammunition-hill's `.deb`,
Skid-Finder's firmware, mother-ticker's offline bundle. The same
supply-chain story as the container release, for a file.

```yaml
name: Release
on:
  push: { tags: ['v*'] }
  pull_request:          # builds and checks; never publishes
  workflow_dispatch:

permissions:
  contents: read

jobs:
  artifacts:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/artifact-release.yml@<sha> # vX.Y.Z
    permissions:
      contents: write      # the GitHub release and its assets
      id-token: write      # keyless signing and build provenance
      attestations: write  # the provenance record
    with:
      publish: ${{ startsWith(github.ref, 'refs/tags/v') }}
      build-install-command: sudo apt-get install -y dpkg-dev
      build-command: ./packaging/debian/build.sh dist
      artifacts: dist/*.deb
      verify-command: dpkg-deb --info dist/*.deb | grep -q "Version: $VERSION"
      egress-policy: block
      extra-allowed-endpoints: azure.archive.ubuntu.com:80
```

The build job holds `contents: read` and runs everything the caller wrote:
`build-command` with `$VERSION` set (the tag with its prefix removed, or
`0.0.0+<sha>` off a tag), `verify-command`, the collection of every file
matching `artifacts`, and `release-notes-command`. The publish job checks
nothing out. It writes a `SHA256SUMS`, records build provenance for every
file, signs every file with cosign (keyless, a `<file>.sigstore.json` bundle
beside it), and attaches all of it to the release for the tag, creating it
from the notes or uploading to it when it exists. Verify a download with
`cosign verify-blob --bundle <file>.sigstore.json <file>` against this
repository's identity, or `gh attestation verify <file> --owner ChiefGyk3D`.

Inputs of `artifact-release.yml`:

| Input | Default | Meaning |
|---|---|---|
| `build-install-command` | empty | Run before the build, e.g. `sudo apt-get install -y dpkg-dev` |
| `build-command` | empty (the job fails) | Produces the files, with `$VERSION` set |
| `artifacts` | `dist/*` | Space-separated globs naming what to publish |
| `tag-prefix` | `v` | What precedes the version in a tag |
| `verify-command` | empty | Run after the build with `$VERSION` set, to refuse a release whose files disagree with it |
| `release-notes-command` | empty (GitHub generates them) | Prints the release notes to stdout with `$VERSION` set |
| `publish` | `false` | Publish. A pull request never publishes whatever this says |
| `github-release` | `true` | Attach the files, sums, signatures and provenance to the GitHub release |
| `release-title` | empty (the tag) | Title of a release this workflow creates |
| `sign` | `true` | cosign keyless signature bundle per file |
| `attest` | `true` | SLSA build provenance per file |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, GitHub and Sigstore, empty | harden-runner, as in `python-ci.yml`. The build's hosts depend on the build command and go in `extra-allowed-endpoints` |
| `timeout-minutes` | `30` | Per-job timeout |

The workflow outputs `version`.

### Pull-request checks

`python-ci.yml` and `bash-ci.yml` each take two optional jobs that run on
pull requests only. Both default to empty, which skips them; both are part of
the `CI green` gate when set. Both check out the full history
(`fetch-depth: 0`) so `origin/$BASE` resolves, hold `contents: read` and
nothing else, and never run the project's tests. The base branch's name and
the head commit reach the command as environment variables, never by
expansion into the script.

```yaml
    with:
      fragment-check-command: python3 scripts/changelog.py check-pr --base "origin/$BASE"
      commit-claims-command: python3 scripts/check_commit_claims.py --range "origin/$BASE..HEAD"
```

- **`fragment-check-command`** (the `Changelog fragment` job; `BASE` is the pull
  request's base branch). For a repository that keeps one changelog fragment
  per change under `changelog.d/<pr-or-branch>.<kind>.md` instead of editing
  `CHANGELOG.md` in the pull request. Every edit to a shared changelog section
  conflicts with every other pull request; a file each does not. The command
  is the repository's own script, and a failing exit is what turns the job red:
  usually "this change touches `src/` and adds no fragment", or "this change
  edited the Unreleased section".
- **`commit-claims-command`** (the `Commit claims` job; `BASE` is the base
  branch, `HEAD` the pull request's head commit, and git's own `HEAD` in the
  default merge checkout is the merge commit). For a repository whose commit
  messages make claims a diff can check: "adds a test", "removes the flag",
  "no functional change". The command reads each commit in the range and
  compares what it says with what it changed. A repository wants it after a
  commit message has once said something the diff did not do.

Neither is worth turning on for a repository that has no such script: the
command is the whole check, and this repository ships none. The first form
came from Hammunition's `changelog.d/` and its commit-claims check.

### Docs pages

Builds a static site on every pull request and deploys it to GitHub Pages
from the default branch. Built for MkDocs (`mkdocs build --strict`, with
`pip install -e ".[docs]"` first), but both commands are inputs, so anything
that writes a directory of static files fits: Sphinx, mdBook, a script.

```yaml
name: Docs
on:
  push: { branches: [main] }
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  docs:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/docs-pages.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      pages: write      # the deploy job only
      id-token: write   # the deploy job only: Pages verifies it
```

- The `build` job runs your commands with `contents: read` and no token. A
  strict build fails the pull request, so a broken link is caught in review,
  not published as a 404.
- The `deploy` job runs only on the default branch and never on a pull request.
  It holds `pages: write` and `id-token: write`, runs none of your commands,
  and uses the fixed concurrency group `pages`, which queues a deployment
  behind a running one and never cancels it.
- **The repository owner sets one thing once:** Settings, Pages, Build and
  deployment, Source: **GitHub Actions**. Until then `deploy` fails with a
  message that says so and names the URL; `build` is unaffected. `deploy: false`
  keeps a repository building only until it has made the setting.

| Input | Default | Meaning |
|---|---|---|
| `python-version` | `3.11` | Python the install and build run on |
| `install-command` | `pip install -e ".[docs]"` | Run before the build |
| `build-command` | `mkdocs build --strict` | Builds the site; a non-zero exit fails the job |
| `site-dir` | `site` | The directory the build writes, uploaded as the Pages artifact; an empty or missing one fails with a message |
| `deploy` | `true` | Upload and deploy on the default branch. `false` builds only |
| `egress-policy` | `audit` | harden-runner on every job |
| `allowed-endpoints` | `api.github.com`, `files.pythonhosted.org`, `github.com`, `pypi.org` | The allow-list for `block`; not yet measured against a caller, so the default policy is `audit` |
| `extra-allowed-endpoints` | empty | Appended to the list; a build that fetches fonts or plugins needs its hosts here |
| `timeout-minutes` | `30` | Per-job timeout |

It came from Hammunition's `pages.yml`, which published its MkDocs site; the
project-specific parts (its site, its extra, its nav) stayed there.

### Wiki publish

For a repository whose GitHub wiki is a **generated mirror** of something
else, usually its docs. Never a place to write: every run replaces every page,
so a page the generator stops writing disappears from the wiki.

```yaml
name: Wiki
on:
  push: { branches: [main] }
  workflow_dispatch:

permissions:
  contents: read

jobs:
  wiki:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/wiki-publish.yml@<sha> # vX.Y.Z
    permissions:
      contents: write   # the publish job only
    with:
      install-command: pip install -e ".[docs]"
      generate-command: python scripts/gen_wiki.py --out "$OUT_DIR" --commit "$SOURCE_SHA"
```

- Two jobs. `generate` has `contents: read`, runs `install-command` and
  `generate-command` and keeps the tree as an artifact; it runs on pull requests
  too, so a broken generator fails the review. `publish` has `contents: write`,
  checks nothing out and runs none of your commands, so the write token never
  sits beside your code. The token reaches git as a one-command header, never
  in a remote URL.
- The generator writes pages as flat files into `$OUT_DIR` (the `out-dir`
  input, inside the repository) and may read `$SOURCE_SHA`. An empty tree is
  refused, because publishing it would empty the wiki.
- `publish` runs only from the default branch, whatever started the run, and
  never from a pull request. The commit is by `github-actions[bot]` and names
  the source commit. Nothing is pushed when the tree is unchanged. The fixed
  concurrency group `wiki` runs one publish at a time and never cancels one
  halfway through a push.
- **The repository owner does one thing once, and GitHub offers it only in the
  UI:** a wiki's git repository does not exist until its first page is made.
  Open `<repository url>/wiki`, create any page, then re-run. Until then
  `publish` fails with exactly that instruction. The wiki must also be enabled
  in the repository's settings.

| Input | Default | Meaning |
|---|---|---|
| `generate-command` | required | Writes the wiki tree into `$OUT_DIR`; `$SOURCE_SHA` is the commit published |
| `out-dir` | `wiki-out` | Where the generator writes, relative to the repository root and inside it |
| `python-version` | `3.11` | Python the install and generate commands run on |
| `install-command` | empty (installs nothing) | Run before the generator |
| `publish` | `true` | Push to the wiki. `false` generates and keeps the tree only |
| `egress-policy` | `audit` | harden-runner on every job |
| `allowed-endpoints` | `api.github.com`, `files.pythonhosted.org`, `github.com`, `pypi.org` | The allow-list for `block`; not yet measured against a caller |
| `extra-allowed-endpoints` | empty | Appended to the list |
| `timeout-minutes` | `30` | Per-job timeout |

It came from Hammunition's `wiki.yml`, split into two jobs so the write token
is never beside the generator.

### Security

```yaml
name: Security
on:
  push: { branches: [main] }
  pull_request:
  schedule:
    - cron: '0 6 * * 1'   # weekly, so new advisories surface between commits
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/security.yml@<sha> # v1.3.1
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      id-token: write
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      codeql-queries: security-extended,security-and-quality
      snyk: true
      scorecard: true
      egress-policy: block
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

Inputs of `security.yml`:

| Input | Default | Meaning |
|---|---|---|
| `codeql` | `true` | Run CodeQL |
| `codeql-languages` | `python,actions` | Comma-separated. `actions` scans the workflow files themselves and fits every repository; a repository with no Python passes `actions` alone, since CodeQL fails on a language with no source |
| `codeql-queries` | `security-extended` | Query suite |
| `codeql-config` | empty | Inline CodeQL configuration, e.g. `paths-ignore` |
| `gitleaks` | `true` | Secret scan over the full history. Personal accounts need no licence; an organisation puts `GITLEAKS_LICENSE` in the Doppler config |
| `pip-audit-requirements` | `requirements.txt` | File audited with `--strict`; empty skips that step, and the job when `audit-command` is empty too |
| `pip-audit-continue-on-error` | `false` | Report advisories without failing. A migration aid |
| `pip-audit-extra-args` | empty | Extra pip-audit flags, e.g. `--ignore-vuln PYSEC-2026-3740` for an advisory with no fix yet; the ID needs an entry in [`baseline/risk-register.yaml`](baseline/risk-register.yaml) |
| `audit-install-command` | empty | Run before `audit-command`, e.g. `npm ci --ignore-scripts`; Python is available |
| `audit-command` | empty (runs nothing) | A dependency audit that is not pip-shaped: `npm audit --audit-level=high`, `govulncheck ./...`, `cargo audit`. Same job as pip-audit, after it; the tool's registry goes in `extra-allowed-endpoints` under `block` |
| `audit-continue-on-error` | `false` | Report `audit-command` findings without failing. A migration aid |
| `dependency-review` | `true` | On pull requests only |
| `dependency-review-severity` | `moderate` | Fail the review at this severity or above |
| `dependency-review-allow-ghsas` | empty | Comma-separated GHSA IDs the review may not fail on. Each needs an entry in [`baseline/risk-register.yaml`](baseline/risk-register.yaml); the audit checks |
| `dependency-review-deny-licenses` | `AGPL-3.0, GPL-3.0, GPL-2.0, LGPL-3.0, SSPL-1.0` | Comma-separated SPDX identifiers the review fails on when a pull request adds a dependency under one. Empty means no licence rule. A dependency whose licence cannot be detected is reported, not failed. Passed as the action's `deny-licenses`, which upstream has marked deprecated for a future major release; the action rejects it beside `allow-licenses`, which this workflow does not expose |
| `semgrep` | `true` | Semgrep over the repository, SARIF uploaded to the Security tab under category `semgrep`. Installed with pip, since `semgrep/*` actions are not in the allowed set |
| `semgrep-config` | `p/python p/github-actions p/secrets` | Space-separated configs, each passed as `--config`; registry packs or paths in the repository |
| `semgrep-version` | `1.179.0` | Semgrep release installed with pip |
| `semgrep-continue-on-error` | `false` | Report findings without failing (they still reach the Security tab). Without it the scan runs with `--error` and a finding fails the job. A migration aid |
| `semgrep-egress-policy` | `block` | harden-runner policy for the Semgrep job only |
| `semgrep-allowed-endpoints` | the measured list | The Semgrep job's own allow-list: PyPI for the pip install, `semgrep.dev` for the rule registry, and GitHub for the SARIF upload. `extra-allowed-endpoints` is appended to it, for a private rule registry or a config fetched from another host |
| `snyk` | `false` | Snyk Code and Snyk Open Source; needs `SNYK_TOKEN` in the Doppler config. Runs only on a trusted ref, never on a pull request |
| `scorecard` | `false` | OpenSSF Scorecard, published; runs only on the default branch (push or schedule) |
| `python-version` | `3.13` | Python for pip-audit and Snyk |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, the measured list, empty | harden-runner, as in `python-ci.yml` |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `doppler-trusted-refs-only` | `true` | Fetch CI secrets only on the default branch, a tag or a schedule; never on a pull request. See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `30` | Per-job timeout |

Only one job in `security.yml` is Python-shaped, and only by default: the
dependency audit runs pip-audit when `pip-audit-requirements` names a file
and whatever `audit-command` names otherwise, or both. CodeQL, gitleaks,
dependency review, Snyk and Scorecard read the repository whatever it is
written in. A shell-only repository therefore calls it with
`codeql-languages: actions` and `pip-audit-requirements: ""` and changes
nothing else.

The Snyk job fails only when Snyk did not run: an expired or revoked token
(exit 2) or a project it could not read. Findings (exit 1) go to the Security
tab as SARIF and do not fail the job; Snyk is a reporter here, CodeQL and
pip-audit are the gates.

### Dependabot auto-merge

Three things already stand between a dependency bump and the default branch:
the seven-day cooldown in `dependabot.yml`, the `ci / CI green` gate, and a
required pull request. What was left was a human clicking merge on a patch
bump that all three had already cleared. This workflow removes that click and
nothing else.

```yaml
name: Dependabot auto-merge
on: pull_request

permissions:
  contents: read

jobs:
  auto-merge:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/dependabot-auto-merge.yml@<sha> # v1.4.0
    permissions:
      contents: write        # enable auto-merge on the pull request
      pull-requests: write   # read its Dependabot metadata
```

Two settings have to be on, or nothing happens: **Allow auto-merge** in the
repository (`gh api -X PATCH repos/OWNER/REPO -F allow_auto_merge=true`) and a
required status check for the merge to wait on. Both are in
[BASELINE.md](BASELINE.md).

| Input | Default | Meaning |
|---|---|---|
| `max-update-type` | `minor` | The largest semver change that may merge on its own: `patch`, `minor` or `major`. A grouped bump is judged by its largest step |
| `merge-method` | `squash` | `squash`, `merge` or `rebase`. Squash is the default because a repository that requires linear history refuses a merge commit |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, three GitHub hosts, empty | harden-runner, as in `python-ci.yml`. The default is the GitHub subset of the CI measurement: `api.github.com`, `github.com` and `release-assets.githubusercontent.com`. It is not measured from a run of this workflow, so it stays in `audit` until a real Dependabot bump confirms it |
| `timeout-minutes` | `10` | Job timeout |

A major bump, or a pull request whose update type Dependabot did not report,
is left open with a notice saying so. The decision fails closed: an update
type the workflow does not recognise is never merged.

Why this is safe to give `contents: write` on a pull-request trigger, which
is normally the shape to avoid: **the job never checks the pull request out**.
It runs two pinned actions and the `gh` CLI against the API, so none of the
proposed code executes beside the grant. `dependabot/fetch-metadata` verifies
the commits really are Dependabot's before reporting what they change, the job
is gated on the pull request's author, and GitHub gives a fork's pull request
a read-only token whatever the workflow asks for. No `pull_request_target`, no
checkout, no code.

## Doppler setup

Doppler is the one rotation point. A CI job authenticates with a token that
lives for the job and is scoped to one repository's identity, and reads one
config that holds only what CI needs.

The Doppler steps (inlined in each workflow; `.github/actions/doppler-secrets`
is the same thing as a composite action) try, in order:

1. **OIDC** when `doppler-identity-id` is set. GitHub mints a JWT for the job
   (`id-token: write`), the action posts it to Doppler's
   `/v3/auth/oidc`, and Doppler returns a short-lived token for the identity's
   Service Account. Nothing static is stored anywhere.
2. **Service Token** when the caller passes the GitHub secret
   `DOPPLER_TOKEN`. Read-only, one config. Doppler still rotates it, but it is
   one static credential in GitHub per repository. Use it only where OIDC is
   not available (Doppler's Developer plan).
3. **Nothing**, with a notice, so a pipeline runs before Doppler is wired up.
   Steps that need a secret then skip (Docker Hub publish) or fail with a
   message naming the missing name (Snyk).

A fetch happens only on a **trusted ref**: a push to the default branch, a
tag, or a schedule. A pull request from anywhere and a push to any other branch
get nothing and a notice saying so. That is `doppler-trusted-refs-only`, on by
default in every workflow; turning it off means a pull request's proposed code
runs in a job that holds a secret. A pull request from a fork never fetches
anything, whichever way the input is set: GitHub mints no OIDC token for it,
and the step refuses it regardless. `tests/test_doppler_gate.py` runs that
decision under bash for every event and ref shape.

### Once, for the workplace

Service Account Identities need a Doppler workplace on the Team or Enterprise
plan. On a Developer plan, use path 2 and skip the identity step below.

1. **Config.** One Doppler project, `ci`, with an environment `ci` and config
   `ci`, separate from every runtime project. Every caller reads that one
   config (`doppler-project: ci`, `doppler-config: ci`). Put in it only what
   the pipelines read:

   | Name | Used by |
   |---|---|
   | `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | release, when `dockerhub: true` |
   | `SNYK_TOKEN` | security, when `snyk: true` |
   | `GITLEAKS_LICENSE` | security, organisation accounts only |

   Every value in the config is exported into every CI job's environment
   (masked), which is why the runtime secrets do not belong here, and why
   the runtime projects hold no CI credential. Codecov is not in the
   table: the upload authenticates with the coverage job's own GitHub OIDC
   token (`use_oidc: true`), so nothing is stored for it. Enable the
   repository at https://app.codecov.io under the Codecov GitHub App and set
   `codecov: true`.

   None of these providers issues a per-repository credential, which is why
   one config serves every repository. `scripts/doppler-ci-set.sh` prompts
   for one value with echo off and sets it there:

   ```sh
   scripts/doppler-ci-set.sh SNYK_TOKEN
   scripts/doppler-ci-set.sh DOCKERHUB_USERNAME
   scripts/doppler-ci-set.sh DOCKERHUB_TOKEN
   ```

   Snyk: the personal API token from Account settings (service accounts are
   Enterprise only; the token expires and the security job says so when it
   has). Docker Hub: a personal access token with `repo:write`; tokens are
   account-wide, not per repository. Rotation is the same command again,
   once.

   The trade is stated plainly: every CI job of every repository holds every
   CI credential while it runs, including a Docker Hub token in a repository
   that never publishes there. The credentials are account-wide at their
   providers, so one copy is one place to rotate; who fetched is still in
   Doppler's log per repository, through the identities below.

### Per repository

2. **Service Account.** Workplace → Team → Service Accounts → create one per
   repository (e.g. `gha-typo-sniper`), grant it *Viewer* on the `ci`
   project's `ci` environment and nothing else. Its workplace role is empty.

3. **Identity.** On the service account, add an Identity of type OIDC:
   - Issuer: `https://token.actions.githubusercontent.com`
   - Subject: `repo:ChiefGyk3D/<repo>:ref:refs/heads/main` (`master` where
     that is the default branch), plus `repo:ChiefGyk3D/<repo>:ref:refs/tags/*`
     where Doppler accepts more than one subject per identity, or a second
     identity for tags if it does not. The subject must never match
     `repo:ChiefGyk3D/<repo>:pull_request`: the workflows refuse to fetch on a
     pull request, and the identity is the second lock on the same door. The
     broad `repo:ChiefGyk3D/<repo>:*` works but matches pull-request tokens,
     so it relies on the workflow-side gate alone.
   - Audience: leave GitHub's default, `https://github.com/ChiefGyk3D`, which
     is what `dopplerhq/secrets-fetch-action` requests

   Copy the identity's UUID.

4. **Repository variable.** In the GitHub repository, Settings → Secrets and
   variables → Actions → **Variables**, add `DOPPLER_IDENTITY_ID` with the
   UUID. It is an identifier, not a secret: the trust is the OIDC claim match,
   and a variable keeps the caller YAML free of per-repository values.

5. **Delete** `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `CODECOV_TOKEN` and
   `SNYK_TOKEN` from the repository's GitHub secrets once a run has gone green
   through Doppler (`CODECOV_TOKEN` is simply no longer read). `GITHUB_TOKEN`
   is not a stored secret and stays. Then rotate the values at the provider:
   moving a token does not change it.

## Egress

Every job starts with harden-runner. In `audit` mode it logs each outbound
connection; in `block` mode it refuses any host not on `allowed-endpoints`.
The three Python workflows carry a measured list as that input's default:
every host their jobs reached across the calling repositories in a day of
audit-mode runs, with the runner's own infrastructure left out because the
agent allows it on its own. `bash-ci.yml`'s list was measured the other way
round: this repository runs it on itself in `block` mode with the default
list, so a host the list lacks fails here, named in the log, before any
caller meets it. A caller turns blocking on with one line:

```yaml
with:
  egress-policy: block
```

Every caller in `baseline/repos.txt` runs `block` on all three workflows.
A host only one repository reaches, such as an apt repository or an
installer its Dockerfile pulls, goes in `extra-allowed-endpoints` on that
caller, not in the shared default. A blocked connection shows in the job log
as `domain not allowed: <host>`, which is also how a new dependency announces
itself.

The `distro` lists (`distro-allowed-endpoints` in `python-ci.yml` and
`bash-ci.yml`) were measured in `block` mode on the fixture's Debian 12 and 13,
Ubuntu 24.04, Kali and Parrot images on both runners:
[run 37131671587](https://github.com/ChiefGyk3D/git-your-ship-together/actions/runs/37131671587).
`semgrep-allowed-endpoints` was measured the same way in
[run 37131671510](https://github.com/ChiefGyk3D/git-your-ship-together/actions/runs/37131671510),
and `verify-published.yml`'s list (its `fixture verify` job, which refused
GitHub's attestation store until `tmaproduction.blob.core.windows.net` was
added) in the CI run above. Fedora was not measured: `dnf` takes its mirror from a
metalink answer that varies per run, so `fedora:*` needs `distro-egress-policy`
set to `audit`, or the mirrors it reached in `extra-allowed-endpoints`.

The Snyk hosts in `security.yml`'s default (`api`, `app`, `deeproxy`,
`downloads` and `static` under `snyk.io`) came from Snyk's documentation
rather than a measurement, because the first run with a token logged its
connections by IP only. Every Snyk-enabled repository has since run green
under `block` with no `domain not allowed` line, which is the measurement.

## Repository settings that no YAML can set

[BASELINE.md](BASELINE.md) is the full list with the reasons and the `gh api`
command for each, and `python scripts/audit_baseline.py` reports every
repository in `baseline/repos.txt` against it. In short, for each calling
repository, once its first run is green:

1. **Branch protection on the default branch**: require the `CI green` gate
   of every shared CI workflow the repository calls (`ci / CI green`, plus
   `shell / CI green` where a `shell:` job calls `bash-ci.yml`, and so on),
   require a pull request with an approval count of zero, and
   dismiss stale approvals on new pushes. A count of one on a single-maintainer
   repository never produces a review, because GitHub does not let an author
   approve their own pull request; it only blocks the merge until the owner
   overrides it as an administrator, which teaches the habit of overriding.
   Zero keeps the pull request and the green check required and lets a
   Dependabot bump merge on its own.
2. **Actions settings**: `GITHUB_TOKEN` read-only by default and unable to
   approve pull requests; every outside contributor's run needs approval, not
   only a first-time contributor's; and only GitHub-owned actions plus the
   list in `baseline/selected-actions.json` may run at all. The pins say
   which commit of an action runs; this setting says which actions may run,
   so a pull request that adds one outside the list fails at workflow start.
3. **Secret scanning and push protection** (Settings → Code security): both
   on. Push protection refuses a commit that carries a known credential
   shape before gitleaks ever sees it.
4. **Private vulnerability reporting**: on, so `SECURITY.md`'s link works.
5. **Dependabot security updates**: on. The version updates come from the
   repository's `dependabot.yml`; this switch adds the advisory-driven ones.
6. **Repository variable `DOPPLER_IDENTITY_ID`**: see Doppler setup above.
7. **No GitHub Actions secrets** once the Doppler path has produced a green
   run. `gh secret list` should print nothing.
8. **Allow auto-merge**, so a Dependabot bump that clears the cooldown and the
   gate can land without a click. See
   [Dependabot auto-merge](#dependabot-auto-merge).
9. **Version tags are immutable**: a ruleset on `refs/tags/v*` that forbids
   deleting, moving or force-pushing a tag. Callers pin SHAs, but Dependabot
   follows tags, and a moved tag is the one way a pin and its version comment
   can silently disagree.

Signed commits are not required yet. The laptop signs with a registered SSH
key and its commits and tags verify; the rule goes on when every place that
commits is signing (roadmap item 14).

## Releasing a version of this repository

Callers' Dependabot follows the tags, so a tag is the release.

```sh
git fetch --tags && git tag -l | sort -V | tail -3   # see what exists before choosing a number
git tag -a v1.3.1 <sha> -m "v1.3.1: ..."
git push origin v1.3.1
```

Fetch first. Another session cut v1.3.0 while this one believed the latest
was v1.2.0, and the v1.2.1 that followed would have moved every caller's pin
backwards on the next Dependabot run; it was deleted and re-cut as v1.3.1.
zizmor's `ref-version-mismatch` audit fails a caller whose `# vX.Y.Z` comment
names a tag that does not exist, which is the intended check that a pin and
its comment agree.

## Risk register

A scanner sometimes names an advisory that cannot be fixed yet: the newest
release of a package is the affected one, or the affected code is a
transitive dependency nothing here calls. Two inputs of `security.yml` let a
caller skip such an advisory, `pip-audit-extra-args: --ignore-vuln <id>` and
`dependency-review-allow-ghsas: <id>`, and both lead to
[`baseline/risk-register.yaml`](baseline/risk-register.yaml). Taking an
exception is three steps, in this order:

1. **Enter it in the register**, in this repository: the advisory ID and its
   aliases (the GHSA and the PYSEC ID are usually the same advisory), the
   package and affected range, the repositories allowed to except it, which
   check names it, the reason it is accepted rather than fixed, what limits
   the exposure meanwhile, the date accepted, a `review_by` date at most 90
   days out, and an owner. `tests/test_risk_register.py` checks the shape and
   the dates, and fails the day an entry expires.
2. **Name it in the caller**, with a comment pointing at the register entry.
3. **Run the audit.** Its `risk-exceptions` check reads every caller's
   security workflow and fails on an ignored advisory that is not registered,
   is registered for another repository, or whose review date has passed. An
   exception therefore cannot be taken quietly and cannot be forgotten.

When the fix ships, remove both the caller's line and the entry. Renewing an
entry means moving `review_by` and saying why in the reason.

## Lessons learned the hard way

Each of these cost at least an afternoon. They are here so they cost you
nothing.

- **A tag's SHA is not a commit's SHA.** `git ls-remote --tags` lists an
  annotated tag twice; the `^{}` line is the commit. Pin that one. GitHub
  resolves a tag object in `uses:`, Dependabot does not.
- **harden-runner's allow-list is one space-separated line.** A YAML literal
  block (`|`) keeps the newlines, the agent matches nothing and blocks
  everything, including PyPI. Use a folded block (`>`) or one line. Wildcards
  (`*.example.com`) are not supported and invalidate the whole list. A test
  now holds the defaults to one sorted line of `host:port`.
- **The Actions allow-list needs the subdirectory forms too.** `snyk/actions@*`
  does not cover `snyk/actions/setup`; `github/codeql-action@*` does not cover
  `github/codeql-action/init`. And a composite action's own `uses:` lines
  count: `aquasecurity/trivy-action` calls `aquasecurity/setup-trivy`, and
  without that entry every release job failed at start with no annotation to
  say why. Read an action's `action.yml` for nested `uses:` before listing it.
- **Snyk's pip resolver cannot read extras.** A requirement like
  `package[aws,vault]>=0.2` makes `snyk test` exit 2 with "Missing required
  packages" even when everything is installed. `--skip-unresolved=true` is
  Snyk's documented answer, and the workflow's failure message now names this
  case as well as the token.
- **Trivy's setuptools finding may be pip's, not yours.** pip vendors its own
  copies of setuptools and msgpack under `pip/_vendor`, so upgrading
  setuptools in the image clears nothing. `pip uninstall -y pip` as the last
  build step does, and a runtime image has no use for pip anyway.
- **A required review count of one is a required admin override** when one
  person holds write. Set it to zero and let the required check do the
  gating.
- **Dismiss-stale plus Dependabot rebases means re-approving every bump.**
  With the count at zero that is moot; with it at one, every rebase from a
  merged sibling bump dismissed the approval.
- **Codecov needs no token on a public repository.** `use_oidc: true` and the
  job's own identity is enough. The token that used to live in every
  repository that uploads was one more thing to rotate for nothing.
- **A deleted code-scanning configuration leaves its analyses in the API.**
  GitHub records the deletion as one empty analysis in that category; the old
  ones stay listed and look alive. The pull-request check summary is the
  truth: "1 configuration not found" means the deletion has not happened.
- **The first block-mode run may log IPs, not names.** harden-runner's audit
  summary showed Snyk's hosts as addresses only, so that list came from
  Snyk's documentation and was confirmed by a clean run, not measured first.
- **Fetch the tags before you cut one.** See [Releasing](#releasing-a-version-of-this-repository).
- **Every value in a Doppler config is exported.** A CI config that shares an
  environment with runtime secrets makes every runtime secret a CI secret in
  every job. Separate project, separate config, and only the names the
  pipelines read.

## Developing

```sh
pip install -r requirements-dev.txt
pytest
ruff check tests/ scripts/ fixture/ && ruff format --check tests/ fixture/
actionlint          # https://github.com/rhysd/actionlint
zizmor --offline .  # https://docs.zizmor.sh
python scripts/audit_baseline.py   # needs a token with admin read on the repositories
```

The tests are the contract, one file per thing they hold still:

| File | Holds |
|---|---|
| `tests/test_workflows.py` | SHA pins with version comments; no reference to this repository by branch; no `pull_request_target`; the write-permission allow-list; per-job permissions and timeouts; harden-runner first in every job; `persist-credentials: false` on every checkout; no untrusted interpolation; the inlined Doppler script identical to the composite action and gated on the decide step; no OIDC token on a job a pull request can run, and none on the test job; every input declared, defaulted, used and documented here; `CI green` needing every other job; signing and attestation only after a push; no Actions cache on a publishing build; the allow-list defaults one sorted line; every reusable workflow run against the fixture from this repository at the pull request's ref, never publishing |
| `tests/test_doppler_gate.py` | The decide script, run under bash for every event and ref shape: trusted refs fetch, untrusted refs get a notice and never fail, forks never fetch, the Service Token path is gated the same way |
| `tests/test_audit_baseline.py` | The audit, fed a passing repository and a broken one per criterion; a 403 comes back UNKNOWN, never PASS; exit codes tell FAIL from UNKNOWN |
| `tests/test_risk_register.py` | The register's shape, its dates, no duplicate advisory, every repository named is in the baseline list, and no entry has expired |
| `tests/test_fixture.py` | Every fixture requirement carries a hash, every direct dependency is in the lock, the fixture image runs as a non-root user |

Break any one of those and CI names the fix.

The tests are structural. What runs the workflows is `fixture/`: a Python
project small enough to be obviously correct, with one of everything a job
needs, that this repository's own `ci.yml` puts through `python-ci.yml` and
`python-docker-release.yml` (`push: false`) at the pull request's ref, while
`security-self.yml` does the same for `security.yml`. A change to a reusable
workflow therefore runs against a real project here before any caller pins
it, and `CI green` needs those runs. `fixture/README.md` says how to
regenerate its hash-pinned `requirements.txt`.

Adding a repository: `scripts/new-repo.sh OWNER/NAME`. It reads the
repository (languages, tool configuration, Dockerfile, the workflows already
there), writes the caller files from what it found with one CI job per
language, replaces the old CI workflows and names them in the pull request
it opens, applies every setting in BASELINE.md, and appends the repository to
`baseline/repos.txt`. What it cannot do is Doppler: the service account and
identity are made in the dashboard, and it prints those two steps and takes
the UUID back through `--doppler-identity`. `--dry-run --out DIR` shows the
files and the settings without touching anything. Then run the audit until
it is clean. A repository not in the list is not covered.

## The weekly audit

`.github/workflows/audit.yml` runs on Monday at 07:00 UTC and on demand
(Actions, Audit, Run workflow). It has two jobs.

**`audit`** runs `scripts/audit_baseline.py` over every repository in
`baseline/repos.txt` and puts the report in the job summary. The job is red on
any FAIL and on any UNKNOWN: a check the token could not make is not a pass.
The token is `AUDIT_GITHUB_TOKEN`, fetched from Doppler over the job's OIDC
identity. It lives in a **separate Doppler project**, `audit`, config `prd`,
holding that one secret, and not in the shared `ci` project: the token can read
the settings of every repository, and the `ci` config is read by every
caller's pipeline. The job runs only from `main` or the schedule, and the
identity is scoped to that ref alone. harden-runner is in `block` mode with
five hosts: `api.doppler.com`, `api.github.com`, `files.pythonhosted.org`,
`github.com` and `pypi.org`.

**`register-issues`** holds no token but the workflow's own `GITHUB_TOKEN`
(`issues: write`, this repository only). It runs
`python scripts/audit_baseline.py --expiring 21`, which prints one
tab-separated line per [risk-register](#risk-register) entry whose `review_by`
is within 21 days or past, and opens one issue per entry titled
`Risk register: <id> expires <date>`. An open issue for the same `<id>` is
reused, and its title is edited when the date has moved, so a renewal never
opens a second issue. Close the issue when the entry is renewed or removed.

### Setup (the owner's, in the dashboards)

Nothing in the repository can do these; until they are done the `audit` job
fails at the Doppler step, which is the right answer to "the audit could not
run".

1. **Doppler:** create the project `audit` with the config `prd` and add the
   secret `AUDIT_GITHUB_TOKEN`.
2. **Doppler:** create the service account `gha-audit` with read access to
   that project only, and an OIDC identity on it whose subject is
   `repo:ChiefGyk3D/git-your-ship-together:ref:refs/heads/main`.
3. **GitHub:** set the repository variable `AUDIT_DOPPLER_IDENTITY_ID` on
   this repository to that identity's UUID.
4. **GitHub:** create the token as a fine-grained personal access token with
   resource owner `ChiefGyk3D`, access to the repositories in
   `baseline/repos.txt`, and these read-only repository permissions, which
   are exactly what the script's API calls need:
   - **Administration: read** (branch protection, security features,
     private vulnerability reporting, the Actions permission endpoints, rulesets)
   - **Contents: read** (the workflow files, `dependabot.yml` and the lock
     files it reads)
   - **Variables: read** (`DOPPLER_IDENTITY_ID` on each repository)
   - **Metadata: read** (added automatically; the repository and collaborator lists)

   No write permission, and nothing at the account or organization level. Give
   it the shortest expiry you will keep up with and note the date: an expired
   token turns the audit red with UNKNOWN, never green.

### Reading a red run

Open the job summary. Each repository lists its checks as `PASS`, `FAIL` or
`UNKNOWN` with a one-line reason, and the last line counts them. A `FAIL`
names the setting that drifted; fix it in the repository (see
[`BASELINE.md`](BASELINE.md) for what each check wants), or, if the baseline
was wrong, change the baseline in the same pull request that changes the
check. `UNKNOWN` is a check the token could not make, almost always an
expired or under-scoped token (a 403 or 404 in the reason): fix the token, not
the check. A run that fails before the report, at the Doppler step, is a
setup problem; the notice above it says which input was missing. Run the
same thing by hand with `python scripts/audit_baseline.py` and your own
`gh auth login`.

## Licence

MIT. See `LICENSE`.
