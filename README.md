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

Eight reusable workflows and one composite action:

| File | What it does |
|---|---|
| `.github/workflows/python-ci.yml` | Lint, workflow lint, test matrix, coverage upload, optional CLI smoke test, single-arch container build with a check, one `CI green` gate job |
| `.github/workflows/bash-ci.yml` | shellcheck and shfmt over every tracked script, an optional test command, an optional configuration lint (yamllint, ansible-lint), workflow lint, the same `CI green` gate. Holds no token |
| `.github/workflows/container-release.yml` | Build, test, Trivy-scan, then publish multi-arch to GHCR (and Docker Hub), sign with cosign, attach a syft SBOM, record SLSA provenance. Builds whatever the Dockerfile builds |
| `.github/workflows/python-docker-release.yml` | The old name of the above: a thin caller that forwards every input, the secret and the outputs through a `./` reference at its own commit, so an existing pin keeps working. New callers use `container-release.yml` |
| `.github/workflows/python-package-release.yml` | Build the sdist and wheel, `twine check`, refuse a tag that disagrees with the packaged version, smoke-test from the wheel, then publish to PyPI (Trusted Publishing, PEP 740 attestations) and to the GitHub release with SHA256SUMS and build provenance. No secret anywhere |
| `.github/workflows/artifact-release.yml` | For a file rather than an image (a `.deb`, a firmware binary, a bundle): build it with a command, then publish it to the GitHub release with SHA256SUMS, a keyless cosign signature bundle per file and build provenance. No secret anywhere |
| `.github/workflows/security.yml` | CodeQL (the `actions` language included by default), gitleaks, a dependency audit (pip-audit, and any other tool by command), dependency review on pull requests, optional Snyk, optional OpenSSF Scorecard |
| `.github/workflows/dependabot-auto-merge.yml` | Queues a Dependabot bump to merge itself once the required checks pass, up to a size you choose |
| `.github/actions/doppler-secrets` | Fetches a Doppler config as masked environment variables, over OIDC or a Service Token. The workflows inline a copy of it (see the design rules); this is the source |

This repository's own pipeline, which runs the workflows against a real
project before any caller pins them:

| File | What it does |
|---|---|
| `.github/workflows/ci.yml` | actionlint, zizmor, the pytest contract, then `python-ci.yml`, `bash-ci.yml`, `python-package-release.yml`, `artifact-release.yml` and `python-docker-release.yml` called at the pull request's own ref against `fixture/` (bash-ci over the whole repository; bash-ci and the package build in block mode), and a `CI green` gate that needs all of it |
| `.github/workflows/security-self.yml` | `security.yml` called the same way, on push, pull request and a Monday schedule |
| `.github/workflows/dependabot-auto-merge-self.yml` | `dependabot-auto-merge.yml` called the same way, so this repository's own bumps exercise it |
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
  cancel-in-progress: true

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
| `coverage-python-version` | `3.13` | The matrix leg that uploads coverage |
| `install-command` | upgrade pip, `pip install -r requirements.txt` | Run before tests on every leg |
| `test-command` | `pytest` | The test suite |
| `coverage-file` | `coverage.xml` | Uploaded as an artifact when present |
| `codecov` | `false` | Also upload to Codecov over GitHub OIDC; no token, the repository just has to be enabled in the Codecov GitHub App |
| `lint-python-version` | `3.13` | Python for the lint job |
| `lint-install-command` | `pip install ruff` | Installs the linters |
| `lint-command` | `ruff check .` | The lint step |
| `lint-continue-on-error` | `false` | Report lint failures without failing CI. A migration aid; no caller sets it any more |
| `smoke-command` | empty (skips the job) | Run after installing the project, e.g. `my-cli --version` |
| `smoke-install-command` | `pip install .` | Installs the project for the smoke test |
| `docker-build` | `true` | Build the image, single platform, never pushed |
| `dockerfile` | `Dockerfile` | Path to the Dockerfile |
| `docker-context` | `.` | Build context |
| `docker-test-command` | empty (skips the check) | Run against the built image; `$IMAGE` names it |
| `workflow-lint` | `true` | actionlint and zizmor over the caller's own `.github/workflows` |
| `zizmor-persona` | `regular` | zizmor strictness: `regular`, `pedantic`, `auditor` |
| `egress-policy` | `audit` | harden-runner on every job: `audit` logs outbound connections, `block` allows only `allowed-endpoints` |
| `allowed-endpoints` | the measured list | harden-runner allow-list for `block`, space-separated `host:port`; see [Egress](#egress) |
| `extra-allowed-endpoints` | empty | Appended to the list, for hosts only this repository reaches |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `doppler-trusted-refs-only` | `true` | Fetch CI secrets only on the default branch, a tag or a schedule; never on a pull request. See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `30` | Per-job timeout |

Every command input (`lint-command`, `test-command`, `smoke-command`,
`docker-test-command`, the install commands) reaches the shell as an
environment variable run by `bash -eo pipefail -c`, never by template
expansion into the script. Multi-line values work as written.

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
| `test-command` | empty (skips the job) | The shell test suite: `bats tests/`, `./tests/run.sh`, whatever the repository has |
| `config-lint-install-command` | `pip install yamllint` | Installs the configuration linters, with Python available |
| `config-lint-command` | empty (skips the job) | Lints the configuration kept beside the scripts: yamllint, ansible-lint |
| `config-lint-python-version` | `3.13` | Python for that job |
| `workflow-lint` | `true` | actionlint and zizmor over the caller's own `.github/workflows`; turn off on one job when another caller job already runs it |
| `zizmor-persona` | `regular` | zizmor strictness: `regular`, `pedantic`, `auditor` |
| `egress-policy` | `audit` | harden-runner on every job; see [Egress](#egress) |
| `allowed-endpoints` | the measured list | harden-runner allow-list for `block`, space-separated `host:port` |
| `extra-allowed-endpoints` | empty | Appended to the list, for hosts only this repository reaches |
| `timeout-minutes` | `15` | Per-job timeout |

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
| `dockerhub` | `false` | Also publish to Docker Hub, credentials from Doppler |
| `dockerhub-repository` | repository name, lower-cased | Docker Hub repository name |
| `sign` | `true` | cosign keyless signature |
| `sbom` | `true` | syft SPDX SBOM, attached with cosign and kept as an artifact |
| `provenance` | `true` | GitHub Artifact Attestation (SLSA provenance) |
| `trivy` | `true` | Scan the image, upload SARIF |
| `trivy-severity` | `CRITICAL,HIGH` | Severities reported |
| `trivy-exit-code` | `"0"` | `"1"` makes findings fail the job |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, the measured list, empty | harden-runner, as in `python-ci.yml` |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `doppler-trusted-refs-only` | `true` | Fetch CI secrets only on the default branch, a tag or a schedule; never on a pull request. See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `60` | Job timeout; arm64 builds under QEMU are slow |

Outputs: `digest` and `image` (`ghcr.io/...@sha256:...`) of the published
index, empty when not pushed.

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

## Licence

MIT. See `LICENSE`.
