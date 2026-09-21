# git-your-ship-together

> Reusable workflows. Repeatable builds. Less "what the fuck broke?"

One place to fix a pipeline bug or add a scan step, instead of one per
repository. These are the GitHub Actions workflows shared by ChiefGyk3D's
Python projects (Typo Sniper, Stream Daemon, Star Daemon, Boon Tube Daemon, and
whatever comes next).

Why it is built this way, what it is built on, and what it defends against:
[docs/DESIGN.md](docs/DESIGN.md). What every calling repository must meet:
[BASELINE.md](BASELINE.md).

Three reusable workflows and one composite action:

| File | What it does |
|---|---|
| `.github/workflows/python-ci.yml` | Lint, test matrix, optional CLI smoke test, single-arch container build with a check, one `ci-green` gate job |
| `.github/workflows/python-docker-release.yml` | Build, test, Trivy-scan, then publish multi-arch to GHCR (and Docker Hub), sign with cosign, attach a syft SBOM, record SLSA provenance |
| `.github/workflows/security.yml` | CodeQL, gitleaks, pip-audit, dependency review on pull requests, optional Snyk |
| `.github/actions/doppler-secrets` | Fetches a Doppler config as masked environment variables, over OIDC or a Service Token |

Design rules, applied throughout:

- **Doppler is the single source of truth for secrets, in CI as well as at
  runtime.** A workflow authenticates to Doppler with a short-lived token minted
  from the job's own GitHub OIDC identity. Nothing is duplicated into GitHub's
  encrypted secrets. See [Doppler setup](#doppler-setup).
- **Every third-party action is pinned to a commit SHA** with a version comment;
  Dependabot moves both together. `tests/test_workflows.py` fails otherwise.
- **Permissions are declared per job and every write is on a list** with a
  reason (`ALLOWED_WRITES` in the tests). `contents: read` at the top of every
  file; jobs widen only what they need.
- **Nothing from an untrusted context is interpolated into a shell.** Values
  pass through `env:`.
- **Every job has a timeout**, and every checkout sets
  `persist-credentials: false`.
- **Every job starts with harden-runner.** `audit` by default, which logs
  every outbound connection; `egress-policy: block` on the caller turns on
  the measured allow-list each workflow carries as its default. See
  [Egress](#egress).
- **The workflows never reference this repository by branch.** A reusable
  workflow cannot name the commit it runs from, so the Doppler steps are
  inlined rather than referenced as `@main`; a test holds the four copies
  identical to `.github/actions/doppler-secrets`, which stays as the source
  and for use outside these workflows.

## Calling the workflows

Callers pin a **commit SHA with the version in a comment**, the same rule
every third-party action is held to here, and Dependabot moves the pin:

```yaml
uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@<sha> # v1.0.0
```

Resolve a tag with `git ls-remote --tags <repo> 'refs/tags/vX.Y.Z*'` and take
the `^{}` (peeled) line when there is one: an annotated tag's own SHA is a tag
object, not a commit. Four pins in the first version of this repository were
tag objects; GitHub happened to resolve them, Dependabot would not have.

Secrets are passed by name, never with `secrets: inherit`, so a called
workflow can only ever see the one secret it declares.

### CI

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  ci:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@<sha> # v1.0.0
    permissions:
      contents: read
      id-token: write
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}   # optional fallback, may be unset
    with:
      python-versions: '["3.11", "3.12", "3.13"]'
      test-command: pytest --cov=my_package --cov-report=xml
      dockerfile: docker/Dockerfile
      docker-test-command: docker run --rm "$IMAGE" python -c "import my_package"
      doppler-project: my-project
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

Point branch protection at the **CI green** job. It needs every other job and
fails if any of them failed, so a job added here can never merge unchecked.

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
| `lint-continue-on-error` | `false` | Report lint failures without failing CI. A migration aid |
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

### Container release

```yaml
name: Release
on:
  push:
    branches: [main]
    tags: ['v*']
  pull_request:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  container:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-docker-release.yml@<sha> # v1.0.0
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
      security-events: write
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      dockerfile: docker/Dockerfile
      push: ${{ github.event_name != 'pull_request' }}
      docker-test-command: docker run --rm "$IMAGE" python -c "import my_package"
      dockerhub: true
      doppler-project: my-project
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

Inputs of `python-docker-release.yml`:

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
| `timeout-minutes` | `60` | Job timeout; native builds on arm64 under QEMU are slow |

A publishing build never reads the GitHub Actions cache. Anyone who can open
a pull request can write to that cache, and a poisoned layer inside a signed
release is the one outcome the signature cannot undo. Pull-request builds use
the cache, publishing builds start clean.

Outputs: `digest` and `image` (`ghcr.io/...@sha256:...`) of the published
index, empty when not pushed.

### Security

```yaml
name: Security
on:
  push: { branches: [main] }
  pull_request:
  schedule:
    - cron: '0 6 * * 1'
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/security.yml@<sha> # v1.0.0
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      id-token: write
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      codeql-config: |
        paths-ignore:
          - tests/
```

Inputs of `security.yml`:

| Input | Default | Meaning |
|---|---|---|
| `codeql` | `true` | Run CodeQL |
| `codeql-languages` | `python` | Comma-separated |
| `codeql-queries` | `security-extended` | Query suite |
| `codeql-config` | empty | Inline CodeQL configuration, e.g. `paths-ignore` |
| `gitleaks` | `true` | Secret scan over the full history. Personal accounts need no licence; an organisation puts `GITLEAKS_LICENSE` in the Doppler config |
| `pip-audit-requirements` | `requirements.txt` | File audited with `--strict`; empty skips the job |
| `pip-audit-continue-on-error` | `false` | Report advisories without failing. A migration aid |
| `pip-audit-extra-args` | empty | Extra pip-audit flags, e.g. `--ignore-vuln PYSEC-2026-3740` for an advisory with no fix yet; say why in the caller |
| `dependency-review` | `true` | On pull requests only |
| `dependency-review-severity` | `moderate` | Fail the review at this severity or above |
| `snyk` | `false` | Snyk Code and Snyk Open Source; needs `SNYK_TOKEN` in the Doppler config |
| `scorecard` | `false` | OpenSSF Scorecard, published; runs only on the default branch (push or schedule) |
| `python-version` | `3.13` | Python for pip-audit and Snyk |
| `egress-policy`, `allowed-endpoints`, `extra-allowed-endpoints` | `audit`, the measured list, empty | harden-runner, as in `python-ci.yml` |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `doppler-trusted-refs-only` | `true` | Fetch CI secrets only on the default branch, a tag or a schedule; never on a pull request. See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `30` | Per-job timeout |

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
   `DOPPLER_TOKEN` (`secrets: { DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }} }`). Read-only, one config. Doppler
   still rotates it, but it is one static credential in GitHub per repository.
   Use it only where OIDC is not available.
3. **Nothing**, with a notice, so a pipeline runs before Doppler is wired up.
   Steps that need a secret then skip (Docker Hub publish) or fail
   with a message naming the missing name (Snyk).

A fetch happens only on a **trusted ref**: a push to the default branch, a
tag, or a schedule. A pull request from anywhere and a push to any other branch
get nothing and a notice saying so. That is `doppler-trusted-refs-only`, on by
default in every workflow; turning it off means a pull request's proposed code
runs in a job that holds a secret. A pull request from a fork never fetches
anything, whichever way the input is set.

The Snyk job runs only off pull requests for the same reason, and Codecov
uploads run in their own job that never sees a pull request (see [CI](#ci)).
Everything a repository must meet beyond these workflows - who can push,
branch protection, Actions settings, scanning - is in [BASELINE.md](BASELINE.md),
with `scripts/audit_baseline.py` to check every repository against it.

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
   Enterprise only). Docker Hub: a personal access token with `repo:write`;
   tokens are account-wide, not per repository. Rotation is the same command
   again, once.

   The trade is stated plainly: every CI job of every repository holds every
   CI credential while it runs, including a Docker Hub token in a repository
   that never publishes there. The credentials are account-wide at their
   providers, so one copy is one place to rotate; who fetched is still in
   Doppler's log per repository, through the identities below.

### Per repository

2. **Service Account.** Workplace → Team → Service Accounts → create one per
   repository (e.g. `gha-typo-sniper`), grant it *Viewer* on the `ci`
   project's `ci` environment and nothing else.

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
   is not a stored secret and stays.

## Egress

Every job starts with harden-runner. In `audit` mode it logs each outbound
connection; in `block` mode it refuses any host not on `allowed-endpoints`.
The three workflows carry a measured list as that input's default: every
host their jobs reached across the calling repositories in a day of
audit-mode runs, with the runner's own infrastructure left out because the
agent allows it on its own. A caller turns blocking on with one line:

```yaml
with:
  egress-policy: block
```

A host only one repository reaches, such as an apt repository or an
installer its Dockerfile pulls, goes in `extra-allowed-endpoints` on that
caller, not in the shared default. Two things the agent does not say out
loud, learned the hard way: the list is space-separated, so a YAML literal
block (`|`) keeps the newlines and the agent then matches nothing and blocks
everything; and wildcards such as `*.example.com` are not supported and
invalidate the list. `blocked` connections show in the job log as `domain
not allowed: <host>`, which is also how a new dependency announces itself.

The Snyk job's hosts are not in `security.yml`'s default yet: no Snyk token
had been configured when the lists were measured. Measure one run in audit
mode after the token is in, then add them.

## Repository settings that no YAML can set

[BASELINE.md](BASELINE.md) is the full list with the reasons, and
`python scripts/audit_baseline.py` reports every repository in
`baseline/repos.txt` against it. In short, for each calling repository, once
its first run is green:

1. **Branch protection on `main`**: require the `CI green` status check
   (python-ci's gate job), require a pull request, and dismiss stale
   approvals on new pushes. A job added to python-ci is covered
   automatically because the gate `needs` every other job.
2. **Secret scanning and push protection** (Settings → Code security): both
   on. Push protection refuses a commit that carries a known credential
   shape before gitleaks ever sees it.
3. **Private vulnerability reporting**: on, so `SECURITY.md`'s link works.
4. **Dependabot security updates**: on. The version updates come from the
   repository's `dependabot.yml`; this switch adds the advisory-driven ones.
5. **Repository variable `DOPPLER_IDENTITY_ID`**: see Doppler setup above.
6. **Delete the GitHub secrets** the old workflows used once the Doppler path
   has produced one green run: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`,
   `CODECOV_TOKEN`, `SNYK_TOKEN`.

And in this repository: tag releases from `main` (`git tag -a vX.Y.Z <sha>`,
`git push origin vX.Y.Z`). Callers' Dependabot follows the tags; zizmor's
`ref-version-mismatch` audit fails a caller whose `# vX.Y.Z` comment names a
tag that does not exist, which is the intended check that a pin and its
comment agree.

## Developing

```sh
pip install -r requirements-dev.txt
pytest
ruff check tests/ && ruff format --check tests/
actionlint          # https://github.com/rhysd/actionlint
zizmor --offline .  # https://docs.zizmor.sh
```

`tests/test_workflows.py` is the contract: SHA pins with version comments, the
write-permission allow-list, per-job permissions and timeouts, no untrusted
interpolation, every input declared, defaulted, used and documented here, and
that the Doppler fallback secret reaches every fetch. Break any one of those
and CI names the fix.

## Licence

MIT. See `LICENSE`.
