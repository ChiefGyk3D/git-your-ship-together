# git-your-ship-together

> Reusable workflows. Repeatable builds. Less "what the fuck broke?"

One place to fix a pipeline bug or add a scan step, instead of one per
repository. These are the GitHub Actions workflows shared by ChiefGyk3D's
Python projects (Typo Sniper, Stream Daemon, Star Daemon, Boon Tube Daemon, and
whatever comes next).

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

## Calling the workflows

Callers reference `@main`. Pin to a tag or SHA instead if you want a caller
to stop moving with this repository.

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
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@main
    permissions:
      contents: read
      id-token: write
    secrets: inherit
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

Inputs of `python-ci.yml`:

| Input | Default | Meaning |
|---|---|---|
| `python-versions` | `'["3.11", "3.12", "3.13"]'` | JSON array for the test matrix |
| `coverage-python-version` | `3.13` | The matrix leg that uploads coverage |
| `install-command` | upgrade pip, `pip install -r requirements.txt` | Run before tests on every leg |
| `test-command` | `pytest` | The test suite |
| `coverage-file` | `coverage.xml` | Uploaded as an artifact when present |
| `codecov` | `false` | Also upload to Codecov; needs `CODECOV_TOKEN` in the Doppler config |
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
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `30` | Per-job timeout |

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
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-docker-release.yml@main
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
      security-events: write
    secrets: inherit
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
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `60` | Job timeout; native builds on arm64 under QEMU are slow |

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
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/security.yml@main
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      id-token: write
    secrets: inherit
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
| `dependency-review` | `true` | On pull requests only |
| `dependency-review-severity` | `moderate` | Fail the review at this severity or above |
| `snyk` | `false` | Snyk Code and Snyk Open Source; needs `SNYK_TOKEN` in the Doppler config |
| `python-version` | `3.13` | Python for pip-audit and Snyk |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | empty | See [Doppler setup](#doppler-setup) |
| `timeout-minutes` | `30` | Per-job timeout |

## Doppler setup

Doppler is the one rotation point. A CI job authenticates with a token that
lives for the job and is scoped to one repository's identity, and reads one
config that holds only what CI needs.

The composite action `.github/actions/doppler-secrets` tries, in order:

1. **OIDC** when `doppler-identity-id` is set. GitHub mints a JWT for the job
   (`id-token: write`), the action posts it to Doppler's
   `/v3/auth/oidc`, and Doppler returns a short-lived token for the identity's
   Service Account. Nothing static is stored anywhere.
2. **Service Token** when the caller passes the GitHub secret
   `DOPPLER_TOKEN` (via `secrets: inherit`). Read-only, one config. Doppler
   still rotates it, but it is one static credential in GitHub per repository.
   Use it only where OIDC is not available.
3. **Nothing**, with a notice, so a pipeline runs before Doppler is wired up.
   Steps that need a secret then skip (Docker Hub publish, Codecov) or fail
   with a message naming the missing name (Snyk).

A pull request from a fork never fetches anything, whichever path is
configured.

### One-time, per repository

Service Account Identities need a Doppler workplace on the Team or Enterprise
plan. On a Developer plan, use path 2 and skip step 3.

1. **Config.** In the project the daemon already uses at runtime (or a new
   `ci` project), add an environment `ci` with config `ci`. Put in it only what
   the pipelines read:

   | Name | Used by |
   |---|---|
   | `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | release, when `dockerhub: true` |
   | `CODECOV_TOKEN` | CI, when `codecov: true` |
   | `SNYK_TOKEN` | security, when `snyk: true` |
   | `GITLEAKS_LICENSE` | security, organisation accounts only |

   Every value in the config is exported into the job's environment (masked),
   which is why the runtime secrets do not belong here.

2. **Service Account.** Workplace → Team → Service Accounts → create one per
   repository (e.g. `gha-typo-sniper`), grant it *Viewer* on that project's
   `ci` config and nothing else.

3. **Identity.** On the service account, add an Identity of type OIDC:
   - Issuer: `https://token.actions.githubusercontent.com`
   - Subject: `repo:ChiefGyk3D/<repo>:*` (or tighten to
     `repo:ChiefGyk3D/<repo>:ref:refs/heads/main` and
     `repo:ChiefGyk3D/<repo>:ref:refs/tags/*` for release-only access)
   - Audience: leave GitHub's default, `https://github.com/ChiefGyk3D`, which
     is what `dopplerhq/secrets-fetch-action` requests

   Copy the identity's UUID.

4. **Repository variable.** In the GitHub repository, Settings → Secrets and
   variables → Actions → **Variables**, add `DOPPLER_IDENTITY_ID` with the
   UUID. It is an identifier, not a secret: the trust is the OIDC claim match,
   and a variable keeps the caller YAML free of per-repository values.

5. **Delete** `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `CODECOV_TOKEN` and
   `SNYK_TOKEN` from the repository's GitHub secrets once a run has gone green
   through Doppler. `GITHUB_TOKEN` is not a stored secret and stays.

## Developing

```sh
pip install -r requirements-dev.txt
pytest
ruff check tests/ && ruff format --check tests/
actionlint          # https://github.com/rhysd/actionlint
```

`tests/test_workflows.py` is the contract: SHA pins with version comments, the
write-permission allow-list, per-job permissions and timeouts, no untrusted
interpolation, every input declared, defaulted, used and documented here, and
that the Doppler fallback secret reaches every fetch. Break any one of those
and CI names the fix.

## Licence

MIT. See `LICENSE`.
