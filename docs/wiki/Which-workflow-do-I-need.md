# Which workflow do I need?

Every reusable workflow at a glance. Use this page to decide *which* to call. Each
workflow's own page explains how it works and carries its inputs table, generated from
the workflow's YAML so it cannot drift; the README is the authority.

## Which one do I need?

| My repository has... | Call | Page |
|---|---|---|
| Python code | `python-ci.yml` | [python-ci](Workflow-python-ci.md) |
| Shell scripts (almost every repo does) | `bash-ci.yml` | [bash-ci](Workflow-bash-ci.md) |
| OpenTofu / Terraform | `tofu-ci.yml` | [tofu-ci](Workflow-tofu-ci.md) |
| Arduino / ESP32 firmware | `arduino-ci.yml` | [arduino-ci](Workflow-arduino-ci.md) |
| Atheris fuzz targets (or wants Scorecard's Fuzzing credit) | `python-fuzz.yml` | [python-fuzz](Workflow-python-fuzz.md) |
| A Dockerfile to publish | `container-release.yml` | [container-release](Workflow-container-release.md) |
| A published image you want checked from outside | `verify-published.yml` | [verify-published](Workflow-verify-published.md) |
| A package for PyPI | `python-package-release.yml` | [python-package-release](Workflow-python-package-release.md) |
| Files to publish (`.deb`, firmware, bundles) | `artifact-release.yml` | [artifact-release](Workflow-artifact-release.md) |
| Anything (security scanning) | `security.yml` | [security](Workflow-security.md) |
| A service that serves HTTP (a dashboard, an API; passive, active, by API definition or signed in) | `dast.yml` | [dast](Workflow-dast.md) |
| Dependabot | `dependabot-auto-merge.yml` | [dependabot-auto-merge](Workflow-dependabot-auto-merge.md) |
| A GitHub Projects v2 board (organization) | `project-sync.yml` | [project-sync](Workflow-project-sync.md) |
| A static docs site | `docs-pages.yml` | [docs-pages](Workflow-docs-pages.md) |
| A wiki generated from docs | `wiki-publish.yml` | [wiki-publish](Workflow-wiki-publish.md) |

A repository with several languages calls **one CI workflow per language**, each
from its own caller job, and requires every gate. See
[Getting started](Getting-started.md).

## At a glance

| Workflow | Holds a write token? | Needs Doppler? | Runs on a PR? | Publishes? |
|---|---|---|---|---|
| `python-ci.yml` | No (the `coverage` job has `id-token`, off PRs) | Optional (Codecov uses OIDC directly) | Yes | No |
| `bash-ci.yml` | No | No | Yes | No |
| `tofu-ci.yml` | `plan` job has `id-token`, default branch only | For the plan's credentials | Yes (no plan) | No, nothing applies |
| `arduino-ci.yml` | No | No | Yes | No (binaries kept as an artifact) |
| `python-fuzz.yml` | No | No | Yes | No |
| `container-release.yml` | Yes, after a push only | Docker Hub credentials, if used | Builds and scans only | GHCR (and Docker Hub) |
| `verify-published.yml` | No (`packages: read`) | No | n/a (scheduled) | No |
| `python-package-release.yml` | Yes, publish jobs only | No (Trusted Publishing) | Builds and checks only | PyPI and GitHub release |
| `artifact-release.yml` | Yes, publish job only | No | Builds and checks only | GitHub release |
| `security.yml` | `security-events`, plus `id-token` for Snyk and Scorecard | For `SNYK_TOKEN` | Yes (no Snyk, no secrets) | SARIF to the Security tab |
| `dast.yml` | `security-events` on the upload job only; the job that runs your service holds `contents: read` | No | Yes (not the upload, from a fork) | SARIF to the Security tab |
| `dependabot-auto-merge.yml` | `contents`/`pull-requests` write; checks nothing out | No | Dependabot PRs | Merges |
| `project-sync.yml` | App token via Doppler; checks nothing out | Yes (the App's key) | `pull_request_target` | Board updates |
| `docs-pages.yml` | `pages`/`id-token` on the deploy job only | No | Builds only | GitHub Pages |
| `wiki-publish.yml` | `contents: write` on the publish job only | No | Generates only | The wiki |

(The README's input tables are authoritative for defaults; this table is the
shape, not the contract.)

## Common building blocks

Every workflow shares these inputs (exact defaults vary slightly by workflow; read
the README table):

| Input | What it does |
|---|---|
| `egress-policy` | `audit` logs outbound connections; `block` refuses anything off the list |
| `allowed-endpoints` | The measured allow-list for `block`: one line of space-separated `host:port` |
| `extra-allowed-endpoints` | Hosts only *your* repository reaches, appended to the list |
| `timeout-minutes` | Per-job timeout |
| `doppler-project`, `doppler-config`, `doppler-identity-id` | Secret fetch (where the workflow fetches any) |
| `doppler-trusted-refs-only` | Fetch only on trusted refs (default `true`; leave it) |
| `workflow-lint` / `zizmor-persona` | Lint the caller's own workflow files |

## The old name

`python-docker-release.yml` is the old name of `container-release.yml`. It is a thin
caller that forwards every input, the secret and the outputs, held identical by a
test, so existing pins keep working. New callers use `container-release.yml`.
