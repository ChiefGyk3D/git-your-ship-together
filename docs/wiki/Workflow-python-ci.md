# python-ci

**What it does.** The CI for a Python project: lint, an optional type check, workflow lint, the
test suite across a matrix of Python versions and runners, an optional run of the tests inside other
distributions' container images, a coverage upload, an optional CLI smoke test, a single-architecture
container build that is run before it is trusted, and two optional pull-request checks. The last job,
**`CI green`**, needs every other job and fails if any failed, so branch protection requires one name.

**Why it exists.** Nine projects each kept their own copy, and every copy had been fixed on its own. The
rules that shaped it: the job that runs your tests must not be able to mint a token; coverage must not run
beside proposed code; and "passes on my machine" is not a result, so the matrix and the distribution images
exist. See [Why GYST exists](Why-GYST-exists.md).

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `lint` | `contents: read` | Runs your `lint-command` |
| `typecheck` | `contents: read` | Only when `typecheck-command` is set; part of the gate |
| `workflow-lint` | `contents: read` | actionlint and zizmor over *your* `.github/workflows`; turn off on one job when another already runs it |
| `test` | `contents: read`, **no OIDC token** | Runs your tests and everything they import. It never holds a token, because that code could mint one |
| `distro` | `contents: read` | Only when `distros` is non-empty. Runs your install and test commands as root in a throwaway container of a distribution's official image, under its own egress list. The container shares the job's network namespace, so the egress block still applies |
| `coverage` | `contents: read`, `id-token: write` | Downloads the report artifact and uploads to Codecov over OIDC. Never runs on a pull request, so nothing your tests execute ever runs beside a token. Coverage therefore appears per push to the default branch, not per pull request |
| `smoke` | `contents: read` | Installs the project and runs `smoke-command` |
| `docker` | `contents: read` | Builds the image for one platform, never pushes, runs `docker-test-command` against it |
| `fragment-check`, `commit-claims` | `contents: read` | Pull requests only; see below |
| `ci-green` | none | `if: always()`; fails if any needed job failed or was cancelled, passes on success or a deliberate skip |

## A minimal caller

```yaml
jobs:
  ci:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      id-token: write   # the coverage job declares it; without this the run is a startup_failure with no check
    with:
      python-versions: '["3.12", "3.13"]'   # omit it to test every supported CPython (see below)
      test-command: pytest --cov=src --cov-report=xml
      egress-policy: block
```

**Which Pythons the default tests.** The default `python-versions` is every CPython still in security support: 3.11 to 3.15
as of 2026-10-30, each with its end date in `.github/python-support.json` (3.11 to 2027-10-31, 3.12 to 2028-10-31, 3.13 to
2029-10-31, 3.14 to 2030-10-31, 3.15 to 2031-10-31, from the [devguide](https://devguide.python.org/versions/)). Each
version is one `Test` job per runner, so the default is five jobs on one runner and ten on two. A caller that must keep
supporting an older Python lists it in `python-versions`; nothing here stops it. `tests/test_python_support.py` fails when a
listed version is past its end date, so the default shrinks on schedule, and it holds every workflow default and the README
equal to the file. The tool locks behind `security.yml` and `agent-scan.yml` stop at 3.14: some locked packages publish
no 3.15 wheel yet.

Point branch protection at `ci / CI green`. A repository with more than one language calls one CI workflow per language
from one job each and requires each gate (`ci / CI green` and `shell / CI green`, say).

**The grant that fails silently.** GitHub validates a called workflow's declared permissions at startup, before any `if`. A
caller that pins `permissions: contents: read` makes the coverage job's `id-token: write` impossible, and the run ends
`startup_failure` with **no check run at all**. Nothing is red; the required check never appears. Measured on two callers
on 2026-10-03, which then merged without a gate (issue #74, closed: the [Troubleshooting](Troubleshooting.md) page now has the
row, and a test checks that the example grants every permission the workflow declares).

## Notes from measured trouble

- **Kali and Parrot are pinned.** `kalilinux/kali-rolling` and `parrotsec/core` use redirectors that answer each
  request with a different mirror, which a block list cannot follow. The default `distro-setup-command` rewrites
  Kali's sources to `kali.download` and Parrot's to `deb.parrot.sh/direct/parrot`, each one name.
- **Fedora is not on the list.** `dnf` takes its mirror from a metalink answer that varies per run, so a caller testing
  `fedora:*` sets `distro-egress-policy: audit` or adds the mirrors it observed. The `distro` lists were measured in
  block mode on Debian 12 and 13, Ubuntu 24.04, Kali and Parrot, both runners.
- **Distribution coverage:** Ubuntu, Xubuntu, Kubuntu and Pop!_OS are covered by `ubuntu:24.04` (same userland);
  Raspberry Pi OS by `debian:12` or `debian:13` with `ubuntu-24.04-arm` (same userland, same architecture, not a Pi);
  Qubes has no userland of its own, so `debian:13` and `fedora:42` cover its templates.
- **Pull-request checks.** `fragment-check-command` and `commit-claims-command` run your own scripts on pull requests,
  with full history and the base branch and head commit as environment variables. They exist for repositories whose
  changelog is one file per change and whose commit messages make claims a diff can check ("adds a test"). Neither is
  worth turning on without a script of your own.
- **Workflow lint under `block`** needs `registry.npmjs.org` for actionlint, so the default list carries it; before that
  it was an entry every caller added by hand (issue #65).

<!-- inputs -->

## What it refuses to do

It never gives the test job a token, never uploads coverage from a pull request, never pushes the image it builds, and never
lets a failed job leave `CI green` passing.
