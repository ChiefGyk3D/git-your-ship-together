# Why this repository exists, and what it is built on

Nine Python projects, each with six copy-pasted workflow files, and every one
of them slightly different because they were fixed one at a time. Snyk turned
on in one project and never given a token in the one next to it. Four of the
first pins on this repository pointed at tag objects rather than commits, and
GitHub happened to resolve them. And the secrets themselves lived in GitHub's
encrypted store, which is write-only: you can set a value, you cannot read it
back, so nobody could say with confidence which repository held which
credential or when it was last rotated.

This repository is the answer to that. One CI pipeline, one release pipeline,
one security pipeline, each written once and called by every project. A bug
fixed here is fixed everywhere on the next Dependabot bump. And every secret a
pipeline needs lives in exactly one place, Doppler, where it can be listed,
scoped and rotated.

The rest of this document is the what, the why, and the products involved.
The [README](../README.md) is the manual for calling the workflows and
[BASELINE.md](../BASELINE.md) is the list of settings every repository must
meet. Nothing here is a secret; the identifiers, hostnames and tokens that make
a pipeline run are deliberately absent.

## What a push goes through

A push to a calling repository, or a pull request against it, runs three
workflows. Each one is a reusable workflow in this repository, pinned by the
caller to a commit SHA with the version in a comment.

**CI** (`python-ci.yml`) runs ruff on the code, the test suite across a
Python matrix, an optional smoke test that installs the package and runs it,
and a single-architecture container build that is executed once before it is
trusted. Coverage is uploaded to Codecov by a separate job that only ever
touches the report artifact. A final job called `CI green` needs every other
job and fails if any of them failed. Branch protection points at that one job,
so a job added later is covered without editing a rule anywhere.

**Security** (`security.yml`) runs CodeQL, a full-history gitleaks scan,
pip-audit on the requirements, dependency review on pull requests, Snyk on
pushes to the default branch, and the OpenSSF Scorecard on the default branch
only. Results land in the repository's Security tab as SARIF.

**Release** (`python-docker-release.yml`) builds the image for the runner's
architecture, runs it, scans it with Trivy, and only then builds the multi-arch
image and pushes it to GHCR (and to Docker Hub where a project already
publishes there). It then signs the image with cosign, attaches a syft SBOM as
a cosign attestation, and records SLSA build provenance through GitHub's
attestation API. On a pull request it builds and scans and stops; nothing is
pushed, signed or attested from a pull request.

## The threat this is built against

A secret leaving a CI job. A job can leak a secret three ways: through code
that runs beside it (the project's own tests and their dependencies, a pull
request's proposed changes, a compromised third-party action), through a
person with write access, or because the secret is stored somewhere it can be
read back. Each design rule below closes one of those, and the tests in
`tests/test_workflows.py` fail the build if a rule is broken.

**The job that runs the caller's code holds no OIDC token.** The `test` job
executes the repository's own tests and everything they import. A token there
is a token that code can mint. So `test` has `contents: read` and nothing
else, and the Codecov upload happens in a separate `coverage` job that
downloads the report artifact and never sees a pull request.

**Secrets are fetched only on a trusted ref.** A push to the default branch, a
tag, or a schedule. A pull request from anywhere, and a push to any other
branch, gets a notice and nothing. A pull request from a fork never fetches
anything whichever way the input is set, because GitHub mints no OIDC token
for it and the Doppler step refuses it regardless.

**Every third-party action is pinned to a commit SHA.** A tag can be moved; a
SHA cannot. The version rides in a comment so a human can read it and so
zizmor's audit can check that the comment and the pin still agree. Dependabot
moves both together, with a seven-day cooldown so a release cut this morning
is not adopted this afternoon.

**Every write permission is on a list with a reason.** Each workflow starts
from `contents: read`. A job widens only what it needs, and `ALLOWED_WRITES`
in the tests holds every one of those widenings with the reason it exists. A
new write is a review decision, not a side effect of adding a step.

**Nothing from an untrusted context is interpolated into a shell.** A commit
message, a branch name or a pull request title reaches a `run:` block through
`env:`, never through `${{ }}` inside the script. The tests scan every `run:`
block for it.

**Every job starts with harden-runner.** In audit mode by default, which
writes every outbound connection into the job summary. Once a few runs show
what a job actually talks to, a caller can switch to `block` with an
`allowed-endpoints` list. That switch is not forced yet, because an allow-list
written before it is measured is a guess.

**These workflows never reference this repository by branch.** A reusable
workflow cannot know the commit it runs from, so the Doppler steps are inlined
into each workflow rather than referenced as `@main`, and a test holds the
four copies identical to the composite action that is their source. Pointing
at `@main` would have meant a push here changes the callers' pipelines with no
pin, no review and no Dependabot PR.

## Why Doppler, and how it is scoped

GitHub's encrypted secrets are fine for one repository. Across nine they are a
liability: write-only, so nothing can be audited; duplicated, so rotation means
finding every copy; and readable by any workflow in the repository that names
them. And the projects already used Doppler at runtime, so their credentials
already had a home with an audit log.

The CI design keeps the runtime and CI worlds apart on purpose:

- One Doppler project, `ci`, with one config, `ci`, holds every credential
  the pipelines read: the Docker Hub username and token, the Snyk token, and
  nothing else. Every value in that config is exported into every CI job, so
  a runtime token placed there would become a CI secret in nine repositories.
  That is the reason it is its own project and not a config beside `prd`.
  The credentials are account-wide at their providers anyway, so one copy is
  one place to rotate, at the cost that a repository which never publishes
  to Docker Hub still holds the Docker Hub token while its jobs run.
- Each repository gets its own Doppler Service Account, Viewer on that one
  config and nothing else, with an empty workplace role. A token minted for
  it can read that config and cannot list, write or see any other project,
  and Doppler's log names which repository fetched.
- Each Service Account carries one OIDC identity. GitHub mints a JWT for the
  job, the job posts it to Doppler, and Doppler returns a short-lived token for
  that Service Account. The identity checks the token's issuer, its audience
  and its subject, which names the repository. Nothing static is stored on
  either side.
- The identity's UUID goes into a repository variable, not a secret. It is an
  identifier; the trust is the claim match, and a variable keeps the caller
  YAML free of per-repository values.

A Service Token path exists as a fallback for a Doppler plan without OIDC
identities. It is one static credential per repository in GitHub, which is
exactly the thing the design is trying to end, so it is the documented second
choice, and OIDC wins whenever an identity is configured.

Codecov is the one provider that needs no credential at all. Its action
verifies the job's GitHub OIDC token directly, so for a public repository the
token was one more thing to store for no reason, and it is gone.

## The products, and why each one

| Product | Role here | Why this one |
|---|---|---|
| GitHub Actions reusable workflows | The mechanism for "write once, call from nine places" | Native, no runner to host, and `workflow_call` lets a caller pass inputs and exactly the secrets it names. `secrets: inherit` is never used. |
| Doppler | The only store for CI secrets | Already the runtime store for these projects; per-config scoping, an audit log, and Service Account identities that accept GitHub's OIDC token. |
| GitHub OIDC | Job identity | Every job can mint a short-lived JWT naming its repository and ref. Doppler, Codecov, cosign and GitHub's attestation API all accept it, so no long-lived credential has to exist for any of them. |
| step-security harden-runner | Egress audit on every job | The only way to see what a job talks to without instrumenting it; the audit summary is what a `block` allow-list is later written from. |
| ruff | Lint | One fast tool in place of flake8, isort and pyupgrade, with the bandit rules available under the same config. Each project picks its rule set; the check is gating, not advisory. |
| pytest | Tests | The projects already used it. The matrix runs it on every supported Python. |
| Codecov | Coverage over time | Free for public repositories, authenticates over OIDC, and the upload runs in its own job away from the test code. |
| actionlint and zizmor | Lint for the workflows themselves | actionlint catches YAML and expression mistakes; zizmor catches the security ones, including a pin whose version comment no longer matches. Both run on the caller's workflow files, not only on these. |
| CodeQL | Static analysis | GitHub's own, free for public repositories, results in the Security tab. |
| gitleaks | Secret scan of the full history | GitHub's push protection stops a known credential shape at push time; gitleaks is the second net, over history, on every pull request. |
| pip-audit | Known-vulnerable dependencies | Reads the requirements file directly; no account, no token. |
| dependency-review | New vulnerable or badly licensed dependencies in a pull request | GitHub's own; posts a summary on the pull request. |
| Snyk | Open Source and Code scanning | Optional. It needs a token, and it runs only off pull requests so the token is never beside proposed code. |
| OpenSSF Scorecard | An outside opinion of the repository's practices | Runs on the default branch only, publishes with the job's OIDC identity. |
| Trivy | Image vulnerability scan before push | Scans the locally built image for CRITICAL and HIGH findings and uploads them to the Security tab. By default findings are reported, not blocking; a caller sets `trivy-exit-code: 1` to make them fail the release. |
| docker buildx and QEMU | Multi-arch image build | The daemons run on both amd64 and arm64 hosts. |
| GHCR, and Docker Hub | Registries | GHCR authenticates with the job's own `GITHUB_TOKEN`, so it needs nothing stored. Docker Hub is kept only for the projects that already publish there and is the reason the `ci` config holds a registry credential at all. |
| cosign (sigstore) | Image signature, keyless | The signature is bound to the job's OIDC identity and logged in Rekor. No signing key to store, lose or rotate. |
| syft | SBOM | Generated from the built image and attached as a cosign attestation, so the SBOM is bound to the same identity as the signature. |
| GitHub attestations | SLSA build provenance | GitHub's own record of which workflow, at which commit, produced the image. |
| Dependabot | Moves the pins | Bumps action SHAs and their version comments together, and bumps the callers' pin on this repository when a tag is cut. |

## What the tests enforce

`tests/test_workflows.py` is the contract. It fails the build here if any of
the following stops being true: every action is SHA-pinned with a version
comment; no workflow references this repository by branch; no workflow uses
`pull_request_target`; every file starts at `contents: read` and every write
is on the allow-list; every job declares its own permissions, a timeout and
harden-runner as its first step; every checkout refuses to persist
credentials; no `run:` block interpolates an untrusted context; the inlined
Doppler script matches the composite action byte for byte; every Doppler fetch
is gated on the decide step and every decide step feeds the trusted-ref gate;
no job that can run on a pull request holds an OIDC token unless it is listed
with a reason; the job running the caller's tests holds no OIDC token; every
input is declared, defaulted, used and documented in the README; `CI green`
needs every other job; the release signs and attests only after a push; and a
publishing build never reads the Actions cache.

`tests/test_doppler_gate.py` runs the decide script under bash for every event
and ref shape and checks the mode it returns. `tests/test_audit_baseline.py`
feeds `scripts/audit_baseline.py` a passing repository and a broken one per
criterion, so the audit that checks the nine repositories is itself checked.

The structural tests say what a workflow looks like; `fixture/` is what runs
it. This repository's own CI calls `python-ci.yml` and
`python-docker-release.yml` against that project at the pull request's ref,
and `security-self.yml` does the same for `security.yml`, so a change is
exercised on a real project before any caller pins it, and a test holds that
every reusable workflow is called this way. `tests/test_risk_register.py`
keeps `baseline/risk-register.yaml` honest: every entry complete, every date
a date, no review more than 90 days out, no entry expired.

## What it does not do yet

Signed commits and tags are not required, because no signing key exists on the
maintainer's machines today and a rule would only block the maintainer.
harden-runner is not in `block` mode, because each repository's allow-list has
to be measured first. And a pinned allow-list of actions in repository settings
is not set, because everything is already SHA-pinned and the list would
duplicate the pins for the cost of a settings change on every new action.
BASELINE.md carries the same list with the reasoning, and it is the place that
changes when one of them is adopted.

## Using this for your own repositories

Fork it or copy the three workflow files and the tests. The things you will
change: the owner in the OIDC subject and audience, the Doppler project names,
and the Docker Hub and Snyk inputs if you do not use them. Service Account
identities need Doppler's Team plan or above; on a Developer plan use the
Service Token path and accept one static secret per repository. Keep the
tests. They are most of the value, because they are what turns "we pin our
actions" from a habit into a build failure.
