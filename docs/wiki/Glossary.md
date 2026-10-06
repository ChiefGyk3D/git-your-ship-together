# Glossary

Words that appear across this wiki, in the order a newcomer meets them.

**GitHub Actions.** GitHub's built-in automation. It runs jobs on a machine
GitHub hosts (a **runner**) when an event happens.

**Workflow.** A YAML file under `.github/workflows/`. It names the events it
reacts to and the **jobs** it runs.

**Job and step.** A job is a set of steps run on one runner, in order. A step is
either a shell command (`run:`) or an **action** (`uses:`).

**Action.** A packaged step someone else wrote, such as `actions/checkout`.
Referenced as `owner/name@version`.

**Reusable workflow.** A workflow written to be called by another workflow,
declared with `on: workflow_call`. Like a function: it takes **inputs** and
may take **secrets** and return **outputs**. Every file in
`.github/workflows/` here that has a page named `Workflow-<name>` is one.

**Caller.** The workflow in your repository that calls a reusable workflow
with `uses:` and passes inputs under `with:`.

**Input.** A named value a caller passes under `with:`. Each workflow page lists
them, generated from the YAML.

**Pin.** Naming the exact commit to run, `@<40-hex sha> # v1.12.0`, instead of a
tag or a branch that can move. The comment is for humans and for zizmor, which
checks that it still agrees with the SHA.

**Dependabot.** GitHub's bot that opens pull requests to update dependencies,
including the pins in workflow files.

**Cooldown.** A delay before Dependabot proposes a brand-new release. Here,
seven days, so a release cut this morning is not adopted this afternoon.

**Gate job (`CI green`).** The last job of a CI workflow. It needs every other
job and fails if any failed. Branch protection requires it by name.

**Branch protection.** A repository setting that requires, for the default
branch, things like a pull request and a passing check before merge.

**Ruleset.** A newer repository setting for rules on branches or tags. Here it
makes `v*` tags immutable.

**Concurrency.** A way to make one run cancel or queue behind another for the
same group. It belongs to the caller; a reusable workflow cannot carry it.

**Trusted ref.** A push to the default branch, a tag, or a schedule. Anything
else (a pull request, a push to another branch) is untrusted, and the secret
fetch skips it.

**Fork.** A copy of a repository under another account. A pull request from a
fork gets a read-only token and no secrets, whatever the workflow asks for.

**OIDC (OpenID Connect).** A way for a job to prove who it is. GitHub mints a
short-lived signed token (a **JWT**) naming the repository and the ref. A
service that trusts GitHub checks the signature and the names, and answers. No
password is stored anywhere. See
[Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md).

**JWT.** JSON Web Token: the signed token above. Its `sub` ("subject") claim
says which repository and ref it came from.

**Subject (`sub`).** The claim an OIDC identity matches. It looks like
`repo:OWNER/REPO:ref:refs/heads/main`, or in the **immutable** form
`repo:OWNER@<owner-id>/REPO@<repo-id>:ref:refs/heads/main`, which survives a
rename or transfer.

**Doppler.** The secrets manager every CI secret lives in. A job fetches only on a
trusted ref.

**Service account and identity (Doppler).** A service account is a Doppler
principal with read access to one config. An identity is the rule that says
"a GitHub token with this issuer, audience and subject may act as that
service account".

**Service token.** A static, read-only Doppler credential. The fallback when
OIDC identities are not available. One stored secret per repository, which is
what the design tries to avoid.

**GitHub App.** A bot identity with its own narrow permissions, installed on
an account or organization. Its installation token lives one hour and names the
App in the audit log. Used by `project-sync` instead of a personal token.

**PAT (personal access token).** A token that acts as a person. Avoided for CI
credentials wherever an App can do the job.

**harden-runner.** A StepSecurity action that starts every job. In `audit` it
logs outbound connections; in `block` it refuses any host not on the list.

**Egress.** Outbound network traffic from a job.

**SARIF.** Static Analysis Results Interchange Format. A JSON file of
findings that GitHub imports into the **code scanning** tab (the repository's
Security tab). Each scanner uploads under its own **category**, so alerts do
not overwrite each other.

**SAST, SCA, DAST.** Static analysis of source (CodeQL, Semgrep); software
composition analysis, meaning known-vulnerable dependencies (pip-audit,
dependency review, Snyk Open Source); dynamic analysis against a running
service (not built here yet, issue #97).

**CodeQL, Semgrep, gitleaks, Snyk, Scorecard, Trivy.** The scanners. See
[Security scanning explained](Security-scanning-explained.md).

**SBOM.** Software bill of materials: a list of what is inside an artifact.
The container release attaches an SPDX one; releases of packages do not yet
(issue #99).

**Sigstore, cosign, Rekor.** A system for signing without holding a key.
cosign signs using the job's OIDC identity, and Rekor is the public log that
records it.

**Provenance (SLSA).** A signed statement of which workflow, at which commit,
built an artifact. GitHub stores it as an *artifact attestation*.

**Trusted Publishing.** PyPI accepting a job's OIDC identity for a named
repository, workflow and environment instead of an API token.

**Risk register.** `baseline/risk-register.yaml`: every advisory a pipeline is
told to ignore, with a reason, an owner and a review date at most 90 days
out.

**Baseline.** The settings every repository must meet, in
[BASELINE.md](../../BASELINE.md), and the weekly **audit** that checks them.

**Fixture.** `fixture/`: the smallest project that exercises every job, run by
this repository's own CI against each reusable workflow.

**Dogfooding.** Running your own product on yourself. Here every reusable
workflow is called from `ci.yml` at the pull request's own ref.
