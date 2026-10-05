# Secrets: Doppler and OIDC

**What this is.** How a CI job here gets a credential it needs (a Docker Hub
token, a Snyk token, a GitHub App key) without that credential living in GitHub.
It is the page most worth reading slowly, because the same idea (a job proves who
it is instead of holding a password) shows up in PyPI Trusted Publishing, cosign
signing, Codecov and build attestations too.

## The model, for someone new to it

The old way: you copy a token into GitHub's "Secrets" page, and every workflow in
that repository can read it. Three problems. You cannot read it back, so you cannot
audit it. You copy it into every repository, so rotating it means finding every
copy. And deleting the GitHub secret does not revoke the token that was in it.

The model here has four parts.

1. **Doppler** holds the secrets. It is a secrets manager the maintainer's
   projects already used at runtime, so it already had an audit log.
2. **No long-lived secret is stored in GitHub.** There is not one GitHub Actions
   secret in a calling repository once it is on this path. `gh secret list` should
   print nothing.
3. **The job proves who it is.** When a job runs, GitHub can mint a short-lived
   signed token for it (OIDC; see the [Glossary](Glossary.md)). The token says,
   in signed claims, which repository the job belongs to and which ref it runs on.
   The job posts it to Doppler.
4. **Doppler answers only if the identity matches.** An *identity* in Doppler is a
   rule: "a token from GitHub's issuer, for this audience, whose subject is exactly
   this repository on this branch, may act as this service account". If the claims
   do not match, Doppler refuses. If they do, it returns a token that lives for the
   job and can read one config.

```
 GitHub job ──(id-token: write)──> GitHub mints a JWT: issuer, audience, subject
     │
     └── posts the JWT to Doppler /v3/auth/oidc
              │
              ├── issuer, audience and subject match an identity? ──no──> refused
              │
              └── yes ──> short-lived token for that service account
                              │
                              └── reads the one config it may read ──> masked env vars
```

Nothing static exists on either side. Doppler's log says which repository
fetched.

## Where it sits in the workflows

The workflows try, in order:

1. **OIDC** when `doppler-identity-id` is set.
2. **A service token** when the caller passes the GitHub secret `DOPPLER_TOKEN`:
   read-only, one config. Doppler still rotates it, but it is one static
   credential in GitHub per repository, which is what the design is trying to end,
   so it is the second choice for a Doppler plan without OIDC identities.
3. **Nothing**, with a notice. A pipeline runs before Doppler is wired up; steps
   that need a secret then skip (Docker Hub publish) or fail naming the missing
   secret (Snyk).

The fetch is gated on a **trusted ref**: a push to the default branch, a tag or a
schedule. A pull request from anywhere and a push to any other branch get a notice
and nothing else. That is `doppler-trusted-refs-only`, on by default in every
workflow. A pull request from a fork never fetches whichever way the input is set,
because GitHub mints no OIDC token for it and the step refuses it regardless.

Why: a pull request runs the code it proposes. A secret in that job is a secret
the proposal can read. `tests/test_doppler_gate.py` runs the decision under bash
for every event and ref shape.

The Doppler steps are copied into each workflow that needs them rather than called
as a shared action, because a reusable workflow cannot name the commit it runs
from; a test holds the copies byte-identical to
[`.github/actions/doppler-secrets`](../../.github/actions/doppler-secrets/action.yml),
which is the source.

## What lives in the `ci` config

One Doppler project `ci` with environment `ci` and config `ci`, separate from every
runtime project. Every caller reads that one config. It holds only what pipelines
read:

| Name | Used by |
|---|---|
| `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` | the container release, when `dockerhub: true` |
| `SNYK_TOKEN` | `security.yml`, when `snyk: true` |

Not in the table: Codecov (the upload authenticates with the coverage job's own
OIDC token, so nothing is stored) and gitleaks (the binary needs no licence; the
old action's `GITLEAKS_LICENSE` is gone, issue #90).

**Every value in a Doppler config is exported into the job's environment.** That is
why the config is its own project: a runtime token placed beside the CI names would
become a CI secret in every job of every repository. The trade is stated plainly:
every CI job holds every CI credential while it runs, including a Docker Hub token
in a repository that never publishes there. The credentials are account-wide at
their providers, so one copy is one place to rotate, and Doppler's log still names
which repository fetched.

`scripts/doppler-ci-set.sh NAME` sets one value, typed with echo off, never on a
command line or in shell history. `--from-file PATH` takes a multi-line value such
as a PEM key.

## Setup, once per workplace and once per repository

Service Account Identities need a Doppler workplace on the Team or Enterprise plan.
On a Developer plan use the service token path and skip the identity steps.

**Once:** create the `ci` project, environment and config, and set the names above
with `doppler-ci-set.sh`.

**Per repository:**

1. **Service account.** Create one per repository (for example `gha-typo-sniper`),
   granted *Viewer* on the `ci` project's `ci` environment and nothing else. Its
   workplace role is empty.
2. **Identity** on that service account, type OIDC:
   - Issuer: `https://token.actions.githubusercontent.com`
   - Audience: GitHub's default, `https://github.com/<owner>`.
   - Subjects: see the next section.
3. **Repository variable** `DOPPLER_IDENTITY_ID` set to the identity's UUID
   (Settings, Secrets and variables, Actions, **Variables**). It is an identifier, not
   a secret: the trust is the claim match, and a variable keeps the caller YAML free
   of per-repository values.
4. **Delete** any old GitHub secrets (`DOCKERHUB_*`, `CODECOV_TOKEN`, `SNYK_TOKEN`)
   once a run has gone green through Doppler. Then rotate the values at the
   provider: moving a token does not change it. `GITHUB_TOKEN` is not a stored
   secret and stays.

`scripts/new-repo.sh` does the GitHub side and prints the Doppler steps.

## The subject forms, including the immutable one

The `sub` claim names the repository and the ref. GitHub can send it in two forms,
and which one a repository sends is its own setting
(`gh api repos/OWNER/REPO/actions/oidc/customization/sub`, field
`use_immutable_subject`):

| Form | Example |
|---|---|
| Plain | `repo:OWNER/REPO:ref:refs/heads/main` |
| Immutable | `repo:OWNER@<owner-id>/REPO@<repo-id>:ref:refs/heads/main` |

The immutable form uses numeric ids, so a rename or a transfer cannot make a
different repository match. Repositories created from mid-2026 send it by
default; older ones send the plain form.

List **both**, each with its tag twin (`:ref:refs/tags/*`), and `master` instead of
`main` where that is the default branch. Listing both means flipping the setting
changes nothing.

**Measured, 2026-10-03:** eight repositories on the immutable default failed every
Doppler fetch with `claim "sub" does not match identity auth config` until the
second form was added; three of them from their first run with Snyk on. The audit
cannot see Doppler's side, so a new repository's first push to `main` is the check.
Doppler accepts several subjects per identity and has no update call: to change
the list, create a new identity, point the repository variable at it, then delete
the old one.

## Why `:pull_request` is excluded, and the one place it is allowed

The identity for the `ci` config must never match
`repo:OWNER/REPO:pull_request`. The workflows already refuse to fetch on a pull
request, and the identity is the second lock on the same door. The broad
`repo:OWNER/REPO:*` works but also matches pull-request tokens, so it would rely on
the workflow-side gate alone.

There is exactly one place that needs the opposite: `project-sync.yml`, whose
caller reacts to `pull_request_target` so that a pull request from a fork reaches
the project board. On that event GitHub's subject is
`repo:OWNER/REPO:pull_request`, and the `ci` identity correctly refuses it.
**Measured 2026-10-05** on the first live callers: every `pull_request_target` run
failed at the Doppler step with the `claim "sub"` error, while `issues`,
`schedule` and `workflow_dispatch` runs worked (issue #93). The same measurement
found the second problem: the board App's private key sat in the shared `ci`
config, so it was in the environment of every job of every repository.

The proposed fix in issue #93, **open as of this writing**, is a separate Doppler
project `projects`, config `prd`, holding exactly one secret
(`PROJECTS_APP_PRIVATE_KEY`), its own service account and identity whose subjects
include the `:pull_request` forms, and a separate repository variable
`PROJECTS_DOPPLER_IDENTITY_ID`. Allowing `:pull_request` there is acceptable
because the job has no checkout, the config holds one key, and the key can only
write a board. The blast radius is stated in the issue: a fork's pull request
event can mint a token that writes items and field values and reads issues and
pull requests in the installed repositories; it cannot read any other secret or
run any code. Until it lands, the README's `ci`-config instructions are what
exist. See [Keeping a project board current](Keeping-a-project-board-current.md).

## The audit gets its own project

The weekly audit's token can read the settings of every repository, and the `ci`
config is read by every caller's pipeline, so the audit's token lives in a separate
Doppler project `audit`, config `prd`, behind its own service account whose
identity is scoped to `main` of this repository only. Issue #89 proposes replacing
the personal access token with a GitHub App so no PAT remains. See
[The baseline and the weekly audit](Baseline-and-the-weekly-audit.md).

## What this refuses to do

- It never stores a long-lived credential in GitHub on the OIDC path.
- It never uses `secrets: inherit`; a caller passes `DOPPLER_TOKEN` by name, and may
  leave it unset.
- It never fetches on a pull request or a branch that is not the default, unless a
  caller sets `doppler-trusted-refs-only: false` (only `project-sync` has a reason).
- It never puts a runtime credential in the `ci` config.
- It never uses a personal access token for a CI credential where a GitHub App can
  do the job (the maintainer's ruling, 2026-10-05).
