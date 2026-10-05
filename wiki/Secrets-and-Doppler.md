# Secrets and Doppler

How CI gets credentials **without storing them in GitHub**. Full setup steps are in the
README: [Doppler setup](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#doppler-setup).
The reasoning is in
[docs/DESIGN.md](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/docs/DESIGN.md#why-doppler-and-how-it-is-scoped).

## The problem

GitHub's encrypted secrets are fine for one repository. Across many they are:

- **Write-only**: nothing can be audited, you cannot list or read back what a repository holds.
- **Duplicated**: rotating means finding every copy.
- **Readable by any workflow in the repository that names them.**

## The design

```
 GitHub job ──(1) mints OIDC JWT: "I am repo X, ref Y"──▶ Doppler /v3/auth/oidc
                                                              │ checks issuer, audience, subject
 GitHub job ◀──(2) short-lived token for X's Service Account──┘
 GitHub job ──(3) reads the one `ci` config──▶ masked env vars for later steps
```

- **One Doppler project, `ci`, one config, `ci`**, holding only what pipelines read
  (`DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `SNYK_TOKEN`; the Projects App key where used).
  Every value in that config is exported into every CI job, so a *runtime* secret must never
  go there: it would become a CI secret in every repository.
- **One Service Account per repository**, *Viewer* on that one config and nothing else, with an
  empty workplace role. Doppler's log therefore says *which repository* fetched.
- **One OIDC identity per Service Account**, checking issuer
  (`https://token.actions.githubusercontent.com`), audience, and subject (the repository and ref).
- The identity's UUID goes in a repository **variable** (`DOPPLER_IDENTITY_ID`), not a secret.
  It is an identifier; the trust is the claim match.

Codecov needs no stored credential at all: its action verifies the job's OIDC token directly.
PyPI and cosign likewise use OIDC. The weekly audit's token lives in a **separate** Doppler project,
because it can read every repository's settings.

## The three paths, in order

1. **OIDC** when `doppler-identity-id` is set. Nothing static is stored anywhere. *This is the normal path.*
2. **Service Token** when the caller passes the GitHub secret `DOPPLER_TOKEN`. Read-only, one
   config, but one static credential in GitHub per repository. Only for Doppler plans without
   OIDC identities (the Developer plan).
3. **Nothing**, with a notice, so a pipeline runs before Doppler is wired up. Steps needing a secret then
   skip (Docker Hub publish) or fail naming the missing name (Snyk).

## Trusted refs only

A fetch happens only on a **push to the default branch, a tag, or a schedule**. A pull request from
anywhere, and a push to any other branch, gets a notice and nothing. This is
`doppler-trusted-refs-only` (on by default). A fork's pull request never fetches whichever way the
input is set: GitHub mints no OIDC token for it, and the step refuses it regardless.
`tests/test_doppler_gate.py` runs the decision under bash for every event and ref shape.

## Setting it up (summary)

**Once for the workplace** (needs Doppler Team or Enterprise for identities):

1. Create the `ci` project / environment / config.
2. Put only the CI names in it, using the helper (the value is typed twice with echo off and never
   reaches a command line or shell history):
   ```sh
   scripts/doppler-ci-set.sh SNYK_TOKEN
   scripts/doppler-ci-set.sh DOCKERHUB_USERNAME
   scripts/doppler-ci-set.sh DOCKERHUB_TOKEN
   ```

**Per repository:**

1. Create a Service Account (e.g. `gha-<repo>`), *Viewer* on the `ci` config only.
2. Add an OIDC Identity. Issuer as above. **Subject: list both forms, each with its tag twin**:
   - `repo:OWNER/REPO:ref:refs/heads/main` and `repo:OWNER/REPO:ref:refs/tags/*`
   - the *immutable* form `repo:OWNER@<owner-id>/REPO@<repo-id>:ref:refs/heads/main` and its tags twin

   GitHub sends the immutable form from repositories created from mid-2026 and the plain form from
   older ones. Listing both means a flip of the setting changes nothing. The subject must **never**
   match `repo:OWNER/REPO:pull_request`.
3. Copy the identity UUID into the repository variable `DOPPLER_IDENTITY_ID`.
4. After a green run, **delete** the old GitHub secrets (`gh secret list` should print nothing) and
   rotate the values at the provider: *moving a token does not change it.*

The exact commands, plus the audience setting, are in the README section above.

## The trade-off, stated plainly

Every CI job of every repository holds every CI credential while it runs, including a Docker Hub
token in a repository that never publishes there. The credentials are account-wide at their
providers, so one copy is one place to rotate; and who fetched is still in Doppler's log per
repository, through the identities.

## Adapting this for your own repositories

Change the owner in the OIDC subject and audience, the Doppler project names, and the Docker Hub
and Snyk inputs if you do not use them. On a Developer plan use the Service Token path and accept
one static secret per repository. See [Troubleshooting](Troubleshooting) for the common
`claim "sub" does not match identity auth config` failure.
