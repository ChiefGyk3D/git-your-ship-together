# Design Rules and Why

The whole design is built against one threat: **a secret leaving a CI job.**

A job can leak a secret three ways:

1. **Code that runs beside it**: the project's own tests and their dependencies,
   a pull request's proposed changes, a compromised third-party action.
2. **A person with write access.**
3. **Being stored somewhere it can be read back.**

Every rule below closes one of those. Each rule is also a **test**, so breaking
it fails the build rather than relying on anyone remembering. (The full prose
version is
[docs/DESIGN.md](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/docs/DESIGN.md).)

## The rules

### Doppler is the single source of truth for secrets
*Closes: stored somewhere it can be read back.*

GitHub's encrypted secrets are write-only, so you cannot list them, check when
they were rotated, or tell which repository holds which. Across many repositories
they are duplicated, so rotation means finding every copy. Doppler can be
listed, scoped and rotated, and has an audit log. See
[Secrets and Doppler](Secrets-and-Doppler).

### Authenticate with OIDC, not a stored password
*Closes: stored somewhere it can be read back.*

The job proves who it is with a token GitHub mints for it. Doppler turns that into
a short-lived credential. Nothing static exists on either side to steal.

### Secrets are fetched only on a trusted ref
*Closes: code that runs beside it.*

Only a push to the default branch, a tag, or a schedule fetches. A pull request
gets a notice and nothing. A fork's pull request never fetches, because GitHub
mints no OIDC token for it. The Doppler identity's subject is also written so it
cannot match a pull-request token: the workflow gate and the identity are two
locks on the same door.

### The job that runs the caller's code holds no OIDC token
*Closes: code that runs beside it.*

`python-ci.yml`'s `test` job executes the project's tests and everything they
import. A token there is a token that code can mint. So `test` has
`contents: read` and nothing else, and the Codecov upload runs in a separate
`coverage` job that downloads the report artifact and never runs on a pull
request.

### Every third-party action is pinned to a commit SHA
*Closes: code that runs beside it.*

A tag can be moved. A commit cannot. The version rides in a trailing comment so
humans and zizmor can check the two agree. Dependabot moves both together, after
a seven-day cooldown.

### Every write permission is on a list, with a reason
*Closes: code that runs beside it; a person making a careless change.*

Each workflow starts from `contents: read`. A job widens only what it needs, and
`ALLOWED_WRITES` in the tests records every widening with why. A new write is a
review decision, not a side effect of adding a step.

### Nothing from an untrusted context is interpolated into a shell
*Closes: code that runs beside it.*

A commit message, branch name or PR title reaches a `run:` block through `env:`,
never through `${{ }}` inside the script. That includes every command a caller
supplies. The tests scan every `run:` block.

### Every job starts with harden-runner
*Closes: code that runs beside it (limits what it can reach).*

Audit mode logs every outbound connection; block mode refuses anything not on the
allow-list. Every adopted repository runs `block` with a *measured* list. A new
dependency shows up as a `domain not allowed` line. See [Egress Control](Egress-Control).

### Every job has a timeout; every checkout refuses to persist credentials
*Closes: runaway jobs; token left in git config.*

Cheap, mechanical, and the kind of thing that is forgotten without a test.

### A publishing build never reads the Actions cache
*Closes: code that runs beside it.*

Anyone who can open a pull request can write to the Actions cache. A poisoned
layer inside a *signed* release is the one outcome a signature cannot undo, so
publishing builds cache nothing. Downloaded tools elsewhere are cached **and**
still hash-checked on every run, so the cache can save a download but never lower
the bar.

### Signing and attestation happen only after a push, never from a pull request
*Closes: forged provenance.*

A pull request builds, tests and scans, and stops. A test holds that order.

### Required review count is zero (on single-maintainer repositories)
*Closes: the habit of overriding.*

GitHub does not let an author approve their own PR. A count of one on a repository
where one person has write access only blocks the merge until the owner overrides
it as admin, and that teaches overriding. Zero keeps the PR and the green check
required, and lets a Dependabot bump merge itself. See
[Repository Baseline](Repository-Baseline).

### The workflows never reference this repository by branch
*Closes: an unreviewed change reaching every caller.*

A reusable workflow cannot know which commit it was loaded from. If a workflow
used `uses: ChiefGyk3D/git-your-ship-together/.github/actions/...@main`, a push
here would change every caller's pipeline with no pin, no review and no
Dependabot PR. So the Doppler steps are **inlined** into each workflow, and a test
holds all the copies byte-identical to
`.github/actions/doppler-secrets/action.yml`, which is their source.

### Concurrency belongs to the caller
A called workflow's `github.workflow` is the *caller's* name, so a concurrency
group declared inside a reusable workflow would cancel the caller itself. The
caller sets it: a newer push cancels an older pull-request run, but a run on the
default branch or a tag is never cancelled halfway.

### `secrets: inherit` is never used
A caller passes `DOPPLER_TOKEN` by name, so a called workflow can see only the one
secret it declares (and it may be unset: OIDC is the normal path).

## Why these products

The full "why this one" table is in
[docs/DESIGN.md](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/docs/DESIGN.md#the-products-and-why-each-one).
In short:

| Need | Choice | Reason |
|---|---|---|
| Write once, call from many | GitHub Actions reusable workflows | Native; no runner to host; callers name exactly the secrets they pass |
| Secret store | Doppler | Already the runtime store; scoped configs, audit log, OIDC identities |
| Job identity | GitHub OIDC | Accepted by Doppler, Codecov, cosign, PyPI and GitHub attestations: no long-lived credential anywhere |
| Egress control | harden-runner | The only way to see what a job talks to without instrumenting it |
| Signing | cosign keyless | No key to store, lose or rotate; bound to the workflow identity |
| Linting workflows | actionlint + zizmor | One catches mistakes, the other catches security mistakes |

## What it deliberately does not do yet

- **Signed commits and tags are not required.** Some machines that commit here
  still commit unsigned, so a rule today would block them. The item is tracked in
  BASELINE.md and the roadmap.
