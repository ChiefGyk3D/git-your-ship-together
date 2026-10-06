# Why GYST exists

**What this is.** A list of the problems that produced this repository, each
with the rule it became and the check that holds the rule. If a rule looks
fussy, find its problem here.

## Why it exists

Nine Python projects each carried six copied workflow files, and every copy
was slightly different because each had been fixed on its own. Snyk was turned
on in one project and never given a token in the one next to it. Four of the
first pins in this repository pointed at tag objects rather than commits; GitHub
happened to resolve them and Dependabot would not have. And the credentials
lived in GitHub's encrypted secrets, which are write-only: you can set a value
and never read it back, so nobody could say which repository held which
credential or when it was last rotated.

The threat all of it is written against is **a secret leaving a CI job**. A
job can leak one three ways: through code that runs beside it (the project's
own tests and their dependencies, a pull request's proposed changes, a
compromised third-party action), through a person with write access, or
because the secret is stored somewhere it can be read back. Every rule below
closes one of those.

## The problems, and what each became

### Copied workflows drift

**Problem.** Six files times nine repositories is fifty-four places a pipeline
bug lives. Fixing it meant fifty-four edits, and some were never made.

**Became.** One reusable workflow per job family, called by every repository
with a pin. See [Getting started](Getting-started.md) for what a caller looks
like and the [workflow pages](Home.md) for each one. A reusable workflow
cannot name the commit it runs from, so the callers pin by commit SHA and
Dependabot moves the pin.

**Held by.** `tests/test_workflows.py` runs every reusable workflow from this
repository's own `ci.yml` against `fixture/`, a small project with one of
everything, so a change is exercised on a real project before any caller pins
it.

### Secrets in GitHub secrets

**Problem.** Write-only storage, duplicated per repository, readable by any
workflow in the repository that names them. Deleting a GitHub secret also does
not revoke the token that was in it.

**Became.** Doppler is the single store, fetched over a short-lived OIDC
identity, and CI holds no long-lived credential. See
[Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md).

**Held by.** `tests/test_doppler_gate.py` and the Doppler tests in
`tests/test_workflows.py`; the audit's `doppler-identity` and
`workflows-pinned` checks on every repository.

### Unpinned actions

**Problem.** A tag can be moved. An action pinned to `v4` runs different code
tomorrow with no commit anywhere to show for it.

**Became.** Every third-party action is pinned to a commit SHA with the
version in a comment; Dependabot moves both together after a seven-day
cooldown so a release cut this morning is not adopted this afternoon. Measured
once and kept: a tag's SHA is not a commit's SHA. `git ls-remote --tags`
lists an annotated tag twice and only the `^{}` line is the commit.

**Held by.** `test_every_action_is_pinned_to_a_sha_with_a_version_comment`,
and zizmor, which fails a caller whose comment and SHA disagree.

### A job that holds a token runs code it should not

**Problem.** The job that runs a project's tests also runs everything the
tests import. A token in that job is a token that code can use.

**Became.** The job that runs the caller's code holds no OIDC token and only
`contents: read`. Coverage is uploaded by a different job that never sees a
pull request. Every workflow page lists which job holds which grant.

**Held by.** `test_the_job_running_the_callers_tests_holds_no_oidc_token` and
`test_no_job_that_can_run_on_a_pull_request_holds_an_oidc_token`.

### Interpolation into a shell

**Problem.** `${{ github.event.pull_request.title }}` inside a `run:` block is
code injection: the title becomes shell.

**Became.** Every value reaches the shell through `env:`, including every
command a caller supplies. A caller's `test-command` is data until `bash`
runs it as the caller intended.

**Held by.** `test_no_run_block_interpolates_untrusted_context`.

### A poisoned cache inside a signed release

**Problem.** Anyone who can open a pull request can write to the Actions
cache. A poisoned layer inside a signed release is the one outcome a signature
cannot undo, because the signature is then valid.

**Became.** A publishing build never reads the Actions cache.

**Held by.** `test_a_publishing_build_never_reads_the_actions_cache`.

### Egress nobody watches

**Problem.** A compromised step that phones home looks like any other step.

**Became.** harden-runner starts every job. It defaults to `audit` (log every
outbound connection) and every calling repository runs `block` with the
measured allow-list each workflow carries. A new dependency announces itself as
`domain not allowed: <host>`. Lesson kept: the allow-list is one
space-separated line; a YAML literal block keeps its newlines and the agent then
matches nothing, including PyPI.

**Held by.** `test_the_default_allow_list_is_one_line_of_sorted_host_ports`.

### CI that passes on your machine

**Problem.** Tests that pass on the author's Python and fail on another, or
pass on Ubuntu and fail on Debian, Kali or arm64.

**Became.** A test matrix over Python versions and runners, and a `distros`
input that runs the suite inside a distribution's own container image
(Debian, Ubuntu, Kali, Parrot) on an Ubuntu runner, natively on arm64 when
asked. A single `CI green` job needs every other job, so branch protection
points at one name per language and a job added later is covered
automatically.

### Settings no YAML can set

**Problem.** Branch protection, Actions policy and secret scanning live in
repository settings. A repository can have perfect workflows and an open
default branch.

**Became.** [BASELINE.md](../../BASELINE.md) lists them and
`scripts/audit_baseline.py` checks every repository weekly. See
[The baseline and the weekly audit](Baseline-and-the-weekly-audit.md).

### Findings that never end

**Problem.** An advisory with no fixed release cannot be fixed, and an
ignore comment in a workflow file is forgotten.

**Became.** The risk register: every ignored advisory has a reason, an
owner and an expiry at most 90 days out, and the audit fails on one that is
unregistered or expired.

## What this does not claim

It does not claim the pipelines are unbreakable. It holds the properties above
with tests, says which are measured and which came from documentation, and
lists what is still open on the [Roadmap](Roadmap.md).
