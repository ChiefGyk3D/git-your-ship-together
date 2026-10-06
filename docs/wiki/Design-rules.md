# Design rules

**What this is.** The rules every workflow here follows. Each is a heading with
its reason (the incident or threat) and the test that fails the build if it is
broken. All tests are offline and read only this repository's files. A rule
without a test is not on this list, and each test was broken on purpose once to
confirm it goes red with a message naming the fix. See
[Releases and supply chain](Releases-and-supply-chain.md) for the release rules
and [Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md) for the secret ones.

The tests live in [`tests/`](../../tests): `test_workflows.py` is the main
contract, with `test_hygiene.py`, `test_doppler_gate.py`, `test_security_jobs.py`
and the per-workflow files beside it.

## Doppler is the only store for CI secrets

**Why.** GitHub's encrypted secrets are write-only and duplicated per
repository, so nothing can be audited and rotation means finding every copy.
**Held by.** `test_only_the_doppler_workflows_fetch_secrets` (a workflow that
grows a fetch without joining the list fails) and the audit's `doppler-identity`
and `workflows-pinned` checks. Details in
[Secrets: Doppler and OIDC](Secrets-Doppler-and-OIDC.md).

## Every third-party action is pinned to a commit SHA, with a version comment

**Why.** A tag can be moved, so a tag pin changes what runs with no commit to
show for it. The version in the comment lets a person read the pin and lets
zizmor check that the two still agree. A tag's SHA is not a commit's SHA: an
annotated tag lists twice in `git ls-remote --tags`, and only the `^{}` line is
the commit. Four of this repository's first pins were tag objects. **Held by.**
`test_every_action_is_pinned_to_a_sha_with_a_version_comment`; zizmor on every
caller.

## Permissions are declared per job, and every write is on a list with a reason

**Why.** A grant widened "to make it work" is a gift to anyone who lands code in a
dependency. Each file starts at `contents: read`; a job widens only what it
needs. **Held by.** `test_every_workflow_declares_read_only_top_level_permissions`,
`test_every_reusable_job_declares_its_own_permissions` and
`test_no_job_grants_a_write_that_is_not_on_the_list`, whose `ALLOWED_WRITES` set
records why each write exists. A new write is a review decision, not a side
effect.

## Nothing from an untrusted context is interpolated into a shell

**Why.** A branch name or pull request title inside `${{ }}` in a `run:` block
is injection. Values pass through `env:`, and that includes every command a
caller supplies (`test-command`, `build-command`, and so on): they reach
`bash -eo pipefail -c "$COMMAND"` as data. **Held by.**
`test_no_run_block_interpolates_untrusted_context` and
`test_every_run_block_here_reads_inputs_through_env`.

## Every job has a timeout, and every checkout refuses to persist credentials

**Why.** A hung job burns minutes; a checkout that leaves its token in
`.git/config` hands it to every later step. The one exception is the wiki
publish checkout, which keeps its token on purpose because that is how the push
happens without a credential in a shell variable. **Held by.**
`test_every_job_has_a_timeout` and
`test_every_checkout_refuses_to_persist_credentials` (the exception is a named
set).

## Every job starts with harden-runner

**Why.** It is the only way to see what a job talks to without instrumenting it,
and the audit summary is what a `block` allow-list is later written from. The
input defaults to `audit`; every caller in `baseline/repos.txt` runs `block`
with the measured list each workflow carries. A blocked connection reads
`domain not allowed: <host>`, which is also how a new dependency announces
itself. Measured lessons: the allow-list is one space-separated line, because a
YAML literal block keeps its newlines and matches nothing; wildcards are not
supported and invalidate the whole list; the first block-mode run may log IPs,
not names, so Snyk's list came from documentation and was confirmed by a clean
run rather than measured first. **Held by.**
`test_every_reusable_job_starts_with_harden_runner`,
`test_the_default_allow_list_is_one_line_of_sorted_host_ports`,
`test_workflow_lint_default_allows_its_download_hosts`.

## `disable-sudo: true` unless a job runs the caller's own install command

**Why.** A compromised step should not become root on the runner. The three
exceptions are the jobs that run a caller's install command, which a caller may
legitimately write as `sudo apt-get install ...`. **Held by.**
`test_every_harden_runner_disables_sudo_unless_the_job_needs_it` in
`test_hygiene.py`.

## The job that runs the caller's code holds no OIDC token

**Why.** The `test` job executes the repository's tests and everything they
import. A token there is a token that code can mint. Coverage goes to Codecov
from a separate `coverage` job that only touches the report artifact and never
runs on a pull request. **Held by.**
`test_the_job_running_the_callers_tests_holds_no_oidc_token` and
`test_no_job_that_can_run_on_a_pull_request_holds_an_oidc_token`.

## Secrets are fetched only on a trusted ref

**Why.** A pull request's proposed code would otherwise run in a job that holds a
secret. Only a push to the default branch, a tag or a schedule fetches. A pull
request from a fork never fetches whatever the input says, because GitHub mints
no OIDC token for it and the step refuses it regardless. **Held by.**
`tests/test_doppler_gate.py`, which runs the decide script under bash for every
event and ref shape, and `test_doppler_fetch_steps_are_gated_on_the_decision`.

## A publishing build never reads the Actions cache

**Why.** Anyone who can open a pull request can write to that cache, and a
poisoned layer inside a signed release is the one outcome the signature cannot
undo. Download caches in the CI workflows are still hash-checked on every run,
so a cache can save a download and never lower the bar. **Held by.**
`test_a_publishing_build_never_reads_the_actions_cache` and
`test_every_download_restores_a_cache_first_and_hashes_what_is_on_disk`.

## The workflows never reference this repository by branch

**Why.** A reusable workflow cannot name the commit it runs from, so the Doppler
steps are inlined into each workflow instead of calling the composite action as
`@main`. Pointing at `@main` would let a push here change every caller's
pipeline with no pin, no review and no Dependabot pull request. **Held by.**
`test_reusable_workflows_never_reference_this_repository_by_branch` and
`test_the_inlined_doppler_script_matches_the_composite_action`, which holds the
four copies byte-identical to `.github/actions/doppler-secrets`.

## No `pull_request_target` in the shared workflows

**Why.** That trigger runs with secrets against a pull request's context, and is
dangerous the moment a job checks out and runs the pull request's code. No
shared workflow uses it. The one caller that needs it, `project-sync`, never
checks anything out; see [Keeping a project board current](Keeping-a-project-board-current.md).
**Held by.** `test_no_workflow_uses_pull_request_target`.

## Concurrency belongs to the caller

**Why.** A called workflow's `github.workflow` is the caller's name, so a group
declared inside would cancel the caller itself. **Held by.**
`test_a_reusable_workflow_does_not_declare_concurrency`. The exceptions are
fixed literal groups (`pages`, `wiki`) that queue and never cancel.

## `CI green` needs every other job

**Why.** Branch protection points at one name per language, so a job added later
is covered without editing a rule anywhere. **Held by.**
`test_ci_green_gate_needs_every_other_job` and the audit's required-check
derivation.

## Every reusable workflow is run here before any caller pins it

**Why.** A workflow tested only structurally ships to every caller before anything
runs it. **Held by.**
`test_every_reusable_workflow_is_run_from_this_repository_at_the_pull_requests_ref`:
`ci.yml` calls each one at the pull request's own ref against `fixture/`.

## Every input is declared, defaulted, used and documented

**Why.** An undocumented input is an input nobody sets correctly. **Held by.**
`test_every_input_has_a_description_and_a_default`,
`test_every_declared_input_is_used`, `test_every_input_used_is_declared` and
`test_readme_documents_every_input`. This wiki's input tables are generated from
the same YAML; see [Adopting GYST in your own project](Adopting-GYST-in-your-own-project.md)
for the generator.

## Downloaded tools are pinned by version and sha256

**Why.** shellcheck, shfmt, OpenTofu, tflint, arduino-cli, hadolint and gitleaks
are fetched as binaries, not through actions, so no third-party action joins the
allow-list for them and what lints today is what lints next year. **Held by.**
`test_every_downloaded_tool_is_checked_against_a_pinned_hash`.

## What is not a rule yet

Signed commits and tags are not required: the maintainer's laptop signs with a
registered SSH key and verifies, but cloud sessions and other machines still
commit unsigned, so a rule would only block them. The audit is a weekly report,
not a gate. See [Roadmap](Roadmap.md).
