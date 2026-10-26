# Changelog

Callers pin a commit of this repository, so a change reaches a caller only when it re-pins. Entries here
name what a caller sees after that.

## Unreleased

### EX-0001 widened: `dependency-review` and `python-ci` `test` follow `egress-policy-secretless` (issue #225)

- **Changed.** With `egress-policy-secretless` at its default (`audit`), `security.yml` `dependency-review` and
  `python-ci.yml` `test` now run harden-runner in `audit` on GitHub-hosted runners (the runtime
  `runner.environment == 'github-hosted'` control and, for `test`, the hosted-label rule apply as for the other
  relaxed jobs). Both kept failing at the egress canary on westus2. A caller that sets
  `egress-policy-secretless: block` gets `block` and the canary back for both. `test` also stops using the pip cache
  while it is in `audit`, like the other audit jobs.
- **Deviation, stated.** `dependency-review` holds `pull-requests: write` (the summary comment), which the
  "secretless" definition excluded; the maintainer decided on 2026-10-26 to relax it anyway. The record
  (`docs/security/exceptions/EX-0001-harden-runner-block-westus2.md`, "Widening of 2026-10-26") says what the token
  can do and why that is acceptable. `test` uploads the coverage report that `coverage` sends to Codecov; the
  record explains why that data file is not a privileged output.
- **Unchanged.** Every job with a stored secret, an OIDC token or a publish-capable token (`coverage`, `snyk`,
  `scorecard`, `plan`, `verify`, `verify-release`, the publish, deploy and container jobs, the Doppler jobs) stays in
  `block`, and so do the `build` and `generate` jobs whose output a release or deployment consumes verbatim. The
  expiry (2026-11-07) is unchanged.

### Doppler decide step: only version tags are trusted (issue #209)

- **Changed.** The trusted-ref rule in `doppler-secrets` and every inlined copy (python-ci, tofu-ci, security,
  container-release, project-sync, audit) now treats a tag as trusted only when it is exactly
  `refs/tags/vMAJOR.MINOR.PATCH`. Any other tag name no longer receives secrets, so a caller that fetched on a
  pre-release or free-form tag gets a notice and no secrets until it releases from a `vN.N.N` tag. The default
  branch, schedule, pull request and fork rules are unchanged. This narrows which refs receive secrets; the docs say
  what the Doppler identity must still restrict.
- **Changed (round 2).** A refused tag now fails a job that asked for a secret-backed feature instead of skipping it.
  The decide step has a new output, `untrusted-tag` (also exposed by `doppler-secrets`), true when the ref is a tag
  that is not `vMAJOR.MINOR.PATCH`. `security.yml` with `snyk: true` and `container-release.yml` with `push: true` and
  `dockerhub: true` then fail with an error naming the ref, where they used to warn and stay green. GHCR-only releases,
  the default branch, schedules, pull requests and forks are unchanged. A caller that triggers those jobs on a loose
  tag pattern (`v*`) and cuts a pre-release such as `v1.2.3-rc.1` now sees a red job; to opt out, do not trigger the
  Doppler-backed jobs on such tags. The decide step also resets `nocasematch` and `nocaseglob`, so an inherited
  `BASHOPTS` cannot make `V1.2.3` look like a release tag.
- **Docs (round 3).** The docs now say what the decide step does about events: any event other than a pull request
  event fetches on the default branch or a release-shaped tag (issues, issue_comment, workflow_run and
  repository_dispatch included), and a caller that holds fetched secrets on such events must not process their data
  unsafely. Narrowing the events is #219; the tests pin the current behavior. In `container-release.yml` the
  refused-tag guard sits in the `merge` job, so the run fails after per-architecture images were pushed to GHCR; no
  index and no Docker Hub image is published.
- **Docs.** The fork claim is now exact: a `pull_request` from a fork never fetches; `pull_request_target` with
  `doppler-trusted-refs-only: false` does, and the test now pins that.

### New workflow: `lory-audit.yml` (issue #202)

- **Added.** An optional reusable workflow that asks Lory (Lorikeet Security's AI pentester) for a deep-dive audit
  through its documented pipeline scan API. For scheduled and on-demand use (a monthly cron and
  `workflow_dispatch`), not a per-pull-request gate; the caller template is `examples/lory-audit-caller.yml`.
  Advisory by default (`fail-on-findings: false`); a failed, timed-out, oversize or malformed call, or a missing or
  non-integer `exit_code`, always fails the job. `contents: read` only; the `LORY_PIPELINE_TOKEN` secret reaches one
  step and curl reads it from standard input. Findings are not copied into GitHub: the body is never
  logged, never uploaded and deleted as soon as the judging step ends; the summary shows only `exit_code` and a
  timestamp, and the findings are read in the vendor portal. The response lives in a private `mktemp -d` directory
  (0700, files 0600) handed to the next step through a step output, and the token is removed from the environment
  before any child process starts. Only an HTTP status of exactly 200 is accepted
  (redirects are not followed), curl runs with `--disable` and without proxy variables, and the egress allow-list
  is fixed in the workflow (no `allowed-endpoints` input). The first real run is a spike: the response schema beyond
  `exit_code`, deep-audit support for a non-pull-request target and the rate limits are unknown.
- **Tests.** `tests/test_lory_audit.py` runs both shell scripts as shipped against a stub `curl`. This workflow is not
  dogfooded by `ci.yml` (it needs a vendor token and calls a third party); `test_workflows.py` records that in
  `NOT_DOGFOODED`.

### v1.25.1: the egress canary runs only on Linux (issue #196)

- **Fix.** The EX-0001 egress canary used `timeout` and `getent`, which macOS lacks (and `getent` is missing
  in Git Bash on Windows), so a macOS matrix leg failed with the misleading "known westus2 DNS issue"
  message. Every inlined copy now has `runner.os == 'Linux' &&` in its `if`, so the step is skipped on macOS
  and Windows runners. The canary is a diagnostic for harden-runner `block` on Linux, so no control is
  weakened. Callers re-pin to pick it up. `tests/test_egress_canary.py` fails if a canary lacks the condition.

### Security exception EX-0001: harden-runner `block` on westus2 runners

GitHub-hosted runners in the Azure region `westus2` break harden-runner in `block` mode (about 6 percent of
jobs hang or fail; see the README section "Known CI platform issue: westus2 (EX-0001)" and
`docs/security/exceptions/EX-0001-harden-runner-block-westus2.md`). Upstream has no fix date.

- **New input `egress-policy-secretless`** (exactly `audit` or `block`, default `audit`) on `python-ci`,
  `bash-ci`, `tofu-ci`, `arduino-ci`, `security`, `dast`, `python-fuzz`, `threat-model`,
  `python-docker-release`, `container-release`, `python-package-release` and `verify-published`. It
  governs only the jobs that hold no stored secret, no OIDC token and no write-scoped or publish-capable
  token, that pass no token beyond the default, and whose output no privileged job consumes. Every job still
  has the read-scoped default job token. `egress-policy` keeps governing every other job, and its default
  does not change. **Behavior change:** a caller that passes `egress-policy: block` and nothing else now gets
  `audit` on the secretless jobs until it also passes `egress-policy-secretless: block`. The exception
  expires 2026-11-07 at the latest. `python-ci`'s `test`, `dast`'s `scan`, and `docs-pages` and
  `wiki-publish` jobs in full stay under `egress-policy`, because a privileged job consumes their output.
- **GitHub-hosted runners only, decided at run time.** A secretless job is `audit` only when the policy input
  equals `audit` and GitHub's `runner.environment` is `github-hosted`; a self-hosted runner (whatever
  label it carries) runs in `block`. Where a caller chooses the runner label (`runner`, `runners`,
  `distro-runners`: `bash-ci` `test` and `distro`, `python-ci` `distro`, `python-fuzz` `fuzz`), the label
  must also match a standard GitHub-hosted label (case-insensitively, like all GitHub string comparison).
- **No cache in an audit job.** The pip cache (`python-ci`, `python-fuzz`, `docs-pages`), the buildx `gha`
  cache (`python-ci` `docker`, `container-release` non-publishing build) and the Arduino package cache are on
  only when the job's own effective policy is `block`, so code running in an audit job cannot poison a cache a
  block-mode job restores. Audit-mode jobs install without the cache and run a little slower. Hash-verified
  tool caches are unchanged.
- **Exact policy check.** A policy input that is not exactly `audit` or `block` fails the job in its first
  step, before harden-runner, with a fixed message that names the input and the length of its value. The
  effective-policy expressions use GitHub's case-insensitive `==`, so the check, not the expression, is the exact
  control. Before, harden-runner rejected such a value or treated it its own way.
- **Egress canary.** Every job that can run in `block` now has a step that fails in seconds with "egress
  broken on this runner (known westus2 DNS issue, EX-0001): rerun the job" when any address of `github.com`,
  `api.github.com` or the Actions results receiver is unreachable (four tries, a second apart), under an
  internal 90 second deadline, and prints diagnostics for a support ticket. It runs only in `block` and reads
  no secret. The block jobs' allow-lists gain `results-receiver.actions.githubusercontent.com:443` (and
  `github.com:443` / `api.github.com:443` where a list lacked them: the two `distro` jobs, `project-sync`).
- **Lower default `timeout-minutes`.** Callers that rely on the old defaults must pass the input.
  `python-ci` 30 to 15, `bash-ci` 15 to 10, `tofu-ci` 20 to 16, `security` 30 to 15, `docs-pages` 30 to 10,
  `wiki-publish` 30 to 10. Each new value is at least three times the slowest healthy p99 measured for that
  workflow (`tofu-ci`: its `test` job, p99 305 s, so 16 minutes rather than 10).
- **harden-runner pinned at v2.22.2** (`dc2769abcc0fcfbadfc1df54081c1608579ef6b2`) everywhere. This is
  hygiene, not the fix: the experiment behind EX-0001 shows v2.22.2 breaks the same way on westus2.
