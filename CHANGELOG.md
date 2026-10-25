# Changelog

Callers pin a commit of this repository, so a change reaches a caller only when it re-pins. Entries here
name what a caller sees after that.

## Unreleased

### New workflow: `lory-audit.yml` (issue #202)

- **Added.** An optional reusable workflow that asks Lory (Lorikeet Security's AI pentester) for a deep-dive audit
  through its documented pipeline scan API. For scheduled and on-demand use (a monthly cron and
  `workflow_dispatch`), not a per-pull-request gate; the caller template is `examples/lory-audit-caller.yml`.
  Advisory by default (`fail-on-findings: false`); a failed, timed-out, oversize or malformed call, or a missing or
  non-integer `exit_code`, always fails the job. `contents: read` only; the `LORY_PIPELINE_TOKEN` secret reaches one
  step and curl reads it from standard input. The first real run is a spike: the response schema beyond
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
