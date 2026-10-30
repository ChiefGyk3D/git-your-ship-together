# Changelog

Callers pin a commit of this repository, so a change reaches a caller only when it re-pins. Entries here
name what a caller sees after that.

## Unreleased

### New: `agent-scan.yml`, optional advisory scans of agent skills and MCP tool definitions (issue #234)

- **Added.** A reusable workflow that runs two static scanners from Cisco AI Defense: `cisco-ai-skill-scanner` over the skill
  directories or entry files a caller names (`skill-paths`) and `cisco-ai-mcp-scanner` in `static` mode over MCP `tools/list`
  JSON files (`mcp-tool-files`). Each scan is off until its paths are given. Findings are advisory (job summary and SARIF in code
  scanning, the job stays green) until the caller sets `fail-on-severity`, which the workflow applies to the severities in the
  parsed reports (both scanners exit 0 on a critical finding, and no exit code is read as a finding; the skill scanner must
  exit 0, so a crash that left a partial report uploads nothing). The MCP scanner reports at most HIGH. Outputs: `skill-findings`, `skill-max-severity`,
  `mcp-findings`, `mcp-max-severity`.
- **Static engines only.** No LLM engine, no cloud engine, no VirusTotal, no AI Defense API, no API key, no secret. The scanners
  run from an empty directory with an environment the script builds (no token, no repository `.env`); the MCP scanner is told
  not to fetch its price list, so under `egress-policy: block` they reach nothing. The default allow-list is the checkout and the
  pip install (`api.github.com`, `files.pythonhosted.org`, `github.com`, `pypi.org`).
- **Supply chain.** Both scanners are installed from hash locks inside the workflow, `--require-hashes --no-deps
  --only-binary=:all:`: `.github/requirements/cisco-ai-skill-scanner.{in,txt}` and `cisco-ai-mcp-scanner.{in,txt}`, written by
  `scripts/tool_locks.py`, which now carries a workflow and an oldest Python per tool. Dependabot bumps them with the other locks.
- **Fails closed on what it could not scan.** A path outside the repository, a pattern that matches nothing, a file that is not a
  non-empty `{"tools": [...]}` list, two tools with the same name, a scanner that crashed, an MCP result set that is not exactly
  one result per requested tool, or a severity the script does not know fails the job and uploads no report, so a partial scan never closes the alerts of the last good run.
- **Egress and patterns.** The scan jobs run third-party code beside the checkout, so `egress-policy` defaults to `block`
  (checkout and PyPI hosts); `audit` opts out. Patterns are expanded by a bounded walk (entries, depth, matched bytes) that never
  enters a symlinked directory.
- **Jobs.** `skill-scan` and `mcp-scan` hold `contents: read` and follow `egress-policy` (their SARIF is uploaded verbatim by
  another job); `skill-upload` and `mcp-upload` hold `security-events: write`, check nothing out and follow
  `egress-policy-secretless`. A caller grants `security-events: write` even with `upload-sarif: false`.
- **Nothing changes for an existing caller.** No existing workflow changed; a caller opts in by pinning a commit that has the new file.
  Docs: [agent-scan](docs/wiki/Workflow-agent-scan.md), `examples/agent-scan-caller.yml`. Tests: `tests/test_agent_scan.py`,
  `tests/test_tool_locks.py`; CI runs the workflow on `fixture/agent-scan`, a planted skill and tool list included, and fails
  unless the scanners fire on them.
- **Licence.** Both are Apache-2.0 on PyPI. The skill scanner's `LICENSE` file is the licence header only (653 bytes) and its
  metadata says Apache-2.0, which is why GitHub shows NOASSERTION; the MCP scanner ships the full text.

### Distro legs: a Kali mirror caught mid-sync no longer reddens the gate (issue #228)

- **Fixed.** The default `distro-setup-command` of `bash-ci.yml` and `python-ci.yml` retried `apt-get update` three times, 15 s apart,
  which is shorter than Kali's mirror takes to settle ("File has unexpected size ... Mirror sync in progress?" for hours). It now tries
  six times with a pause of 20, 40, then 60 s, clears `/var/lib/apt/lists/*` between tries so a partial index is not reused, and after
  the sixth failure exits non-zero with apt's error and an `apt-get still failing after 6 attempts` line. A healthy mirror takes the
  same single pass as before. The leg is not advisory and no egress endpoint was added. A caller with its own `distro-setup-command`
  is unchanged. Tests: `tests/test_distro_apt_retry.py`.

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

### New: `wait-ci` watcher, script and composite action (issue #223)

- **Added.** `scripts/wait-ci.sh` and `.github/actions/wait-ci`: one tested CI watcher for monitors and merge scripts, in
  place of hand-written `mergeStateStatus` loops. It pins the head SHA at the start and checks only that commit; green needs
  the named required check (`CI green` by default, matched exactly) to have reported and succeeded on that SHA, at least N check
  runs complete, and none failed or cancelled. No check runs, or a required context that has not reported yet, is not green.
  A moved head exits 4 (or, with `--on-push reset`, re-pins; the total timeout keeps running). `--merge` squash-merges with
  `--match-head-commit` and retries a policy block a bounded number of times. A required name counts only from the expected GitHub App (`--app-id`, default Actions; `--any-app` opts out), and an explicit `--sha` is never replaced by a head move. Check run names reach bash base64-encoded, and a name with a control character is red, never green. Only a policy block is retried; a merge gh accepts but leaves queued is exit 5, not merged. Numeric options are plain bounded integers (exit 64 otherwise, no 64-bit wraparound or octal surprises), the check-run list must be whole (GitHub's 1000 cap is on check suites, so the suite count is read once per poll and 1000 or more, or an unreadable count, is never green; a check-runs `total_count` larger than the runs seen, or 1000 or more, is never green either) and every run must carry the pinned `head_sha`. A read must hold still: pages are requested one by one (at most twelve), every page must report the same `total_count`, no run id may repeat, the distinct ids must equal `total_count`, the suite count is read before and after the run pages and must be equal, readable and under 1000, and a read that looks green is repeated and must show the same (id, status, conclusion) set; this costs extra API calls per poll (two suite calls plus one per page, doubled when a read looks green). A merge is reported only when merged and head.sha come from one response and the head is the verified SHA; a PR merged at another head is exit 4 with merged=false. After a merge call the pull request must be readable: an unreadable state is exit 1 (result error), and exit 5 (queued) is reserved for a positively observed unmerged pull request at the verified head. It prints the verified SHA and never a token.
  Exit codes: 0 green (and merged if asked), 1 red, 2 timeout, 3 hung, 4 head moved, 5 queued, 64 bad input.
- **No change to any existing workflow.** Nothing calls the new action yet; a caller opts in by pinning a commit that has it.
  Docs: [wait-ci](docs/wiki/Action-wait-ci.md). Tests: `tests/test_wait_ci.py`.

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

### doppler-secrets: `export: outputs` and a `names` allow-list (issue #207)

- **Added.** The composite action `.github/actions/doppler-secrets` takes `export` (`env`, the default, or `outputs`) and
  `names` (a comma or whitespace separated allow-list). `env` is unchanged: every secret goes to `GITHUB_ENV`, so each
  later step and every action post-run hook inherits it. `outputs` writes nothing to `GITHUB_ENV`; every value is masked
  (each line, the whole value, its JSON-escaped form) before it is written, and one masked JSON output, `secrets`, is
  returned (`{}` when nothing was fetched) for the caller to read with `fromJSON(steps.<id>.outputs.secrets).NAME` and
  hand to single steps through `env:`. `names` narrows either mode and is **required** with `export: outputs` (an empty
  list would return the whole config). In `outputs` mode every non-empty value is masked whatever Doppler's visibility
  says, Doppler's own `DOPPLER_PROJECT`/`CONFIG`/`ENVIRONMENT` labels are never returned, an empty selected value fails
  the job, as does a value under 8 characters (masking a short or common-word value redacts that text from later logs)
  or one containing a NUL. A missing name, an invalid `export`, a malformed
  or empty-after-parsing `names`, and a result over 500,000 UTF-16 code units (GitHub's 1 MB output limit is counted in
  UTF-16) each fail the job without echoing a value. Caller rules: never pass the whole `secrets` output as an env value
  or put it in `GITHUB_ENV`, `GITHUB_STEP_SUMMARY`, artifacts, caches, debug output or job outputs; `add-mask` protects
  logs only and is not an authorization boundary; any step that receives an extracted value can steal it.
  Both authentication paths and the trusted-refs-only guard are kept; the `mode` output is unchanged.
- **Reply handling.** The Doppler reply is read into a private file capped at 4,000,000 bytes (`--max-filesize` plus
  `head -c`) and must be valid UTF-8 (`iconv -f UTF-8 -t UTF-8`) before jq parses it; the UTF-16 size is computed on
  parsed JSON because jq 1.7 raw input miscounts multibyte characters across read chunks. In `export: env` mode values
  Doppler marks unmasked stay unmasked (compatibility); `outputs` is the form for production credentials.
- **Mask function and request checks.** Every mask command is printed by one function, `emit_mask`, which escapes `%`,
  CR and LF (one line carries the Semgrep rule `unsafe-add-mask-workflow-command`, which flags any mask command; the
  escaping is proved by `test_the_mask_function_escapes_a_hostile_value`). The OIDC request URL (https, a GitHub Actions
  host) and request token (character class, length) are checked and the token masked before the first request. Every
  pipeline stage of the reply read is checked (request builder, curl, head); only the oversize path tolerates curl's
  write error. A selected value holding U+FFFD, which is what jq 1.7 makes of an escaped lone low surrogate, fails the
  job in both modes. The reply and mask list live in a private (700/600) temp directory removed on every exit.
- **Caller impact.** None unless a caller sets the new inputs. The default path still runs the pinned
  `dopplerhq/secrets-fetch-action`. The new paths call the Doppler API with curl and jq (that action can only export
  everything it reads), with credentials on standard input. The inlined decide step is untouched, so the five workflow
  copies stay byte-identical. Callers that want `outputs` (the `no-php-no-cry` and `Reach-Around` deploy workflows) re-pin
  to the release that carries this.
- **Tests.** `tests/test_doppler_outputs.py` runs the new steps as shipped against a stub `curl`.
- **Static analysis.** Semgrep's `unsafe-add-mask-workflow-command` audit rule matches any literal mask command, and `add-mask` is the
  only way to mask. The action prints it from one function, escaped first, and that one line carries a rule-scoped ignore with
  its reason; a test fails if a second mask line or a second ignore appears.

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
