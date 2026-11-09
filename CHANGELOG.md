# Changelog

Callers pin a commit of this repository, so a change reaches a caller only when it re-pins. Entries here
name what a caller sees after that.

## Unreleased

### Changed: `project-sync.yml` calls safo v0.2.0 (issue #398)

The Action behind `project-sync.yml` moves from `v0.1.2` to `v0.2.0` (commit `180002332e359b883c33aa4d512b5ba29b2c7657`, the signed annotated tag). Its release hardens which events may use a credential. Callers re-pin and change nothing else: this workflow passes neither `board-file` nor `status-body-file`, so the new rule that those files must be committed and checked out does not apply, and no checkout step or permission was added (`contents: read` and `id-token: write` stay).

What you see after you re-pin:

- **Same-repository events work as before**: `issues`, `pull_request_target` (default branch, pull request from this repository), `schedule` and `workflow_dispatch`. The run now prints one notice naming the event, the ref and the trusted revision it used.
- **A pull request from a fork is refused under `pull_request_target`.** safo now gives a credential to a fork's pull request only when the Action input `allow-fork-pull-request-target` is `"true"`; this workflow does not pass it, so the sync job fails with a message naming the event, and that card is not added until the next scheduled reconcile. A repository that is itself a fork gets no credential either (`allow-fork-repository`). Neither switch is exposed here on purpose; ask in an issue if a caller needs one.
- **Any event not on safo's allow-list** (for example `pull_request` from a fork) is refused for the same reason.
- **Test.** `tests/test_project_sync_wrapper.py` pins the new commit and asserts, for every workflow, that a checkout precedes a safo step that passes `board-file` or `status-body-file`, with a negative case.

### New: `wait-ci.sh --from-protection` and a fail-fast on a gate name that never reports (issue #378)

Five merge captains hit a 10-minute hang or gated on the wrong thing: the default gate is a bare `CI green`, `--require-check` only adds to it, and a nested name (`ci / CI green`, `gate / CI green`) needed `--context`, which replaces the default. Nothing existing changes unless a caller uses the new flag; the fail-fast changes only how a wait that could never end is reported.

- **`--from-protection`.** The gate is read from the default branch: its classic required status checks, then its active rulesets (the union, as GitHub enforces both), with app ids honored. It replaces the default gate, is mutually exclusive with `--context`, and `--require-check` still adds. No readable required check is exit 64 naming the branch.
- **Fail fast.** A requested name that has not reported while every run on the pinned head is complete and the list read identical on 3 polls over at least 60 s now ends with exit 2 (`result` `missing`) and names the missing context and the check names that did report, instead of waiting for the hung timer. A run still open, or a late workflow that starts within that window, is waited for as before. Every other exit code, the head pin, the mergeability read and the settle rule are unchanged.
- **`--help`.** The script prints its usage and options.

### Added: `repin.sh` finds the other copies of the old pin (issue #380)

Two callers failed their re-pin pull requests because a file outside the workflows held the old SHA: a test asserting `bash-ci.yml@<old> # v1.31.0`, and a script constant that a test compared with the workflow pin.

- **Report.** After the pins are rewritten, and in `status` and `apply --dry-run`, `scripts/repin.sh` searches the tracked files of the git checkout for each old full 40-hex SHA as a whole word and lists every hit outside the rewritten workflow refs as `path:line`. Binary files, symlinks, untracked files, a longer hex string that merely contains the SHA, and release-history files (`CHANGELOG*`, `HISTORY*`, `NEWS*`, `RELEASES*`, `RELEASE_NOTES*`) are never hits.
- **New exit code 11** (`apply` and `pr`): the pins were rewritten but copies remain, listed. `pr` still opens the workflow-only pull request and names the copies in its body. Every existing code keeps its meaning; `status` keeps 0, 10 and 3.
- **`--also-update-literals`** (`apply`, `pr`): rewrites those exact copies, and a `# vX.Y.Z` comment only where it directly follows the SHA (a closing quote may sit between), prints each rewrite, and with `pr` commits those files too. `--dry-run` prints the diff. A caller that already re-pinned has no old SHA left to search for, so pass the flag on the run that re-pins.
- **The scheduled workflow** inlines the new script and does not pass the flag: a caller with copies gets the workflow-only pull request and a failed step (exit 11) that names them.
- **File names are data.** Only names made of `A-Za-z0-9._/-` are listed, rewritten or put in a pull request body; any other name (a backtick, a backslash, a newline, a space, `$(...)`, a `;`) is skipped and only counted ("N file(s) with unsafe names skipped"), and that count alone makes the run exit 11. The file name reaches awk through `ENVIRON`, never `-v`, and sed gets only `-e` scripts and `--` before the file.
- **Tests.** `tests/test_repin.py` builds a git fixture with a workflow ref, a test asserting the old pin, a script constant, a CHANGELOG line (untouched), a history file, a binary file, a symlink, an untracked file and a longer hex string.

### Added: a GYST-owned fixture image for `fixture verify` and `fixture rescan` (issue #381, refs)

`fixture verify` and `fixture rescan` checked `ghcr.io/chiefgyk3d/star-daemon:latest`, a third-party moving tag, so a rebuild, rename or privacy change there turned this repository red (#285, #315). No caller input changes; this is this repository's own pipeline.

- **`fixture/gyst-fixture/`.** A five-line Dockerfile on `alpine:3.23` pinned by digest, one copied file (`VERSION`), non-root, no build-time network, no secret.
- **`.github/workflows/fixture-image.yml`.** On a manual run or a push to `main` that changes the image source, calls this repository's own `container-release.yml` (hadolint, Trivy, keyless cosign signature, SPDX SBOM attestation, SLSA provenance) to publish `ghcr.io/chiefgyk3d/gyst-fixture`, tagged `1.0.0`, `latest` and the commit, and its merge job's summary shows the digest. It sets `allowed-publish-events: push,workflow_dispatch` and `require-tag-ref: false` for this one image, guarded by `if: github.ref == 'refs/heads/main'`; the defaults of `container-release.yml` (push events, `vX.Y.Z` tag refs) are unchanged for every caller.
- **One pin file.** `fixture/gyst-fixture/DIGEST` holds `unpublished` or one `sha256:<64 hex>`. A new `fixture pin` job in `ci.yml` reads it and hands the two fixture jobs their image, source repository, signer identity regexp and test command; any other content fails the job. While it says `unpublished` (this change) both jobs keep checking star-daemon, so `main` does not depend on an image that does not exist yet. The follow-up change writes the digest, which switches them to `gyst-fixture@sha256:...`. `tests/test_fixture_image.py` pins the format, that the digest is written nowhere else, and the signer regexp.
- **After the first publish (owner, once).** The package GHCR creates is private ("When you first publish a package, the default visibility is private"), and `fixture verify` and `fixture rescan` pull anonymously, so it must be made public. VERIFIED against GitHub Docs on 2026-11-09 ("Working with the Container registry" and "Configuring a package's access control and visibility"): on the package's page, Package settings, "Danger Zone", "Change visibility", Public (the docs warn a public package cannot be made private again). VERIFIED against the REST reference for Packages (docs.github.com/en/rest/packages/packages, 2026-11-09): it lists, gets, deletes and restores packages and package versions and has no operation that sets visibility, so there is no API command to give. The lead confirms the result with `docker logout ghcr.io; docker pull ghcr.io/chiefgyk3d/gyst-fixture@sha256:<digest>` (INFERRED to work anonymously once public; not run, the image does not exist yet).

### Added: a failed Trivy image scan names what tripped it (issue #383)

A caller sees this after it re-pins; no input changes, no egress host is added and the scan's exit behavior is unchanged.

- **`Summarize a failed Trivy scan`.** A new step in both build jobs of `container-release.yml` (`python-docker-release.yml` forwards through it) runs when the scan step fails (`inputs.trivy && failure()`, 2 minutes at most, no network). From the SARIF the scan already wrote it prints the totals by severity and one row per rule id and file path with its count, secret rules first, at most 50 rows. It never prints the matched text, a message or a snippet; ids and paths are JSON-escaped and cut to 200 characters. It always exits 0, so it never changes pass or fail.
- **The site-packages hint.** When every secret hit is under a `site-packages` path it adds one line: set `skip-secret-scan-in-site-packages: true` on the call to skip secret rules there (CVE scanning stays on). The input stays opt-in and off by default.
- **Where it lives.** `scripts/trivy_sarif_summary.py` (stdlib only); its marked block is inlined byte for byte, held identical by `tests/test_trivy_sarif_summary.py`. `verify-published.yml` and `base-image-digest.yml` scan with their own Trivy binary and JSON output, not this scan, and are unchanged.

### New: `main-verify.yml`, a post-merge check that main has green required checks (issue #379)

On 2026-11-09 commit 52592bc, a Dependabot bump merged by the auto-merge token, landed on `main` with no workflow run at all: GitHub starts no run for a push made with the job token, so `main` can sit unverified. Nothing changes for a caller; this is this repository's own workflow.

- **`main-verify.yml`.** Runs on a push to `main`, every six hours and by hand. It reads the default branch head and the required checks on it (from the branch protection when the token can read it, else `FALLBACK_CONTEXTS`, `CI green`). Green: one line, nothing else. A required check red: the job fails and the annotation lists the red contexts with counts. None reported once the commit is 10 minutes old (and no `ci.yml` run for it is queued): `ci.yml` is dispatched on `main` by `workflow_dispatch`, which a job token may start, and the required checks are awaited for at most 25 minutes. Still nothing completed, or anything not green: the job fails. Three jobs, so `actions: write` is on the dispatch job alone; no secret; default branch only; every wait and request is bounded.
- **`scripts/verify_main.py`** (stdlib only) holds the logic; `tests/test_verify_main.py` runs it against a stubbed REST API and a fake clock.
- **Limits.** The push trigger is itself not created for a push made with the job token, so a bot-merged commit is caught by the six-hour schedule, up to six hours late. `ci.yml` must keep `workflow_dispatch` (it has it; a test pins that). Not shipped as a reusable workflow: it would need the script inlined and an input for the CI workflow's file name; another repository can copy the file and the script.

### Changed: the repository's own test job runs pytest in parallel (issue #306)

- **`ci.yml` `Test the workflows`.** `Run the tests` is now `pytest -q -n auto` (pytest-xdist, one worker per CPU). The step took 622 s of a 641 s job on the latest successful main run, and the last 15 successful runs of the job took 563 to 958 s. No test, assertion or check changed, the job name and `CI green` wiring are the same, and a caller sees nothing (this file is the repository's own CI, not a reusable workflow).
- **`requirements-dev.in` / `.txt`.** `pytest-xdist==3.8.0` (and its `execnet`) added; the lock was regenerated with `pip-compile --generate-hashes --strip-extras`, which also drops the `[extras]` brackets pip-compile now strips from two existing lines.
- **Guard.** `tests/test_workflows.py` fails if the step loses `-n auto` or the lock loses `pytest-xdist`.

### Changed: every job has a measured time cap (issue #247)

On 2026-10-30 fixture jobs finished in seconds and then sat idle for 20 to 35 minutes until a cap; each cost a re-run. A caller sees nothing until it re-pins, and nothing changes in a reusable workflow's inputs or defaults.

- **Fixture calls and self jobs.** `ci.yml`, `security-self.yml`, `wiki.yml` and `dependabot-auto-merge-self.yml` now pass each reusable workflow's `timeout-minutes` input (5, or 10 for the Python CI fixture and the security scan, from the last 30 green runs: p95 under 3 minutes everywhere). `actionlint`, `zizmor`, `fixture sbom`, the two action fixtures and `rescan fails when it should` drop to 5; `dast fails when it should` drops from 60 to 30. `Test the workflows` stays at 20. Every cap has a `# normal: ~N min` comment above it.
- **Not changed.** The reusable workflows' defaults (a caller's job can be much slower than the fixture) and the container builds' 60.
- **Test and page.** `tests/test_job_timeouts.py` fails a job with no cap, a cap above 90 minutes without a written reason, an `inputs.` expression that names no number input, and a caller that leaves a called workflow's default in place. [Job timeouts](docs/wiki/Job-timeouts.md) holds the measurements, what the logs of runs 41035462015 and 41065673856 show (the hang is after the last step, not in the harden-runner post step or the artifact upload) and the effect of the docs-only gating.

### New: fleet status report, `fleet-status.yml` and `scripts/fleet_status.py` (issue #382)

This repository's own workflow; nothing a caller pins changes.

- **One page of counts.** Weekly (Monday 06:37 UTC) and on demand, for the non-archived, non-fork repositories of the owner (more owners with `--owner`, repeated): the GYST pins in each repository's `.github/workflows` against the latest release (current, behind, unknown, none), open Dependabot alert counts by severity, whether the default branch is protected (classic protection or a ruleset) with the exact required check names, and the newest default-branch push result. A markdown table goes to the job summary and a JSON file to an artifact kept 30 days.
- **Counts only, REST only, standard library only.** No advisory text, package name or secret is read into the report. Every request has a timeout, a transient failure is retried twice, the rate-limit headers are respected, a request cap applies, a redirect is refused, and a rate limit stops the run with a message and no report instead of a partial table.
- **No new credential.** The job holds `contents: read` and the default job token only. What that token cannot read (alerts, protection, other private repositories) is `n/a` in the table, never a guess; run the script by hand with a wider token to fill it in.

### Fixed: tool installs survive a GitHub download outage (issue #372, refs)

On 2026-11-09 a GitHub incident timed out anonymous traffic (HTTP 504, curl exit 22) and every plain `curl -sSfL` tool install failed on its first try. A caller sees this after it re-pins; no input changes and no egress host is added.

- **`fetch_release`.** One helper (`scripts/fetch-release.sh`) now makes all 14 release downloads: gitleaks (`security.yml`), syft (`python-package-release.yml`), Trivy (`base-image-digest.yml`, `verify-published.yml`), hadolint (`container-release.yml`), shellcheck and shfmt (`bash-ci.yml`), OpenTofu (4 jobs), tflint and OPA (`tofu-ci.yml`) and arduino-cli (`arduino-ci.yml`). It sends the job token (passed to the step as `FETCH_RELEASE_TOKEN`), when the step has one, on `https://github.com/` URLs only (through a curl config on stdin: in no argument list, and `set -x` is switched off around it). Only the two jobs already kept in `block` hand it over (`python-package-release.yml` `build`, `tofu-ci.yml` `plan`); a job that follows `egress-policy-secretless` holds no token by design (EX-0001) and downloads anonymously with the same retries. It tries at most 5 times with exponential backoff and jitter (2, 4, 8, 16 s, up to half again), caps each try at 45 s and the whole call at 170 s. The pinned SHA-256 is mandatory and fatal: a missing, malformed or mismatched hash fails at once, is never retried and leaves no file. The existing cache check and the `sha256sum -c` after the download stay.
- **Inlined, held identical.** A reusable workflow cannot call a file of its own commit, so the marked block is copied into each step; `tests/test_fetch_release.py` holds every copy byte-identical to the script, runs the function against a fake curl (retry bounds, mandatory checksum, token never in argv or logs, even under `set -x`), and fails if any step curls a release URL outside the helper.
- **Not changed.** The `sigstore/cosign-installer` (3 steps), `aquasecurity/trivy-action` (3 steps) and `anchore/sbom-action` (1 step) steps download inside third-party actions and still do so; see issue #372.

### Fix: `repin.sh` could not read workflow inputs (issue #374)

- **`scripts/repin.sh`.** `apply`, `status` and `pr` read each called workflow's inputs through the contents API, and
  passed the ref with `gh api -f`, which makes gh send a POST; GitHub rejected it, so every caller exited 5 with
  "cannot read <workflow> at the old pin". The ref now rides in the query string (a GET). A genuine input drop still
  exits 5.

### Changed: the egress steps lose the `(EX-0001)` suffix (issue #311)

- **Step names.** `Egress canary (EX-0001)` is now `Egress canary` and `Validate the egress policy inputs (EX-0001)` is now
  `Validate the egress policy inputs`, in every reusable workflow and in the `egress-canary` and `egress-policy-check`
  composite actions. The canary's error and step-summary text no longer name EX-0001. Behavior, the script and the
  `egress-policy-secretless` input are unchanged. A caller that matches the old step name, such as a merge watcher or a branch
  rule that keys on it, must update to the new name. The closed exception record stays.

### Hardening: credential scope of `repin.yml` (issue #370)

- **`repin.yml`.** The Doppler fetch no longer injects secrets into the job environment (`inject-env-vars: false`); the
  App key now reaches only the token step, through the fetch step's masked outputs. The job's harden-runner also sets
  `disable-sudo: true`. No input, secret or permission changes.

### New: opt-in `token-drift.yml` (issue #342)

A new reusable workflow. Nothing existing changes: a caller sees it only by adding a job that calls it, after it re-pins.

- **`token-drift.yml`.** For a file vendored from another repository whose upstream moves (two sites sharing brand tokens).
  It reads the lock file `vendored-drift.yml` reads (`vendored`, `sha256`, `source.repo/path/commit`) and fails when the
  lock is malformed or disagrees with the optional `vendored-path`, `source-repo` or `source-path` inputs, when the vendored
  file is not a regular file inside the repository or its SHA-256 differs from the pin, and, with `check-live`, when the
  source repository's file differs from the pin. The live check resolves `source-ref` (default branch when empty) to one
  commit through `api.github.com`, fetches the file at exactly that commit and compares file hashes; the message names the
  file, the commit and both hashes. The source must be public; the read-only job token goes to `api.github.com` only, a
  redirect is refused and at most 16 MiB is read. Default egress `api.github.com:443 github.com:443`. `contents: read`, no
  secret, inputs through the environment. `advisory` (default false) turns drift into a warning and the `drifted` output, for
  the planted fixtures. Script: `scripts/check_token_drift.py`, inlined byte for byte and held identical by
  `tests/test_token_drift.py`.
- `ci.yml` calls it on `fixture/token-drift/` (a pin, a live check against this repository's `LICENSE`, two planted drifts) and
  a `token drift control` job fails unless both planted jobs reported drift. All are in the `CI green` gate.

## v1.34.0 (2026-11-09)

### Changed: harden the CI green gate and the docs-only classification (issues #307, #325)

Only this repository's own CI changes. The aggregate `CI green` job now reads its gate code from the base commit on a pull request
instead of the pull request itself, and the docs-only list is by file type with shell files on the never-skip list. Tests pin both.

### Changed: concurrency on the self-callers, and the auto-merge actor gate (issue #313)

Only this repository's own workflows change. `security-self.yml` cancels a superseded pull request run (a push to main and the
weekly schedule run to the end). `wiki.yml` serializes publishes on a group that is not the literal `wiki` (the reusable
publish job holds that one) and never cancels one. `dependabot-auto-merge-self.yml` has one run per pull request and its job
carries the same actor `if:` as the reusable workflow. GitHub still lists a skipped run of that workflow on every pull request:
a `pull_request` trigger cannot filter on who opened it, so that entry cannot be removed, and a test pins what can be done.

### Changed: this repository's `dast-live` and `rescan-live` run when related files change, and nightly (issue #308)

Only this repository's own CI changes. The two live jobs (the real ZAP image, about 450 seconds, and the real Trivy) are gated
by the `changes` job from the entry below: they are left out of a pull request that changes only docs, the changelog or tests
they do not read. `tests/test_dast.py`, `tests/test_verify_published.py`, `tests/test_sbom.py` (run by `fixture-sbom`, which also reads
`README.md`, so that is not on the docs-only list), `tests/test_workflows.py` (which `test_dast.py`
imports) and `tests/fixtures/**` are on the classifier's `never-skip-patterns`, so a change to any of them runs the live jobs
even beside docs. `ci.yml` gains a nightly `schedule` (every day, default branch); the classifier is `false` for anything but a
pull request, so the nightly run is the whole run, live jobs included. A test fails if any job opts out of the schedule, and another fails if any path a gated job reads or runs would alone be docs only.

### Changed: this repository's `ci.yml` skips jobs a docs-only change cannot affect (issue #307)

Only this repository's own CI changes; no reusable workflow and no input a caller uses.

- A new `changes` job runs the `classify-changes` action over `docs/**`, `tests/**` and `CHANGELOG.md`. Every fixture job (all but
  `actionlint`, `zizmor`, the test suite and `CI green`) now needs it and is left out on a pull request that changes only
  those paths. Anything else (a path under `.github/`, `scripts/`, `fixture/`, a requirements file), a push, a schedule, a
  manual run, a moved head and any doubt is `docs-only=false` and runs everything, as before.
- `CI green` is now the `ci-gate` action instead of an inline `grep` for `failure|cancelled`. A skipped job used to count as a
  pass whatever the reason; now it counts only when `changes` succeeded with `docs-only=true`, or (for the jobs that already
  skipped on a fork's pull request) when the run is a fork's pull request. Any other skip, a failure, a cancellation or a job
  dropped from `needs` fails.
- `ci-gate` (action and `scripts/ci_gate.py`) gained two optional inputs, `fork-skippable-jobs` and `fork-pull-request`. Unset,
  it behaves exactly as before.
- `tests/test_path_aware_gating.py` holds the gated jobs, the gate's `skippable-jobs`, `required-jobs` and the fork list
  together.

### New: `scripts/repin.sh` and `examples/dependabot-gyst.yml` (issue #310)

Tooling only: no workflow changes, so a caller sees nothing after it re-pins. `scripts/repin.sh status|apply|pr` moves a
repository's `uses: ChiefGyk3D/git-your-ship-together/...@<sha> # vX.Y.Z` pins to a release, changing only the SHA and the
version comment (checked before anything is written), refusing a non-canonical reference or a downgrade, and, in `pr` mode, opening
one pull request on `repin/gyst-<tag>` without merging. `examples/dependabot-gyst.yml` is a `dependabot.yml` template with a group
for GYST references and a 2-day cooldown. See the [repin wiki page](docs/wiki/Script-repin.md).

### Added: `wait-ci` ends early on a merge conflict, exit 7 (issue #352)

With `--pr`, `scripts/wait-ci.sh` (and the `wait-ci` action) now reads the pull request's `mergeable` and `mergeable_state` on every
poll and again at the re-read after green. `mergeable: false` or state `dirty` ends the wait at once with the new exit code `7`
(`result` is `conflict`), naming the base branch and its head SHA, instead of waiting out the timeout or failing at merge time.
`mergeable: null` (GitHub still computing) is unknown and re-polled; `behind` is a printed note, not a failure. No existing exit code or
green criterion changes, and a conflicting pull request is never reported green or merged. Without `--pr` nothing changes.
Tests: `tests/test_wait_ci.py`.

### New: opt-in `pin-comments.yml` (issue #318)

Checks that the `# vX.Y.Z` comment on every SHA-pinned `uses:` line (workflows and composite actions) names the commit it is
pinned to: the comment must exist, the tag must exist, and it must resolve to the pin. Until now only zizmor's
`ref-version-mismatch` checked this, and only for callers that run zizmor. A lookup that cannot be completed is `UNVERIFIED` and
fails the job (input `unverified: warn` prints it and passes); lookups are bounded (10 s each, 200 and 120 s in all). Read-only;
a caller that sets nothing sees no change. This repository's own CI now runs it. Script: `scripts/check_pin_comments.py`.

### Breaking: `security.yml` no longer supports Python 3.10 (issues #347, #314)

The pip-audit and Semgrep hash locks now cover CPython 3.11 through 3.14 (they covered 3.10 through 3.14). 3.10 reached end of life on 2026-10-01
and no fixed `filelock` exists for it. Locked bumps: `filelock` 4.2.7 to 4.2.9 (the 3.10-only pins are gone), `platformdirs` 4.14.3 to 4.14.5, `py-serializable` 2.1.0 to 2.2.0.
**A caller whose `security` job passes `python-version: "3.10"` must change it** (the default `3.13` is unaffected); on 3.10 the install now fails, since the locked wheels no longer resolve.
The 3.10 grace entry in `.github/python-support.json` is deleted. The weekly audit (`audit.yml`) now runs `scripts/python_support.py`, so a listed version past its security end
or a lapsed grace entry turns it red.

### New: `python-ci.yml` `pr-python-versions` (issue #309)

Opt-in, default empty: a caller that sets nothing sees no change after it re-pins, and the `test` matrix is `python-versions` on every event.
Set to a JSON array such as `'["3.11", "3.15"]'` (the oldest and the newest), the `test` matrix on `pull_request` events is that list; push, schedule and dispatch still run the full `python-versions`, so a caller wanting the full matrix weekly adds a `schedule` trigger.
A new step in each `test` leg fails the job when the value is not a non-empty JSON array of distinct strings, names a version not in `python-versions`, or (with `coverage-threshold` set, on a pull request) leaves out `coverage-python-version`, since no leg would then check the threshold.
`CI green` is unchanged: it still needs `test` and fails on a failed leg. A caller whose branch protection requires individual `Test (Python X, runner)` checks must require only the legs the pull request matrix keeps; requiring `CI green` avoids that.

### Changed: `container-release.yml` refusal notice names only the inputs that apply (issue #329)

When `push: true` is refused, the warning annotation and job summary now follow the failed predicate instead of always naming both inputs: a pull-request event says no input can enable publishing; an event outside the allow-list names `allowed-publish-events`; a ref that is not a release tag names `require-tag-ref: false`; both failing names both. Message text only: the publish decision, outputs and inputs are unchanged.

### Fixed: the `ci-gate` composite action could not be loaded by a runner (issue #331)

**The `.github/actions/ci-gate` composite action in v1.32.0 and v1.33.0 is unusable.** (It is not the reusable workflow
`ci-gate.yml`, which is unaffected.) A job that used the action failed in Set up job with `Unrecognized named-value:
needs` (`TemplateValidationException`, `action.yml` line 12). The cause was the `needs` input's description, which quoted
`${{ toJSON(needs) }}`: a runner evaluates expressions in an action's metadata when it loads the manifest, and the `needs`
context does not exist there. Both tags stay as published. **Use v1.33.1.** Callers that already pass `needs` as an
input (`needs: ${{ toJSON(needs) }}` in their own `with:`) change nothing but the pin; the input name and its meaning are the
same. The input has no default, and the action now fails with a plain message when it is empty, not JSON, or not a non-empty
JSON object.

`classify-changes` was checked for the same mistake and has none.

How it is kept from happening again: `tests/test_action_manifests.py` refuses an unavailable context in any expression of any
action manifest (and any expression in a description), and GYST's own `CI green` now needs two jobs that run the local
`ci-gate` and `classify-changes` actions on a real runner. The cases that must fail (a failed job, an unnamed skip, a missing
input) stay in `tests/test_docs_only_fast_path.py`, against the script the action calls.

### Changed: `security.yml` says which `.gitleaksignore` entries cannot match a pull request's tree scan (issue #336)

No scan argument, ignore file, default or exit code changes: a caller that re-pins sees the same findings as before and one new
step, `Report commit-bound .gitleaksignore entries`. Since v1.29.0 (`gitleaks-scope: pr-commits`) a pull request also gets a
tree scan, and a tree scan can only match the path-and-rule form of an ignore entry (`file:rule:line`), never the commit-bound
form gitleaks writes for a history finding (`commit:file:rule:line`). A caller whose `.gitleaksignore` holds commit-bound
entries therefore sees reviewed findings fail the pull request again, and a rebase or squash orphans them in the history scan
too. The new step runs on a pull request with `pr-commits` and, when the base commit's `.gitleaksignore` holds such entries,
writes a warning and a step summary naming each by line number, file and rule id (at most 50; never a commit, never a matched
value). It never fails the job and never rewrites an entry.
Migration, pick one: drop the commit id from the entry (`file:rule:line`, also survives a rebase or squash); allowlist the path
and rule in `.gitleaks.toml` with a reason (read from the base commit on a pull request); or set `gitleaks-scope: all-refs`.
README has the details under "Migrating `.gitleaksignore` entries".

### Changed: the documented security-only caller carries a `CI green` gate (issue #337)

The README `Security` caller example now ends in a `gate` job that calls `ci-gate.yml` over `security` (`if: always()`,
`permissions: {}`), so a repository whose only GYST caller is `security.yml` produces a check, `gate / CI green`, that branch
protection can require. `scripts/audit_baseline.py` now also derives `<job> / CI green` from a job that calls `ci-gate.yml`, so
a caller that already uses `ci-gate.yml` is expected to require that check too (before, only `*-ci.yml` calls counted). Nothing
in `security.yml` changes; adding the job and requiring the check is the caller's step, and a protection write on a repository
is a separate approval.

### New: `container-release.yml` `skip-secret-scan-in-site-packages` (issue #327)

Opt-in, default `false`: a caller that sets nothing sees no change after it re-pins, and the Trivy step is byte for byte what it was.
Set to `true`, Trivy **secret** findings are suppressed (all secret rules; Trivy still reads the files) for files in installed Python packages under a short fixed list of image roots (`usr/lib`, `usr/lib64`, `usr/local/lib`, `usr/local/lib64` and `opt/venv/lib`, each followed by `pythonX.Y/site-packages/` (numeric version), anchored at the image root),
through one `allow-rules` path entry in a generated `trivy-secret.yaml` passed as `TRIVY_SECRET_CONFIG`. The vulnerability scan, `trivy-severity`,
`trivy-ignore-unfixed` and `trivy-exit-code` are unchanged, and every other path is still scanned. A genuine secret shipped by a
dependency under those roots will **not** be detected (a supply-chain tradeoff).
Fork pull requests: a caller that passes this input on `pull_request` events lets an untrusted pull request's image weaken only its own secret detection; publishing is already gated off for pull requests.
Why: a package's docstring text can match a secret rule when nothing is a credential; the installed `anthropic` SDK trips
`gcp-service-account` (11 CRITICAL findings on Boon-Tube-Daemon's image, no fixed version). Source: Trivy secret scanning docs, "Allow Rules".

### New: `repin.yml`, scheduled pin-only re-pin (issue #334)

Opt-in, new file: a caller sees nothing until it adds a job that calls it. It runs `scripts/repin.sh` (inlined byte for byte) on
the caller's schedule and, when the caller's pins of these workflows are behind the latest release, opens ONE pull request that
changes the pin SHA and the `# vX.Y.Z` comment and nothing else. It never merges, and it stops without a pull request, naming
them, when the release drops or retypes an input the caller sets or adds a required input it does not set. `repin.sh` gains
that input check (exit 5, `--allow-input-changes` to override). Opening the pull request takes a GitHub App token limited to the
calling repository (Contents, Pull requests, Workflows: write); the job's own token stays `contents: read`, and with no App the
run only reports. The App's private key is never a GitHub secret: it is fetched at run time over the job's OIDC
identity (the secret `REPIN_APP_PRIVATE_KEY`, the same steps as `project-sync.yml`), so the caller grants `id-token: write`.
Inputs: `client-id`, `dry-run`, `doppler-project`, `doppler-config`, `doppler-identity-id`, `doppler-trusted-refs-only`, the egress
trio (the default allow-list adds `api.doppler.com:443`), `timeout-minutes`; secret: `DOPPLER_TOKEN` (optional fallback, leave unset).

### Fixed: sign and attest before the release tags move (issue #286)

Callers pick this up when they re-pin. **Security-sensitive release path.** Also hardens concurrency, ordering and input handling of tag promotion.

- **`container-release.yml`: the release tags move last.** A Rekor 409 on `cosign sign` used to fail the job after the index was already published under `latest` and the other tags, leaving a published image with no SBOM or provenance. The merge job now stages the index in each registry under a tag of the run (`stage-<sha>-<run id>-<attempt>`) and writes no release tag there. It signs, attests the SBOM, records provenance and verifies the signature and the SBOM attestation of that digest in every registry. Only then does the new "Publish the release tags" step write `latest`, the branch, semver and `sha-` tags. If an earlier step fails, no release tag is written and the staged tags stay. This replaces the previous promotion inside the index step and the two "Re-check the final tags" steps.
- **The tag step is bounded, not atomic.** A registry cannot write several tags in one step, so the step cannot promise that all tags move or none. Before writing anything it checks that the staged index reads back at its digest in each registry and records the digest every release tag holds now (a not-found reply means the tag is new; any other read failure stops the step with nothing moved). It writes one tag at a time, `sha-` tags first and `latest` last, each from its own registry, reads each back, and reads every tag again after the last write. Every registry call is retried up to 4 attempts in all, waiting 5, 10 and 20 seconds, only for HTTP 408, 425, 429, any 5xx or a timeout or reset; a write that returns an error is judged by reading the tag back.
- **The restore is best effort and never overwrites another writer.** On a failure a tag is written back to its previous digest only while it still holds the digest this run wrote. A tag that holds any other digest is left alone, and the step fails with a "rollback failed" error naming the tag, the digest it holds, the digest this run promoted and the recorded previous digest. A restore needs the previous manifest to still exist, and the previous digest is whatever the tag held: this workflow does not verify it again. A tag that did not exist before cannot be deleted, so it may remain on the new digest; the step names it. If a restore is refused or fails, the step fails and names every tag and digest left behind. The step does not stop another writer with registry access.
- **A Rekor 409 `equivalent entry already exists` counts as success only after `cosign verify` (`verify-attestation` for the SBOM) of that digest passes** with the signer identity, the OIDC issuer, the calling repository and the commit of the run. Any other error fails at once. Transient errors (HTTP 408, 425, 429 and every 5xx, timeouts, resets) are retried 4 times in all, waiting 5, 10 and 20 seconds.
- **New input `signer-identity-regexp`**, strictly validated in the plan job, before any build leg pushes (literal characters and escaped dots only, ending in `@`) and again in `merge`. A caller needs no change; a fork of this repository sets its own. `python-docker-release.yml` forwards it.
- **New input `allow-unsigned-publish`** (default `false`). A run that would publish with `sign`, `sbom` or `provenance` off now fails in the plan job unless this is `true`; a run that does not publish is unaffected. A caller that publishes unsigned on purpose sets it.
- **Publishes to one destination are serialized, whatever the ref, and a release only moves the mutable tags when it is the newest.** The merge job's concurrency group is keyed on the GHCR image (Docker Hub on or off), never on the ref, and a running publish is never cancelled midway. GitHub keeps one pending run per group, so a pending run is replaced by a newer pending run for the same image; re-run the replaced one. On a branch ref the tag step reads the branch head first: a run whose commit is no longer the head writes only its `sha-` tags and warns; an unreadable head fails the job. On a `vMAJOR.MINOR.PATCH` tag ref it lists the repository's `v*` tags through the API (`contents: read`, already held) and compares SemVer 2.0.0 precedence (a stable release against stable releases only): if a newer release exists it writes only its version tag and the `sha-` tags and leaves `latest`, the major and minor tags alone, with a notice, so a backport such as `v1.9.1` after `v2.0.0` does not move `1.9` or `1`. A tag ref that is not a SemVer release has no order, so it writes only its own tag name and the `sha-` tags. If the tag list cannot be read, nothing moves.
- **Harden concurrency/ordering of tag promotion and rollback.** Covers the publish queue, the newest-ref check and the restore step of the tag step.
- **Not changed:** per-registry signing and the job's outputs (`digest`, `image`), the publish allow-list, and the digest hand-off between the build and merge jobs. The final verify does not re-check the GitHub provenance attestation. The default `signer-identity-regexp` names this repository's `container-release.yml`; it is unverified against a released image's certificate.
- **Guard.** `tests/test_container_release_publish.py` runs the step scripts with stub `cosign` and a fake registry: tag order, release order across refs, retries, failure on the first and on a later tag, a tag landing on the wrong digest, a rollback that does not overwrite another writer, every 5xx status, and the Rekor conflict path.

## v1.33.0 (2026-11-08)

### New: `parallel-ci.yml` and `ci-gate.yml` (issue #330)

Two new reusable workflows. Nothing existing changes: a caller sees them only by adding a job that calls one, after it
re-pins.

- **`parallel-ci.yml`.** One build, then caller-supplied checks as separate jobs that share it, ending in one `CI green`
  gate. A caller passes `build-command`, `build-output-path` and a `jobs` JSON list (`name`, `command`, `timeout`, `areas`,
  `pip-cache`, `tools`, `build`); the build is uploaded once as a one-day artifact named with the run attempt, and each check
  leg downloads it. `areas` path rules (plain `git diff --no-renames --name-only`) skip the checks a change cannot affect and
  **fail closed**: a push, a schedule, a manual run, an empty or unreadable diff, an unmatched path and an odd byte in a name
  all run everything. The gate fails on any failed, cancelled or unexplained-skipped job; the only skip it accepts is the
  whole `checks` job when the path rules selected nothing. Pip and tool-download caches are keyed on pin files the caller names
  and are used only under `block`. Tool setup runs in the same shell as the command that needs it; nothing is written to
  `$GITHUB_PATH` or `$GITHUB_ENV`. Every input is validated and reaches a script through the environment. Every job holds
  `contents: read` and no secret. No `continue-on-error`. Scripts: `scripts/parallel_ci_plan.py`, `scripts/parallel_ci_gate.py`.
- **`ci-gate.yml`.** The gate on its own, for a caller that runs several workflows side by side: `CI green` over a
  `needs-json` it is handed, with `deliberate-skips` as the only excuse for a skip. No token.
- Both run against `fixture/` in `ci.yml` and are in the `CI green` gate. `tests/test_egress_canary.py`'s expression
  evaluator learned the two forms the new cache conditions use (a non-empty `needs` output, a matrix flag); the rule it pins
  (no cache in an audit job) is unchanged.

## v1.32.0 (2026-11-08)

### New: opt-in CI speed-ups, `test-matrix`, `xdist` and the docs-only fast path (issue #331)

All opt-in; a caller that sets nothing sees no change after it re-pins (re-pinning downstream repositories is separate work).
The one visible difference for a `tofu-ci.yml` caller with `test: true` is an extra small job, `test directories`, that lists
the legs; the `test` job keeps its name.

- **`tofu-ci.yml` `test-matrix`** (default `false`). With `test`, `tofu test` runs as one job per directory (`fail-fast: false`)
  instead of every directory in turn. `ci-green` still reports one result and now treats a skipped `test` or `test-dirs` as a
  failure when `test` was asked for; a failed or cancelled leg already made `test` fail or cancel.
- **`python-ci.yml` `xdist`, `xdist-workers`** (default off, `auto`). Installs `pytest-xdist` 3.8.0 and `execnet` from a hash lock (`--require-hashes`, no version input) and sets
  `PYTEST_ADDOPTS=-n <workers>` for the `test-command` step only, so a command that chains scripts before pytest is unchanged.
- **`.github/actions/classify-changes` and `.github/actions/ci-gate`.** A pull request that changes only the caller's docs-only
  paths leaves a named job out on purpose, and the caller's `CI green` counts that skip as a pass and every other skip as a
  failure. The changed files come from the API and anything unconfirmed runs the job. Rules and threat notes:
  [Docs-only fast path and parallel CI](docs/wiki/Docs-only-fast-path.md). Scripts: `scripts/classify_changes.py`,
  `scripts/ci_gate.py`. Issue #330's static-site workflow should call the same actions.

## v1.31.0 (2026-11-07)

### Changed (BREAKING default for publishing callers): `container-release.yml` publishes only from a SemVer tag push (issues #325, #327, pull request #328)

Callers pick this up when they re-pin (callers pin a commit; re-pinning downstream repositories is separate work).

- **Breaking default.** With `push: true`, `container-release.yml` now publishes only for a push of a `vMAJOR.MINOR.PATCH` tag
  (SemVer 2.0.0 pre-release and build parts allowed). Any other run with `push: true` builds and scans only, prints a
  `publish skipped` warning annotation and writes a job summary naming the reason and the inputs to set.
- **New inputs.** `allowed-publish-events` (default `push`; `*` or a comma-separated list of lowercase event names, no spaces;
  validated) and `require-tag-ref` (default `true`).
- **What a caller must do.** A caller that publishes from main, a schedule or a manual run adds
  `allowed-publish-events: push,schedule,workflow_dispatch` and `require-tag-ref: false`. Without them its next run on those
  events builds and scans but does not publish. A caller that publishes only from tag pushes changes nothing.
- **Build split.** The build is split into `build` (publishing; `packages: write`) and `build-local` (no publish permission).
- **Per-registry indexes.** Each registry gets its own multi-platform index, built from digests that are verified first.
- **Strict `platforms`.** The list is validated as written and a repeated platform is refused. The tag check uses the SemVer
  2.0.0 grammar, so `v1`, `v1.2` and `vnot-a-release` do not publish.

### Changed: release workflows are stricter about publishing and assets (issues #325, #327, pull request #326)

Applies to `artifact-release.yml` and `python-package-release.yml` (and the `python-docker-release.yml` name that forwards to
them). Callers pick this up when they re-pin.

- **Publish allow-list.** Publishing runs only for an event named in `allowed-publish-events` (default `push`) on a
  `refs/tags/v<semver>` ref. A caller triggered by `release: published`, such as `hypeman` calling
  `python-package-release.yml`, must set `allowed-publish-events: push,release`.
- **Asset naming policy.** Every local file name must be ASCII letters, digits, `.`, `_` and `-`, starting and ending with a
  letter or digit; checked before any release call. A build that produces another name (spaces, `+`, non-ASCII, a leading or
  trailing `_` or `-`) must rename the file in its `build-command` before re-pinning.
- **Hidden files refused.** Names beginning with `.` in the staging directory are rejected, no longer skipped.
- **Case collisions refused.** Names that differ only in letter case are refused (a conservative policy).
- **Prerelease tags create prereleases.** A new release for a SemVer prerelease tag (for example `v1.2.3-rc.1`) is created with
  `--prerelease`. Earlier versions never set the flag.
- **Existing release must match.** An existing release must carry the `prerelease` flag its tag implies, hold only assets that
  are absent or identical by sha256, and hold exactly this build's files after the upload, or the run fails and the version is
  burned. A draft release for the tag fails the run until it is published or deleted.
- **Asset listing.** Read through the paginated listing, validated before use; every remote asset must be `uploaded` and no
  name may repeat.

## v1.30.0 (2026-11-06)

### New: opt-in `vendored-drift.yml` and `base-image-digest.yml` (issue #296)

Two new reusable workflows. Both are opt-in and existing callers are unchanged: a caller sees them only after it re-pins
(re-pinning downstream repositories is separate work) and adds a job that calls one.

- **`vendored-drift.yml`.** For a file vendored from another repository. Each lock file (path, source repository, commit,
  SHA-256) must match the vendored file's hash, and an optional generator run with `--check` must agree. No lock file is a
  failure. Read-only, no secret. Script: `scripts/check_vendored_drift.py`.
- **`base-image-digest.yml`.** Scheduled check of `FROM image:tag@sha256:...` pins: resolves today's digest of each tag and
  fails when the pinned digest has a fixable HIGH or CRITICAL finding that the current digest does not (the class that failed
  the Reach Around v0.2.1 release scan at tag time). `exit-code: "0"` reports in the job summary only. Read-only, no secret,
  no issue write. Script: `scripts/base_image_digest.py`.
- Both run against `fixture/` in `ci.yml` and are in the `CI green` gate.

## v1.29.0 (2026-11-05)

### New: `gitleaks-hash-manifest-paths` input in `security.yml` (issue #290)

Callers pick this up when they re-pin (re-pinning downstream repositories is separate work). The default is empty, so a
caller that sets nothing sees no change.

- **The false positive.** The default rule `discord-api-token` flags a SHA-256 on a line keyed `discord` (the hash of a
  `discord.svg` in an asset manifest; seen 2026-11-05 in a static-site repository).
- **New input.** Newline-separated repository-relative paths of hash manifests. For exactly those files the job allows a
  finding of `discord-api-token` whose value is exactly 64 lowercase hex characters (`condition = "AND"` over rule, value and
  path; each path anchored at both ends, no globs). Any other rule, path or value is still reported, in the history scan and
  the tree scan.
- **A pull request still cannot allowlist itself.** The allowlist is an overlay that `extend`s the configuration the scan
  uses: on a pull request the base commit's `.gitleaks.toml` (or the scanner defaults), on other events the checked-out one.
  The list is the caller's workflow input.
- **Fails closed.** A line with a glob, space, quote, `..`, an absolute path or any character outside letters, digits,
  `_ . - /`, or more than 100 paths, fails the gitleaks job; the error never echoes the value.
- **Canary** runs with the overlay in its arguments: the planted key must still be caught.

### Changed: `gitleaks-scope` now defaults to `pr-commits` (issue #260)

Callers pick this up when they re-pin (callers pin a commit; re-pinning downstream repositories is separate work).

- **The default flips from `all-refs` to `pr-commits`.** A `pull_request` run now scans only the pull request's commits
  (`base..head`) plus the checked-out tree, so a key-shaped fixture on an unmerged branch no longer turns every other pull
  request red. A push (the default branch included), a schedule, a `workflow_dispatch` and every other event still scan the
  full history, so nothing entering the default branch is scanned less.
- **Opt back in** with `gitleaks-scope: all-refs` on the workflow call to keep the old every-ref scan on pull requests.
- **Unchanged:** the accepted values (`pr-commits`, `all-refs`; anything else fails the job), the base-commit configuration
  on a pull request, the canary, and the residuals listed under the `gitleaks-scope` entry below.

## v1.28.1 (2026-11-02)

### Fixed: workflow lint under `block` could not install pyflakes (issue #282)

Callers pick this up when they re-pin.

- **`tofu-ci.yml` and `arduino-ci.yml`** now allow exactly `pypi.org:443` and `files.pythonhosted.org:443` in the `allowed-endpoints` default. `raven-actions/actionlint` runs `pipx install pyflakes` when pyflakes is missing, and since v1.28.0 the secretless `workflow-lint` job runs `block`, which dropped the connection (`domain not allowed: pypi.org`) and failed the job after about 90 seconds. `python-ci.yml` and `bash-ci.yml` already had both hosts.
- **Callers need no change.** A tofu-ci caller that added `pypi.org:443 files.pythonhosted.org:443` to `extra-allowed-endpoints` for this can remove them. No job went back to `audit`, and no wildcard was added.
- **Guard.** `tests/test_workflows.py` fails if any reusable workflow that runs actionlint lacks the two hosts in its default.
- **`python-ci.yml` and `bash-ci.yml` `distro-allowed-endpoints`** gain `docker-images-prod.s3.dualstack.us-east-1.amazonaws.com:443`. The distro image pull (`docker run debian:13`) failed in hammunition-bunker PR 54 with `domain not allowed` for that host and then an i/o timeout on the layer download; the job was already `block` before v1.28.0. No wildcard. Docker's allowlist page (docs.docker.com/desktop/setup/allow-list/, modified 2026-09-29) lists `registry-1.docker.io`, `auth.docker.io` and `production.cloudfront.docker.com` (already present) but not this S3 host, so it rests on the measured log. A caller that added it to `extra-allowed-endpoints` can remove it.

## v1.28.0 (2026-11-02)

### Changed: secretless jobs run harden-runner `block` by default again (issue #278, security exception EX-0001 closed)

Callers pick this up when they re-pin.

- **`egress-policy-secretless` now defaults to `block`** (it was `audit` since 2026-10-24) in every reusable workflow that has the input: `agent-scan`, `arduino-ci`, `bash-ci`, `container-release`, `dast`, `python-ci`, `python-docker-release`, `python-fuzz`, `python-package-release`, `security`, `threat-model`, `tofu-ci` and `verify-published`. A caller that re-pins and sets nothing now runs its secretless jobs under the `block` allow-list, the same list that `egress-policy` uses. `distro-egress-policy` and `semgrep-egress-policy` already defaulted to `block` and are unchanged; `egress-policy` keeps its own defaults.
- **The pip, buildx and Arduino-package caches come back** in those jobs. The cache gates follow each job's effective policy, so they are on under `block` and off only for a caller that opts into `audit`.
- **Opt-out input.** The input stays. A caller that hits the westus2 symptom again sets `egress-policy-secretless: audit` on the workflow call. The exact-string policy check, the `github-hosted` runtime control and the fail-fast egress canary are unchanged.
- **Check allow-lists.** A caller whose secretless jobs reached a host that only the `audit` default let through (a private mirror, an installer its code pulls) needs it in `extra-allowed-endpoints`; a blocked connection shows in the job log as `domain not allowed: <host>`.

### Closed: security exception EX-0001 (westus2 harden-runner `block`)

- **Status is closed on 2026-11-02**, by the maintainer's decision, before the 2026-11-07 expiry. The record keeps its history and gains a "Closure" section.
- **Evidence.** A 600-job experiment on harden-runner v2.22.3 (the version pinned since v1.27.0; 150 jobs per arm over 3 runs): `block` passed 15 of 15 westus2 jobs and 135 of 135 on other regions; the control, `block` on v2.22.2, passed 137 of 137 on other regions and failed 13 of 13 on westus2, every one hung to the 10-minute timeout. Audit v2.22.3 and the no-tool arm passed. Runs: [41490712453](https://github.com/ChiefGyk3D/git-your-ship-together/actions/runs/41490712453), [41493344115](https://github.com/ChiefGyk3D/git-your-ship-together/actions/runs/41493344115), [41496006377](https://github.com/ChiefGyk3D/git-your-ship-together/actions/runs/41496006377).
- **Caveats.** The root cause is not shown, only the symptom is gone with v2.22.3. Two control arms hit westus2 only 5 and 8 times.
- This repository's own `ci.yml` jobs that call harden-runner directly stay `audit` (they were `audit` before the exception, with no measured allow-list), so their pip caches stay off.

### Changed: syft 1.56.0

- **syft 1.55.0 to 1.56.0** in `python-package-release.yml` (`syft-version` and `syft-sha256` defaults). The SHA-256 is the vendor checksums file's entry for the linux_amd64 tarball, and matches `sha256sum` of the downloaded asset. A caller that pins its own `syft-version` is unchanged.

## v1.27.0 (2026-11-02)

### Changed: pinned actions and tools bumped (issue #270, pull requests #271 and #273, release #274)

Callers pick these up when they re-pin.

- **harden-runner v2.22.3.** Fixes GitHub's DNS resolver and outbound proxy blocking connections that the allow-list permits, in `block` mode.
- **Actions:** setup-python 7.1.0, zizmor-action 0.8.0, docker/login-action 4.7.0, codeql-action 4.39.1.
- **Tools** (each checked against the vendor checksums): OpenTofu 1.13.2, tflint 0.65.0, OPA 1.22.0, Trivy 0.76.1, syft 1.55.0.
- **semgrep 1.183.0** in the `security.yml` scan, so callers get the new rules and fixes on re-pin. **mypy 2.4.1** in this repository's own `ci.yml` only; no caller sees it.
- **ruff default 0.17.3.** The `lint-install-command` default pins ruff 0.17.3, so a caller on the default now lints with 0.17.3. A caller that pins its own ruff is unchanged.

### New: `gitleaks-scope` input in `security.yml` (issue #260)

- **New input `gitleaks-scope`**, exactly `all-refs` (the default; behavior unchanged for every caller) or `pr-commits`.
  Before, the secret scan read every ref in the clone, so one key-shaped fixture on an unmerged branch turned the scan red on
  every other pull request in the repository.
- **With `pr-commits`**, a `pull_request` run scans the commits of the pull request (`base..head`) plus the checked-out tree.
  A push (the default branch included), a schedule, a `workflow_dispatch` and any other event scan every ref whatever the
  input says. The clone stays at full depth so both ends of the range are present.
- **Fails closed.** Any other value fails the gitleaks job, and so does a pull request whose base or head is not a full
  commit id present in the clone; the scan never quietly covers less.
- **Canary.** The planted-key check runs in both modes with the same command shape and argument list as the real scan (one list, built once by the resolve step), and, with `pr-commits`, also exercises the range form (real commit ids) and the tree scan the job will run.
- **Configuration comes from the base on a pull request (both scopes).** On a `pull_request` event the scan reads `.gitleaks.toml` and `.gitleaksignore` from the base commit, copied outside the workspace and passed explicitly, never from the pull request's own tree; a base with no `.gitleaks.toml` gets the scanner defaults; the canary uses the same configuration, so a config that hides the planted key fails it. **Compatibility:** a caller whose pull request changes either file sees the old version until it merges, and a base config that extends another file by relative path is not supported on a pull request. Push, schedule, `workflow_dispatch` and other events keep the checked-out file. This also applies to callers that leave `gitleaks-scope` at `all-refs`. Measured with the pinned binary: a `.gitleaksignore` at the root of the scanned tree applies even with an explicit ignore path (for both the `git` and the `dir` scan), so on a pull request that file in the throwaway checkout is replaced by the base's copy, or removed when the base has none; a change to either file also produces a warning.
- **Residual.** `pr-commits` does not cover a key already in the base history, a key on another unmerged branch, or a key that
  a merge-conflict resolution adds and a later commit removes; an empty range (only the tree scan then); tags and notes outside `base..head`; a workflow re-run (original payload); an inline `gitleaks:allow` comment in the pull request's own files (honored; not disabled, since that would fail legitimate allow comments); the generated SARIF file in the workspace during the tree scan; the merge-preview tree instead of the literal head tree. The README row and the wiki page state each case; protect `.gitleaks.toml` and `.gitleaksignore` with CODEOWNERS. The tree
  scan reports in the job log, with no SARIF upload.
- **Step names changed.** "Scan the full history (gitleaks)" is now "Scan the commits (gitleaks)". A caller that matches the
  step name should update it; job names are unchanged. Existing callers: nothing else changes unless they set the input.

### Changed: `wait-ci` rechecks the check runs right before the merge (issue #263)

- `scripts/wait-ci.sh --merge` re-reads the check runs on the pinned head immediately before the merge call and applies the same
  all-green rule again. A new or open check, or a red one, stops the merge (exit 6, or exit 1 for a red gate).
- The recheck now runs before every merge attempt, retries included, and also compares the check suite counts.
- **New option `--require-protection`.** Before merging, the script reads the base branch's required status checks (branch
  protection and rulesets) and a merge queue. Without the option it warns loudly when none cover the required contexts; with it,
  that is exit 1. The script is a second line only: the atomic guarantee is GitHub-enforced required checks or a merge queue.
- A required status check counts as coverage only when it is bound to the app whose check run the script evaluates, or to no app
  (or `--any-app` was given); one bound to a different app is a warning, and exit 1 under `--require-protection`.
- Bidirectional control characters in a check name are refused like other control characters and never printed.

### Changed: `wait-ci` requires every check run on the pinned commit, not only the gate (issue #259)

- **What changed.** After it pins the head SHA, `scripts/wait-ci.sh` (and the `wait-ci` action) now needs the named gate **and**
  every other check run on that commit to be complete and not red. Success, skipped and neutral pass. A check that is queued or in
  progress is waited for, within the existing `timeout` and `hung-after` and the existing `interval`; a completed run with no
  conclusion is waited for too. Before this, a gate could pass while a separate workflow (a security scan, say) was still running
  or had been missed.
- **New exit code 6, result `other-red`.** The gate held but another check run failed, was cancelled, timed out, needed action,
  failed to start or went stale. A failed gate is still exit 1. Callers that treat any non-zero exit as a refusal need no change;
  one that matches exit 1 for a red non-gate check must also match 6.
- **New optional inputs `allow-red` and `allow-red-reason`** (script: `--allow-red NAME`, repeatable, and `--allow-red-reason TEXT`).
  Empty by default. A named non-gate check may then be red. It is a recorded exception: the reason is required and printed, a
  required context cannot be listed, and an allowed check that is still open is still waited for.
- **Late checks.** New optional input `require-check` (script: `--require-check NAME`, repeatable): a further required check that must
  exist from the expected app and succeed; a missing one is waited for until `timeout` (exit 2), never green. Success is also
  returned only after two consecutive polls, one `interval` apart, read the identical set of check runs; a new check name
  between them restarts the wait. A green therefore takes one interval longer.
- **`allow-red` scoping.** `NAME@APP` matches the name and the reporting app's slug; a bare name matches that name from any app.
- **Same-named run from another app.** It is no longer ignored: it cannot satisfy the gate and is judged as an other check
  (red is exit 6, open is waited for). `--any-app` still counts it as the gate.
- **Control characters** in `allow-red`, `allow-red-reason`, `context` and `require-check` values are exit 64.
- **Reruns.** The latest run per check name and app decides (`filter=latest`); documented, with tests.
- **Tests.** `tests/test_wait_ci.py`: gate green with another check red (every failure conclusion), open (queued, in progress,
  waiting, pending), skipped and neutral, the allow-list and its misuse, a moved head, more than one page of runs, and two runs
  with the gate's name. Docs: [wait-ci](docs/wiki/Action-wait-ci.md).

## v1.26.0 (2026-10-30)

### New: `advanced-security` input in `security.yml` for a private repository without Advanced Security (issue #248)

- **New input `advanced-security`**, exactly `true` (the default, behavior unchanged for every caller) or `false`. A private
  repository without GitHub Advanced Security sets `advanced-security: false` once in its caller; without it the run fails.
  Observed on 2026-10-30 on such a repository: dependency review fails with "Dependency review is not supported on this repository. Please ensure that Dependency graph is enabled along with GitHub Advanced Security"; CodeQL, Semgrep and the gitleaks
  SARIF upload each fail with "Resource not accessible by integration".
- **With `false`:** dependency review and CodeQL are skipped by a job-level `if` (skipped, never failed; only the literal `false` skips); Semgrep and gitleaks run
  as before and still fail the job on a finding, but their SARIF uploads are skipped; both jobs write a job-summary note naming
  what was skipped and why.
- **Loud failure on a bad value.** One new always-running job, `advanced-security-check` ("Advanced Security setting":
  harden-runner, the egress canary, no checkout), fails the called workflow unless the value is exactly `true` or `false`. It is
  not a gate: no job has `needs`, so every scan runs exactly as before, even when the check job fails. A case variant such as
  `False` skips CodeQL and dependency review (GitHub compares strings case-insensitively), and the run is still red; any other bad value runs the scans and fails the check. The check job holds `permissions: {}`.
  Do not mask that red run: `continue-on-error` on the calling job, or an aggregator that treats a skipped or failed called
  workflow as success, hides it.
- **Job count: +1** (`advanced-security-check`). A caller that requires jobs by name is unaffected; the new job reports success when
  the value is valid.
- **Existing callers.** Nothing changes unless a caller sets the input.
- **Tests.** `tests/test_advanced_security.py` runs the validator against 26 invalid values, pins that no job has `needs`, the job
  conditions, pins that no job has `needs`, and runs the summary step under bash.

### New: Python 3.14 and 3.15 in the `python-ci.yml` matrix, and one list of supported Pythons (issue #242)

- **Changed default.** `python-versions` now defaults to `["3.11", "3.12", "3.13", "3.14", "3.15"]`. A caller that leaves it
  unset gains two `Test` jobs per runner on its next re-pin; a caller that sets it is unchanged. `actions/setup-python` v7.0.0
  (the pin used here) installs both: its manifest carries stable 3.14.10 and 3.15.2 for Linux x64 and arm64 on ubuntu 22.04,
  24.04 and 26.04 (read 2026-10-30).
- **One list.** `.github/python-support.json` holds the supported CPython versions with their bugfix and security end dates
  (3.11 to 2027-10-31, 3.12 to 2028-10-31, 3.13 to 2029-10-31, 3.14 to 2030-10-31, 3.15 to 2031-10-31; checked against
  devguide.python.org/versions, page dated 2026-05-27, which gives the month). `scripts/python_support.py` reads it
  (`--today` replaces the clock); `scripts/tool_locks.py` takes its newest minor from it; the workflow defaults, the README
  and `scripts/new-repo.sh` repeat it and `tests/test_python_support.py` holds them equal.
- **Expiry test.** The same test fails once a listed version is past its security end date (the clock is injected, so the
  cases are deterministic), so the matrix shrinks on schedule.
- **`new-repo.sh`.** The generated caller now lists versions up to 3.15 (and falls back to the five supported ones).
- **Not changed: the tool locks stop at 3.14.** Several locked packages have no 3.15 wheel yet (pyyaml 6.0.3, tree-sitter,
  fastuuid, onnxruntime, ruamel.yaml.clib and others), so `security.yml` and `agent-scan.yml` still support Python up to 3.14.
  A caller's own tests are unaffected: the fixture's hash-locked requirements all resolve on 3.14 and 3.15. Python 3.10, end of
  life since 2026-10-01, is still the floor of the pip-audit and Semgrep locks; it has a grace entry in the JSON that expires
  2026-11-30 and fails the test then, so the relock from 3.11 cannot be forgotten.

### Fix: trusted-ref gate hardening (issue #238)

- **Changed.** With `doppler-trusted-refs-only` on, only listed events can be trusted. The input
  accepts `true` or `false` in any casing; any other value fails the job instead of switching the gate off. A `vN.N.N` tag
  is also refused when a complete checkout shows its commit is not in the default branch's history (best effort; see the README).

### Changed (breaking default for cross-repo callers): `verify-published.yml` pins the signing certificate to a source repository (issue #186)

- **Changed.** `identity-regexp` can only name the reusable workflow, so any repository calling the same reusable workflow
  produced a certificate that matched. New optional input `source-repository` is passed to both `cosign verify` and
  `cosign verify-attestation` as `--certificate-github-workflow-repository`. It is shape-checked (`owner/name`) and passed
  through the environment, never interpolated.
- **Default.** The calling repository (`github.repository`). A caller verifying its own image changes nothing.
- **Breaking for cross-repo callers.** A caller that verifies an image built by another repository must set `source-repository`
  to that repository when it re-pins to this version, or verification fails. This repository's own fixture jobs already set it.

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

### Semgrep 1.181.0 (issue #240)

- **Changed.** The Semgrep lock moves from 1.180.0 to 1.181.0, relocked with `scripts/tool_locks.py --relock` (the
  `semgrep.overrides` still apply), so `semgrep.txt` and the lock inside `security.yml` change together. No transitive
  version moved. A caller that still sets the deprecated `semgrep-version` to a value other than `1.181.0` fails the install step.

### CI tooling requirements updated (issue #230)

- **Changed.** The Semgrep lock in `security.yml` now resolves with `.github/requirements/semgrep.overrides`, which
  replaces dependency versions the tool itself pins. `scripts/tool_locks.py --relock` reads the file and
  `tests/test_tool_locks.py` checks the lock holds each pin. Details are tracked privately.

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

## v1.25.1 (2026-10-25)

### The egress canary runs only on Linux (issue #196)

- **Fix.** The EX-0001 egress canary used `timeout` and `getent`, which macOS lacks (and `getent` is missing
  in Git Bash on Windows), so a macOS matrix leg failed with the misleading "known westus2 DNS issue"
  message. Every inlined copy now has `runner.os == 'Linux' &&` in its `if`, so the step is skipped on macOS
  and Windows runners. The canary is a diagnostic for harden-runner `block` on Linux, so no control is
  weakened. Callers re-pin to pick it up. `tests/test_egress_canary.py` fails if a canary lacks the condition.

## v1.25.0 (2026-10-25)

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
