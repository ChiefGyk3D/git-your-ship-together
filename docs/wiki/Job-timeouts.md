# Job timeouts: what each job normally takes and what caps it

Every job in this repository's workflows has an explicit time cap, set to a few times what the job normally takes. A job with no cap runs to GitHub's default of 360 minutes (`jobs.<job_id>.timeout-minutes`, "Default: 360", GitHub's workflow syntax reference, read 2026-11-09). Issue #247 is why this page exists: on 2026-10-30 fixture jobs finished their work in seconds, then sat idle for 20 to 35 minutes until a cap, and each one cost a re-run and about half an hour.

`tests/test_job_timeouts.py` holds the rule: every job has an integer cap (or an `inputs.<name>` expression whose input has an integer default), a calling job sets the called workflow's timeout input explicitly, and nothing is above 90 minutes without an entry and a reason in the test's `ALLOWED_ABOVE_MAX`. A `# normal: ~N min` comment sits above each cap in the workflow files.

## How the values were chosen

Measured on 2026-11-09 through the REST API: the durations of the successful jobs in the last 30 successful runs of `ci.yml` and `security-self.yml`, `wiki.yml` (30 each) and `dependabot-auto-merge-self.yml` (10), p50 and p95 per job name (nearest rank), and the longest run seen. `audit.yml` had no successful run to measure.

- **This repository's own jobs and its fixture calls:** cap = max(5, 3 x p95) rounded up to 5, 10, 15, 20, 30, 45 or 60, and never below the longest run seen plus 50%. A caller of a reusable workflow cannot put `timeout-minutes` on the calling job (GitHub rejects it); it passes the workflow's `timeout-minutes` input instead, which `ci.yml` now does for every fixture. Almost every fixture job takes under a minute, so the cap is 5; the Python CI fixture has one slow leg (an `ubuntu:24.04` distro job, p95 2.8, longest 4.8 minutes) and gets 10.
- **Reusable workflows' own defaults** (what a caller inherits when it passes nothing) were left alone: each already has a number, every one has a `timeout-minutes` input, and a caller's job can be much slower than the fixture. Raising a default would loosen a check, so none was raised. Defaults above max(4 x fixture p95, 30) are only the two container builds (60, multi-arch builds that compile native code); they stay.
- **Jobs that already had a cap** stayed unless far above 3 x p95: `actionlint`, `zizmor`, `fixture sbom`, `fixture ci-gate action` and `fixture classify action` (10, p95 under 1 minute) are now 5; `rescan fails when it should` (20, p95 1.5) is now 5; `dast fails when it should` (60, p95 9.2) is now 30. `Test the workflows` stays at 20, which is below 3 x p95 (48.6) and below the longest run plus 50% (24.9): see "Watch list".

## Measurements

Minutes. "Cap before" is the number the job ran under before this change (a fixture inherited the called workflow's default); "Cap now" is what the job runs under.

| Job (as shown in a run) | Runs | p50 | p95 | Max | Cap before | Cap now |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CI green | 30 | 0.2 | 0.4 | 1.2 | 5 | 5 |
| Test the workflows | 30 | 12.5 | 16.2 | 16.6 | 20 | 20 |
| actionlint | 30 | 0.3 | 0.6 | 0.6 | 10 | 5 |
| agent scan control | 29 | 0.2 | 0.3 | 0.3 | 5 | 5 |
| auto-merge / Dependabot auto-merge | 10 | 0.2 | 0.3 | 0.3 | 10 | 5 |
| changes | 14 | 0.2 | 0.4 | 0.4 | 5 | 5 |
| dast fails when it should | 29 | 8.6 | 9.2 | 9.3 | 60 | 30 |
| fixture / CI green | 29 | 0.3 | 0.4 | 0.4 | 15 | 10 |
| fixture / Changelog fragment | 17 | 0.3 | 0.9 | 0.9 | 15 | 10 |
| fixture / Commit claims | 17 | 0.3 | 0.5 | 0.5 | 15 | 10 |
| fixture / Container build | 29 | 0.6 | 1.2 | 2.9 | 15 | 10 |
| fixture / Distro (debian:12, ubuntu-24.04) | 29 | 0.7 | 0.9 | 1.8 | 15 | 10 |
| fixture / Distro (debian:12, ubuntu-24.04-arm) | 29 | 0.7 | 0.8 | 1.2 | 15 | 10 |
| fixture / Distro (debian:13, ubuntu-24.04) | 29 | 0.7 | 0.8 | 0.8 | 15 | 10 |
| fixture / Distro (debian:13, ubuntu-24.04-arm) | 29 | 0.7 | 0.9 | 1.7 | 15 | 10 |
| fixture / Distro (kalilinux/kali-rolling, ubuntu-24.04) | 29 | 0.7 | 1.0 | 1.1 | 15 | 10 |
| fixture / Distro (kalilinux/kali-rolling, ubuntu-24.04-arm) | 29 | 0.7 | 0.8 | 0.9 | 15 | 10 |
| fixture / Distro (parrotsec/core, ubuntu-24.04) | 29 | 0.8 | 0.9 | 0.9 | 15 | 10 |
| fixture / Distro (parrotsec/core, ubuntu-24.04-arm) | 29 | 0.8 | 0.9 | 1.0 | 15 | 10 |
| fixture / Distro (ubuntu:24.04, ubuntu-24.04) | 29 | 0.8 | 2.8 | 4.8 | 15 | 10 |
| fixture / Distro (ubuntu:24.04, ubuntu-24.04-arm) | 29 | 0.7 | 0.8 | 0.9 | 15 | 10 |
| fixture / Lint | 29 | 0.4 | 0.5 | 1.1 | 15 | 10 |
| fixture / Smoke test | 29 | 0.4 | 0.9 | 1.1 | 15 | 10 |
| fixture / Test (Python 3.11, ubuntu-24.04) | 29 | 0.5 | 0.7 | 0.7 | 15 | 10 |
| fixture / Test (Python 3.11, ubuntu-24.04-arm) | 29 | 0.5 | 0.7 | 0.7 | 15 | 10 |
| fixture / Test (Python 3.12, ubuntu-24.04) | 29 | 0.5 | 0.6 | 0.6 | 15 | 10 |
| fixture / Test (Python 3.12, ubuntu-24.04-arm) | 29 | 0.5 | 0.6 | 0.6 | 15 | 10 |
| fixture / Test (Python 3.13, ubuntu-24.04) | 29 | 0.5 | 0.8 | 1.5 | 15 | 10 |
| fixture / Test (Python 3.13, ubuntu-24.04-arm) | 29 | 0.5 | 0.6 | 0.7 | 15 | 10 |
| fixture / Test (Python 3.14, ubuntu-24.04) | 29 | 0.5 | 0.6 | 1.6 | 15 | 10 |
| fixture / Test (Python 3.14, ubuntu-24.04-arm) | 29 | 0.5 | 0.7 | 0.7 | 15 | 10 |
| fixture / Test (Python 3.15, ubuntu-24.04) | 29 | 0.6 | 0.7 | 0.7 | 15 | 10 |
| fixture / Test (Python 3.15, ubuntu-24.04-arm) | 29 | 0.5 | 0.7 | 0.8 | 15 | 10 |
| fixture / Type check | 29 | 0.4 | 0.6 | 0.7 | 15 | 10 |
| fixture / Workflow lint (actionlint, zizmor) | 29 | 0.6 | 0.8 | 1.1 | 15 | 10 |
| fixture agent scan (planted) / MCP tool scan | 29 | 0.8 | 1.0 | 1.0 | 15 | 5 |
| fixture agent scan (planted) / Skill scan | 29 | 0.9 | 1.1 | 2.0 | 15 | 5 |
| fixture agent scan / MCP tool scan | 29 | 0.8 | 0.9 | 1.1 | 15 | 5 |
| fixture agent scan / Skill scan | 29 | 0.9 | 1.1 | 1.5 | 15 | 5 |
| fixture artifact / Build, verify | 29 | 0.3 | 0.5 | 0.9 | 30 | 5 |
| fixture base image / Base images are as fresh as their tags | 29 | 0.5 | 0.9 | 1.2 | 20 | 5 |
| fixture ci-gate action | 29 | 0.2 | 0.3 | 0.3 | 10 | 5 |
| fixture classify action | 29 | 0.2 | 0.4 | 0.8 | 10 | 5 |
| fixture dast / Upload SARIF | 29 | 0.4 | 0.6 | 0.6 | 20 | 5 |
| fixture dast / ZAP baseline scan | 29 | 1.1 | 1.4 | 1.4 | 20 | 5 |
| fixture docs pages / Build the site | 29 | 0.4 | 0.5 | 0.9 | 10 | 5 |
| fixture drift / Vendored files match their pins | 29 | 0.3 | 0.5 | 0.9 | 10 | 5 |
| fixture firmware / CI green | 29 | 0.3 | 0.4 | 0.4 | 30 | 5 |
| fixture firmware / Compile (arduino:avr:uno) | 29 | 0.6 | 0.7 | 0.8 | 30 | 5 |
| fixture fuzz / Fuzz | 29 | 0.5 | 0.7 | 1.1 | 30 | 5 |
| fixture gate / CI green | 29 | 0.3 | 0.3 | 0.4 | 5 | 5 (fixed in callee) |
| fixture package / Build, check, smoke-test | 29 | 0.6 | 0.9 | 1.0 | 20 | 5 |
| fixture parallel / Build | 29 | 0.3 | 0.5 | 1.0 | 15 | 5 |
| fixture parallel / CI green | 29 | 0.3 | 0.4 | 0.4 | 15 | 5 |
| fixture parallel / Choose the checks | 29 | 0.3 | 0.5 | 0.5 | 15 | 5 |
| fixture parallel / code only | 29 | 0.3 | 0.5 | 0.5 | 15 | 5 |
| fixture parallel / pip cache | 29 | 0.3 | 0.5 | 0.5 | 15 | 5 |
| fixture parallel / second output | 29 | 0.3 | 0.5 | 0.5 | 15 | 5 |
| fixture parallel / site exists | 29 | 0.3 | 0.5 | 0.5 | 15 | 5 |
| fixture parallel / tool on path | 29 | 0.3 | 0.5 | 0.7 | 15 | 5 |
| fixture pin comments / Version comments match their pins | 18 | 0.5 | 0.6 | 0.6 | 10 | 5 |
| fixture project sync / Sync project | 29 | 0.4 | 0.6 | 0.9 | 15 | 5 |
| fixture release / release / Build, test, scan, local (linux/amd64) | 29 | 1.1 | 1.3 | 1.3 | 60 | 5 |
| fixture release / release / Build, test, scan, local (linux/arm64) | 29 | 1.1 | 1.2 | 1.3 | 60 | 5 |
| fixture release / release / Lint the Dockerfile (hadolint) | 29 | 0.3 | 0.6 | 1.0 | 60 | 5 |
| fixture release / release / Plan the build | 29 | 0.2 | 0.3 | 0.3 | 60 | 5 |
| fixture repin / Re-pin | 14 | 0.3 | 0.5 | 0.5 | 10 | 5 |
| fixture rescan / Rescan for new advisories | 29 | 0.5 | 0.7 | 0.9 | 20 | 5 |
| fixture rescan / Verified | 29 | 0.3 | 0.4 | 0.5 | 20 | 5 |
| fixture rescan / Verify ghcr.io/chiefgyk3d/star-daemon:latest | 29 | 0.5 | 0.7 | 0.7 | 20 | 5 |
| fixture sbom | 29 | 0.4 | 0.5 | 0.6 | 10 | 5 |
| fixture shell / CI green | 29 | 0.3 | 0.5 | 1.3 | 10 | 5 |
| fixture shell / Changelog fragment | 17 | 0.3 | 0.9 | 0.9 | 10 | 5 |
| fixture shell / Commit claims | 17 | 0.3 | 0.9 | 0.9 | 10 | 5 |
| fixture shell / Config lint | 29 | 0.4 | 1.0 | 1.0 | 10 | 5 |
| fixture shell / Distro (debian:13, ubuntu-24.04) | 29 | 0.5 | 0.6 | 0.6 | 10 | 5 |
| fixture shell / Distro (debian:13, ubuntu-24.04-arm) | 29 | 0.5 | 0.6 | 0.8 | 10 | 5 |
| fixture shell / Distro (kalilinux/kali-rolling, ubuntu-24.04) | 29 | 0.5 | 0.6 | 0.7 | 10 | 5 |
| fixture shell / Distro (kalilinux/kali-rolling, ubuntu-24.04-arm) | 29 | 0.5 | 0.6 | 0.6 | 10 | 5 |
| fixture shell / Test (ubuntu-24.04) | 29 | 0.3 | 0.5 | 0.5 | 10 | 5 |
| fixture shell / Test (ubuntu-24.04-arm) | 29 | 0.3 | 0.5 | 0.5 | 10 | 5 |
| fixture shell / shellcheck | 29 | 0.3 | 0.5 | 0.9 | 10 | 5 |
| fixture shell / shfmt | 29 | 0.3 | 0.5 | 0.5 | 10 | 5 |
| fixture threat model / Threat model | 29 | 0.3 | 0.4 | 1.4 | 10 | 5 |
| fixture tofu / CI green | 29 | 0.3 | 0.4 | 0.5 | 16 | 5 |
| fixture tofu / Configuration scan (Trivy) | 29 | 0.4 | 0.5 | 0.6 | 16 | 5 |
| fixture tofu / fmt | 29 | 0.3 | 0.5 | 0.9 | 16 | 5 |
| fixture tofu / policy (OPA) | 29 | 0.3 | 0.5 | 1.0 | 16 | 5 |
| fixture tofu / test (fixture/tofu) | 29 | 0.3 | 0.5 | 0.9 | 16 | 5 |
| fixture tofu / test directories | 29 | 0.3 | 0.4 | 0.9 | 16 | 5 |
| fixture tofu / tflint | 29 | 0.3 | 0.5 | 0.5 | 16 | 5 |
| fixture tofu / validate | 29 | 0.3 | 0.9 | 0.9 | 16 | 5 |
| fixture token drift (live) / Vendored file matches its pin and its source | 8 | 0.3 | 0.9 | 0.9 | 10 | 5 |
| fixture token drift (planted live) / Vendored file matches its pin and its source | 8 | 0.3 | 0.5 | 0.5 | 10 | 5 |
| fixture token drift (planted pin) / Vendored file matches its pin and its source | 8 | 0.3 | 1.0 | 1.0 | 10 | 5 |
| fixture token drift / Vendored file matches its pin and its source | 8 | 0.3 | 1.2 | 1.2 | 10 | 5 |
| fixture verify / Verified | 29 | 0.3 | 0.4 | 1.2 | 20 | 5 |
| fixture verify / Verify ghcr.io/chiefgyk3d/star-daemon:latest | 29 | 0.9 | 1.2 | 1.5 | 20 | 5 |
| fixture wiki / Generate the wiki pages | 29 | 0.3 | 0.5 | 0.5 | 10 | 5 |
| rescan fails when it should | 29 | 0.9 | 1.5 | 1.7 | 20 | 5 |
| security / Advanced Security setting | 30 | 0.3 | 0.9 | 1.0 | 15 | 10 |
| security / CodeQL | 30 | 1.2 | 2.1 | 2.5 | 15 | 10 |
| security / Dependency audit | 30 | 0.7 | 1.1 | 1.7 | 15 | 10 |
| security / Dependency review | 19 | 0.3 | 0.9 | 0.9 | 15 | 10 |
| security / OpenSSF Scorecard | 11 | 1.0 | 1.6 | 1.6 | 15 | 10 |
| security / Secret scan (gitleaks) | 30 | 0.5 | 0.7 | 1.0 | 15 | 10 |
| security / Semgrep | 30 | 0.8 | 1.0 | 1.8 | 15 | 10 |
| token drift control | 8 | 0.2 | 0.3 | 0.3 | 5 | 5 |
| wiki / Generate the wiki pages | 30 | 0.5 | 0.7 | 1.1 | 10 | 5 |
| wiki / Publish to the wiki | 30 | 0.3 | 0.9 | 0.9 | 10 | 5 |
| zizmor | 30 | 0.3 | 0.5 | 0.5 | 10 | 5 |

## Watch list

- **`Test the workflows`** takes 12.5 minutes at p50 and 16.6 at the longest of 30 runs, under a cap of 20. That is about 20% of headroom, less than the 50% the rule asks for. It was left at 20 because lowering is not the question and raising a cap is a decision of its own; if a run is cancelled at 20, split the suite or measure again before raising it.
- **No fixture history.** These jobs have a cap (an input default or a fixed number) but no measured run, so their `# normal:` comment says so: `audit.yml` (`audit` 15, `register-issues` 10), the `build` job of `container-release.yml` (the fixture uses `build-local`), `merge` in `container-release.yml` (15), the upload jobs in `agent-scan.yml` (10), `arduino-ci.yml` `test` and `workflow-lint`, `artifact-release.yml` `publish`, `bash-ci.yml` and `python-ci.yml` and `tofu-ci.yml` `workflow-lint`, `docs-pages.yml` `deploy`, `lory-audit.yml`, `python-ci.yml` `coverage`, `python-package-release.yml` `github-release` and `pypi-unsupported`, `security.yml` `snyk`, `tofu-ci.yml` `plan`, and `verify-published.yml` `verify-release`. Measure them when a caller runs them, then tighten.
- **Callers can lower or raise a cap.** Every reusable workflow has a `timeout-minutes` input (`parallel-ci.yml` has `build-timeout-minutes`, and a `timeout` per check in its JSON plan).

## Do the hangs follow the post-job steps?

No. Runs 41035462015 (main) and 41065673856 (pull request #243), job `fixture artifact / Build, verify`, were read from the job logs (`gh api --allow-escape-sequences .../actions/jobs/<id>/logs`):

| Attempt | Job | Started | Last log line | Cancelled |
| --- | --- | --- | --- | --- |
| 1 of 41035462015 | 123995083113 | 09:43:30Z | 09:43:48Z `Cleaning up orphan processes` | 10:18:31Z (35 minutes) |
| 1 of 41065673856 | 124096301311 | 13:44:08Z | 13:44:30Z `Cleaning up orphan processes` | 14:19:09Z (35 minutes) |

In both, every step ran to its end in about 20 seconds: the Upload artifact step (first run: finalized and "successfully uploaded"), the `Post job cleanup` of checkout, the harden-runner post-step (`[harden-runner] post-step` printed its agent log), then the runner's own `Evaluate and set job outputs` and `Cleaning up orphan processes`. Nothing in the log follows that line, and the job was still reported as running until it was cancelled 35 minutes after it started. The second run's job had also failed on the egress canary (`egress broken on this runner (known westus2 DNS issue, EX-0001): rerun the job`), and hung the same way after its post steps, so the hang does not depend on the job passing. So the runner finished and the job's completion was never recorded: the stall is after the last step, not in harden-runner's post step or the artifact upload. A cap cannot prevent that; it can only shorten it. The cap on the job was 30 minutes and the cancellation came at 35 (the extra 5 is not in the logs; it fits a cancellation grace period, which is unverified). Under a 5 minute cap the same hang costs about 10.

## Did the docs-only gating (#362) change run time?

Measured 2026-11-09, REST only. Docs-only means every file in the pull request matches the `changes` job's docs-only patterns and none its never-skip list. The run is the `CI` workflow's successful `pull_request` run on the head commit; duration is `run_started_at` to `updated_at`, which includes a re-run when there was one.

| Group | Pull requests | Median run duration | Median check runs on the head commit |
| --- | ---: | ---: | ---: |
| Before 6602f83 (15 most recent) | #339, #338, #332, #299, #295, #287, #275, #257, #252, #147, #142, #134, #128, #75, #20 | 10.4 minutes | 113 |
| After 6602f83 | #369 only | 15.4 minutes | 46 |

The gating works on the part it was built for: a docs-only pull request now carries 46 check runs, not 113, because the fixture jobs leave the run. The effect on duration cannot be measured yet: only one docs-only pull request has merged since (the change landed on 2026-11-09 at 03:02Z), and its run was longer, not shorter. The run is bounded by the jobs gating never skips, mainly `Test the workflows` (12.5 minutes at p50), so removing the fixtures saves runner minutes and check noise rather than wall-clock time. Measure again once about 15 docs-only pull requests have merged since.
