# CI runner hangs and refused connections, 2026-10-22 to 2026-10-24

Issue: ChiefGyk3D/git-your-ship-together#189. Evidence window: runs created in the last 7 days
as of 2026-10-24 22:30 UTC. Everything below was collected with read-only `gh api` calls; the scripts
and raw data are kept in the research tmp directory (`collect.py`, `stats.py`, `loganalysis.py`,
`drops.py`, `ipcheck.py`, `regions.py`, `waste.py`, `p99.py`, `exp*.py`). Log text and issue text were
treated as data only.

## Verdict

The top hypothesis, with strong but not yet controlled evidence:

**H1: jobs that land on GitHub-hosted runners in Azure region `westus2` break when
step-security/harden-runner is active, because GitHub is changing DNS on those runners (an
"egress DNS resolver" experiment) and harden-runner's DNS-derived IP allow-list then drops
connections to GitHub's own service IPs.** The refusals are IP-level: `github.com:443`,
`api.github.com:443` and the Actions results service are all permitted by name, yet connections
are refused in 2 to 10 ms because the IP the process used is not the IP the agent recorded.

Status: **correlation is near-perfect, mechanism is documented upstream, but no controlled
experiment has isolated it.** It is unproven that any configuration (block, audit, newer pin, no
harden-runner) avoids it on `westus2`, because none of our control arms has landed on `westus2`
in a clean arrangement (see "Experiment flaw" below).

### Evidence for H1

1. Region split in retrievable logs (151 job logs: every hung job whose log still exists, plus
   random samples of green and red jobs from the last 8 hours of 2026-10-24):

   | Region | hung or refused/dropped | clean |
   |---|---|---|
   | `westus2` | 56 | 3 |
   | all other regions (eleven of them) | 0 | 92 |

   The three clean `westus2` jobs are short ones (`CI green` twice, `zizmor`). Selection caveat:
   hung jobs whose logs are gone (404) are not in this sample, see H2.
2. Log signature in every failed or hung `westus2` job: the agent prints
   `ip address dropped: <ip>` for IPs that were never recorded for the allowed name, with
   `endpoint called ... domain: ,` (empty domain) for the same IP. Examples from the listed runs:
   - Reach-Around job 120998092788 (run 40136189408, `Type check`, `westus2`):
     `git-remote-http` connected to 140.82.116.3, the agent had recorded github.com as
     20.29.134.23 only. checkout failed three times with
     `Failed to connect to github.com port 443 after 6 ms` and then `exit code 128` (symptom b).
     `Runner.Worker` was also dropped on 140.82.113.22, which is
     `results-receiver.actions.githubusercontent.com`. The runner reports step and job status to
     that service, so a refused connection leaves steps shown `in_progress` after the work
     finished (symptom a).
   - Reach-Around job 120996165865 (run 40135541827, `Smoke test`, `westus2`): the API shows
     checkout `in_progress` and setup-python `pending` although "Install the project" and the smoke
     test ran and the job log ends 14 s after start. `node` calls to 140.82.112.22 (cache and
     results service) were dropped, which is the setup-python
     `Failed to GetCacheEntryDownloadURL: ECONNREFUSED` (symptom f); python3.13 connections to
     Fastly IPs 151.101.{64,128,192}.223 were dropped while only 151.101.0.223 was recorded for
     pypi.org.
   - Reach-Around job 120998935451 (run 40136204670, `CI green`, `westus2`): all steps done but
     `Post Run step-security/harden-runner` stays `in_progress` while `Complete job` is
     `success`; cancelled at exactly 600 s (symptom c). Status updates to the results service were
     lost the same way.
   - The new upload-artifact failure (`Failed to CreateArtifact: Unable to make request:
     ECONNREFUSED`) appears in the rca-experiment run 40138458010 job 121004921251 (`westus2`),
     with `ip address dropped: 140.82.114.21`, the results service again.
   - Symptom d: Container build job 120998609243 failed in `Build image` with
     `dial tcp 140.82.113.22:443: connect: connection refused` to `results-receiver` (buildx
     `type=gha` cache). That job was in `westus3`, so H1 does not explain it alone (see below).
3. Every affected job's agent log shows `ip address dropped: 168.63.129.16` for `systemd-resolved`
   (Azure DNS, port 53): systemd-resolved is still talking to Azure DNS directly instead of through
   harden-runner's proxy. That is the same line reported upstream for `westus2`.
4. Upstream, same signature, same region:
   - step-security/harden-runner#708 (open, 2026-10-23): on `westus2` runners in block mode the
     agent records one A record per allowed domain and drops connections to the other IPs,
     giving ECONNREFUSED to allowed hosts. Reruns pass. Also shows the `168.63.129.16` drop. A
     commenter reports only switching block to audit got CI unstuck; StepSecurity's CEO replies
     it is related to DNS changes GitHub is experimenting with in `westus2` and that they are
     "in direct conversation with GitHub".
   - harden-runner#705 and actions/runner-images#14925 (open): since 2026-10-12 `westus2`
     hosted runners run an `egress-dns-resolver.service` (an "Actions egress proxy DNS resolver")
     that holds `127.0.0.1:53`. GitHub's maintainer states: "an experiment we're running on some of
     our hosted runners"; a first fix moved the resolver to `127.0.0.100:53` (2026-10-13) and the
     experiment was resumed. StepSecurity (2026-10-15) reports a remaining interaction: DNS queries
     are observed but responses are not captured, so connections to allowed IPs stay blocked.
5. Timeline: zero hung jobs before 2026-10-21, one on 10-21, 22 on 10-22 (mostly Clouds Against
   Humanity `Semgrep`), 5 on 10-23, 62 on 10-24 (55 of them Reach-Around, which ran 1649 jobs that
   day). That matches "since the afternoon" for Reach-Around only because that repo had the load.

### Evidence against, or not explained

- Not every failure is `westus2`: the `Build image` refusal was `westus3` with one dropped IP
  (3.217.73.113 and 140.82.113.22 via `buildkitd`); the sample is small. The experiment run also
  had `harden-runner` pre-step ECONNREFUSED on cache URL in the failing jobs. An alternative or
  second cause on other regions is possible but not demonstrated by any log I could retrieve.
- Hung jobs whose logs return 404 cannot be region-checked. H2 below says this is a different
  mechanism; the count of such jobs is unknown.
- Sample-size caution: only 3 clean `westus2` logs exist, so "P(hang | westus2)" is roughly 95
  percent in our sample and could be lower (clean short jobs are over-represented in the sample
  of green jobs only by chance; I did not stratify).
- harden-runner v0.17.0 agent (v2.22.1 and v2.22.2) was also seen on `westus2` hung jobs (5 of
  57), so upgrading the pin is not shown to fix it.

### Experiment flaw in `rca-experiment` (run 40138458010)

The workflow gates each harden-runner step with a step-level `if:`. The action's `pre:` hook does
not honor the step `if`, so every job, including the "off" arm, ran three harden-runner pre-steps
(v2.21.1 block, v2.22.1 block, and the arm's own) and started agents; the logs show
`pre-step` x3, `main-step` x1 (x0 in "off"), `post-step` x3 in all four arms. So:

- "off" was not off, and the "audit" arm jobs also had two block-mode agents (their logs say
  `egress-policy: block` twice before `audit`).
- All three `westus2` jobs landed in the audit arm and all failed or hung; none of the 45 block or
  "off" jobs landed on `westus2`. The results `block 30/30`, `off 15/15` therefore say nothing about
  those modes on `westus2`; they only show that other regions are healthy.
- To test properly, gate at job level (`if:` on the job, or separate workflow files or a reusable
  workflow with an input) so a skipped harden-runner never reaches its pre-step.

## Other hypotheses, ranked

| # | Hypothesis | For | Against | Falsified by |
|---|---|---|---|---|
| H1 | `westus2` DNS experiment x harden-runner IP allow-list (above) | 56/56 retrievable hung jobs in `westus2`, 0/92 elsewhere; matches #708/#705/#14925 | no controlled arm; `westus3` Build image case | A clean arm (below) where `westus2` jobs with NO harden-runner also hang, or where harden-runner jobs on `westus2` pass |
| H2 | harden-runner audit-mode memory growth (#709, open, 2026-10-24): agent RSS to ~13 GiB, runner worker unresponsive, step timeouts never fire, `if: always()` never run, logs 404, job ends only at job timeout; reproduced on v2.19.4 and v2.22.2 | explains log-404 hung jobs; hung runs end at the job timeout | the reported workload is a 940-test, process-heavy suite; ours are 20 to 60 s jobs; our hung jobs with logs all show the DNS signature | `free -m` / `ps` sampling in a job (watchdog) shows `agent` RSS flat on a hung job |
| H3 | GitHub-side Actions service degradation (status page said operational) | queue waits to 3 minutes on 10-24 17:00 to 21:00 (git-your-ship-together 40114026296, 40112986884) | queue p50 is 3 s for every repo; long queues cluster on large fan-out runs (burst of ~15 jobs) | Queue waits do not correlate with region or burst size |
| H4 | `block` allow-list missing an endpoint | -- | `github.com:443`, `api.github.com:443`, `ghcr.io`, etc. are all listed and still refused; what is refused is an IP, and the resolver names (`results-receiver.actions.githubusercontent.com`) are auto-allowed on good runs | An `allowed-endpoints` addition removing refusals on `westus2` |
| H5 | Pin staleness: GYST pins harden-runner v2.21.1 (`e14015d5...`, agent v0.16.3), v2.22.2 is out (2026-10-19) | newer agent has "improved network and DNS tracing, enforcement logic" (enterprise-tier note) | v0.17.0 agents also hung on `westus2` | Hang rate on `westus2` with v2.22.2 equals v2.21.1 |

Symptom (e), jobs queued for minutes: 19 Reach-Around job-starts waited over 60 s (max 119 s) and
the largest GYST queue waits were 214 s, all on bursts of 7 to 17 jobs. Median queue is 3 s in every
repo. This is not tied to hangs and is not explained by H1; treat as unproven capacity noise.

## Numbers

Collected: 1525 workflow runs, 9938 job rows, seven repos: Reach-Around, git-your-ship-together,
Clouds-Against-Humanity, scrum-around-and-find-out, Stream-Daemon, typo-sniper, ProjectPlus-Without-The-Bullshit. The script `stats.py` prints per repo and
job the median, p95, p99, max, conclusion mix, queue wait; `p99.py` the healthy-body percentiles.

Healthy-job duration, seconds (success and not hung): median / p95 / p99

| Job | n | median | p95 | p99 |
|---|---|---|---|---|
| Lint | 475 | 21 | 31 | 40 |
| Type check | 169 | 32 | 40 | 46 |
| Workflow lint | 463 | 24 | 33 | 48 |
| Smoke test | 174 | 24 | 32 | 37 |
| Python test (3.11 to 3.13) | ~380 | 58 to 65 | 89 to 96 | 92 to 97 |
| Container build | 116 | 43 | 83 | 154 |
| CI green | 1121 | 10 | 17 | 18 |
| CodeQL | 374 | 57 | 103 | 111 |
| Semgrep | 359 | 45 | 55 | 61 |
| Secret scan | 339 | 24 | 30 | 35 |
| OpenTofu `test` | 299 | 257 | 293 | 305 |
| tofu fmt / validate / tflint / policy | ~305 each | 15 to 76 | 21 to 88 | 23 to 104 |
| Wiki generate / publish | 260 / 70 | 17 | 22 / 23 | 24 / 27 |

Rows with large p99/max in the raw output (for example `Lint` max 918 s, `Smoke test` 728 s) are
jobs that stalled and later recovered; they are in `stats_out.txt` and were excluded from the sizing
above only where marked "healthy".

Hangs (completed job with a step still `in_progress` or `pending`, wall time over 5 minutes):

| UTC day | hung jobs | actual runner minutes | at 35 min each |
|---|---|---|---|
| 2026-10-21 | 1 | 35 | 35 |
| 2026-10-22 | 22 | 653 | 770 |
| 2026-10-23 | 5 | 165 | 175 |
| 2026-10-24 | 62 | 1779 | 2170 |

Over 10-22 to 10-24: **89 hung jobs, 2597 actual runner-minutes (43.3 h); 3115 minutes (51.9 h) at 35 min
each**. The 35 comes from the `timeout-minutes` input (default 30 in `python-ci.yml`, same default
in `security.yml`, `wiki-publish.yml`) plus GitHub's 5 minute cancel grace: observed hung durations
cluster at exactly 600 s (5 min `CI green` timeout), 1500 s (20 min callers) and 2100 s (30 min). By
repo: Reach-Around 55 (all 10-24), Clouds-Against-Humanity 13 (11 on 10-22), scrum-around-and-find-out 14,
git-your-ship-together 3, ProjectPlus 3, Stream-Daemon 2, typo-sniper 0. Per-day job totals are in `waste.py` output; the hung share of Reach-Around
10-24 jobs is about 3.3 percent (55 of 1649). The coordinator's figure of 18 hung of 515 for a
shorter window is consistent.

Because the hang is bounded only by the job timeout, a smaller timeout is the lever that cuts waste
now: with the patch below a stuck 15-minute-timeout job costs 20 minutes instead of 35.

harden-runner pins: all GYST reusable workflows pin v2.21.1 `e14015d583714f6e62063499dc959a02595150a1`
(72 uses; agent v0.16.3 in the logs). Reach-Around and scrum-around `ci.yml`/`live-audit.yml` pin
v2.22.1 `ccd8616d44fd3846e67624a50d5aad6d37bf2d25`. Newest release: v2.22.2 (2026-10-19). Egress
mode is `block` in every hardened workflow checked (Reach-Around, scrum-around-and-find-out, Stream
Daemon, typo-sniper, ProjectPlus); the `distro` job has its own policy input. Hardened jobs all use
setup-python with `cache: pip`; Worker tests in Reach-Around (no harden-runner) had 0 failures in 157
jobs and 0 hung. Clouds-Against-Humanity callers do not set `egress-policy` in the caller.

Upstream release notes (v2.19.0 through v2.22.2) mention no fix for any of this. v2.21.1 notes: "Fixes new runner
endpoints not implicitly allowed in block mode". v2.22.2: "Improved network and DNS tracing,
enforcement logic, and process information correlation on Linux (enterprise tier)". Relevant open
issues: #705, #708, #709; closed #679 ("egress-policy: block causes hosted-runner reclamation on long
jobs", ~44 percent at 10 to 14 min, reported in August; a different symptom, long jobs only). I could
not read actions/runner or actions/cache issues beyond what search surfaced; nothing matching was found
there.

## What the issues prove and do not prove for us

Proved by upstream: GitHub runs a DNS experiment on `westus2`; harden-runner in block mode on
those runners drops allowed IPs; the same drop line and the same `168.63.129.16` line appear in our logs.

Not proved: that our `westus2` hangs are caused by that interaction (no controlled arm); that audit
mode helps (our own audit-arm jobs on `westus2` failed, and #709 says audit mode can exhaust memory);
that v2.22.2 helps; that `westus3` or other-region failures share the cause; that H2 applies (no
memory sampling in our jobs).

## Experiments for the maintainer's lead

Run these by `workflow_dispatch` on a throwaway branch of Reach-Around. Print the region first (the
`Region:` line in "Runner Image Provisioner" of each job log is enough) and tabulate (region, arm,
outcome) from logs afterwards with `regions.py` as a template. `westus2` landings are a minority (a few
percent of jobs), so use `strategy.matrix` with 60 or more entries per arm; each entry is cheap (about 20 s).

| ID | Change | Confirms H1 if | Falsifies H1 if |
|---|---|---|---|
| E1 | Four job-level arms (job `if:` or separate jobs, never step `if:`): no harden-runner; block v2.21.1; block v2.22.2; audit v2.22.2. Each job: checkout, setup-python `cache: pip`, `pip install`, `actions/upload-artifact`, print `Region` | `westus2` fails only in harden-runner arms; "no harden-runner" passes on `westus2` | `westus2` also fails with no harden-runner |
| E2 | Same as E1 with `allowed-endpoints` unchanged but add `results-receiver.actions.githubusercontent.com:443` and `pipelines.actions.githubusercontent.com:443` | still fails on `westus2` (allow-list contents are not the issue; the IP is) | passes on `westus2` (then allow-list names were the gap) |
| E3 | In a westus2 job, a first step (before harden-runner) that records `resolvectl status`, `ss -lunp \| grep :53`, `getent ahosts github.com results-receiver.actions.githubusercontent.com` twice 10 s apart | A resolver on `127.0.0.100:53` or `egress-dns-resolver` present, and A records differ between calls | no resolver difference between regions |
| E4 | E1 `block` arm with a memory watchdog step (`free -m; ps -eo rss,comm --sort=-rss \| head -3` every 20 s) | agent RSS stays flat on hung `westus2` jobs (rules out H2) | RSS climbs to GiB scale (then H2 is real) |
| E5 | Worker-style no-harden jobs only, 100 repeats, record region and duration | confirms the control: unhardened jobs never hang on `westus2` | an unhardened job hangs on `westus2` |
| E6 | Re-run only the failed jobs of a hung run until all land outside `westus2` | reruns on non-`westus2` pass 100 percent (matches #708) | reruns fail outside `westus2` |

## Remediation ladder

Keep block mode unless step 5 is invoked and signed.

1. **Cap the cost now (no security change).** Apply the timeout patch: `proposed-timeouts.patch`.
   Defaults drop to python-ci 15, bash-ci 10, tofu-ci 10, security 15, docs-pages 10, wiki-publish 10
   minutes (measured healthy p99 is 18 to 305 s, so each is at least 3x the slowest healthy p99,
   and about 8x for most jobs). Cost of a stuck job: timeout plus 5 minutes grace.
   The `ci-green` aggregate jobs already have 5 minutes. Callers with long jobs set their own
   `timeout-minutes` as before. The README/wiki tables that list the old defaults need updating.
2. **Report upstream with evidence.** Add our run and job IDs, the `Region: westus2` lines, and the
   dropped-IP lines to step-security/harden-runner#708 and GitHub's actions/runner-images#14925;
   open a GitHub Support ticket for the `westus2` egress-DNS experiment.
3. **Run E1 to E6** (above) to turn H1 from correlation into a result. Until then, nothing here is a
   confirmed root cause.
4. **Hygiene (not a fix):** bump the GYST pin to v2.22.2 (`dc2769abcc0fcfbadfc1df54081c1608579ef6b2`,
   per #708/#709) in a normal re-pin PR with the `# v2.22.2` comment, and re-pin all callers.
5. **Only if E1 shows harden-runner is required to trigger the failure and upstream has no fix date**
   (see exception template). Do not set `audit` as the default: our audit-arm jobs on `westus2` failed
   too, and #709 documents a separate audit-mode memory problem.
6. **Do not** loosen the allow-list for this: names are already permitted, and the refusals are per IP.
   If E2 proves a name gap, the only candidates are `results-receiver.actions.githubusercontent.com:443`
   and `pipelines.actions.githubusercontent.com:443`, plus the `productionresultssa*.blob.core.windows.net`
   family the agent already auto-adds.

### Security exception template (use only for step 5)

```
Exception ID: SE-2026-10-GYST-189
Control relaxed: harden-runner egress-policy block on <list of jobs>; changed to <audit | removed>
Why: step-security/harden-runner#708 and actions/runner-images#14925; <E1 run link> shows
  jobs on westus2 hang or lose connectivity to GitHub service IPs with block mode and not without it.
  Observed cost: <N> hung jobs, <M> runner-minutes in <window> (current: 89 jobs, 2597 min in 3 days).
Scope: only these jobs: <names>, only in these repositories: <names>. Not the release, publish,
  sign or secret-bearing jobs. Not `security.yml` jobs that hold tokens.
Compensating controls: jobs run with no repository secrets and `permissions: contents: read`;
  workflow SHA-pinning and zizmor stay on; the global block list (harden-runner v2.19.0+) stays
  active in audit mode; `disable-sudo` stays on; the egress log from the audit run is reviewed per
  week against the previous block-mode allow-list and any new destination opens an issue.
Owner: ChiefGyk3D.
Expiry and revisit trigger: expires 2026-11-24 or when #708 or runner-images#14925 closes, whichever
  is first; re-run E1 on each upstream release; revert at the first clean E1 result on westus2.
Approval: <date and link to approval comment on #189>.
```

## Proposed timeout patch

`proposed-timeouts.patch` (unified diff against the checked-out tree; apply with `patch -p1` from
the repo root after stripping `a/` and `b/`, which is what `-p1` does). It changes only the
`timeout-minutes` input defaults of six reusable workflows:

| Workflow | old | new | slowest healthy p99 (s) |
|---|---|---|---|
| `python-ci.yml` | 30 | 15 | 154 (Container build) |
| `bash-ci.yml` | 15 | 10 | about 50 |
| `tofu-ci.yml` | 20 | 10 | 305 (`test`) |
| `security.yml` | 30 | 15 | 111 (CodeQL) |
| `docs-pages.yml` | 30 | 10 | 28 |
| `wiki-publish.yml` | 30 | 10 | 27 |

Left alone on purpose: `container-release` (60), `dast` (20), `python-fuzz`, `artifact-release`,
`arduino-ci`, `verify-published`, `python-package-release`, which are long by design or have no
measured healthy distribution here. Every job in every reusable workflow already has a
`timeout-minutes`; a missing timeout was not a cause. The `ci-green` jobs are fixed at 5.

## Could not access or not done

- Logs of hung jobs that return 404 (consistent with #709), so their region is unknown.
- Job-level runner image versions: all logs showed image `20261021.618` on
  ubuntu-24.04 and runner agent versions v0.16.3 and v0.17.0; there was no variation to correlate.
- Hour-of-day correlation: hung counts rise with load (10-24 03:00, 17:00 to 21:00 UTC) because
  Reach-Around pushes cluster there; the rate per job by hour was not separated from region.
- `gh search code` covers only default-branch content that GitHub indexed; 27 repositories call GYST,
  seven were sampled.
