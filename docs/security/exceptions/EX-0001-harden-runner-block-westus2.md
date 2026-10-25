# EX-0001: harden-runner `block` relaxed to `audit` for secretless jobs (westus2)

| Field | Value |
|---|---|
| ID | EX-0001 |
| Date | 2026-10-24 |
| Owner | ChiefGyk3D |
| Status | **active** |
| Issue | ChiefGyk3D/git-your-ship-together#189 |
| Expires | 2026-11-07 at the latest, or earlier when the upstream defect is fixed (see "Expiry") |
| Control relaxed | harden-runner `egress-policy: block` becomes `audit`, for secretless jobs only, by the new default of the `egress-policy-secretless` input |

## Why

GitHub-hosted runners in the Azure region `westus2` break harden-runner in `block` mode. About 6 percent of
jobs hang or fail, because GitHub is running a DNS experiment on those runners (an
`egress-dns-resolver.service` that holds `127.0.0.1:53`). The harden-runner agent then records one A record
per allowed domain and drops connections to the other addresses of the same name, GitHub's own services
included. The runner cannot reach its results receiver, so steps stay `in_progress` after the work finished,
checkouts are refused (`Failed to connect to github.com port 443 after 6 ms`), cache and artifact calls fail
with `ECONNREFUSED`, and the job ends only at its timeout plus GitHub's five-minute cancel grace. Rerunning the
job on another region passes. Cost in the three days before this record: 89 hung jobs, 2597 runner-minutes.

### Proof: a 250-job controlled experiment (2026-10-24)

One workflow run, 50 jobs per arm, each job printing its region and doing checkout, `setup-python` with
`cache: pip`, `pip install` and an artifact upload. Arms were gated at job level so that a skipped
harden-runner never reached its pre-step.

| Arm | Other regions | westus2 |
|---|---|---|
| a: no harden-runner | 49 ok | 1 ok |
| b: block, v2.21.1 | 44 ok | **6 BAD** |
| c: block, v2.22.2 | 48 ok | **2 BAD** |
| d: audit, v2.22.2 | 46 ok | 4 ok |
| e: block, v2.22.2, results hosts added to the allow-list | 48 ok | **2 BAD** |

Reading: every non-westus2 job passed in every arm; every westus2 job passed with no tool or with `audit`,
and every westus2 job failed in `block`, whatever the version and whatever names were allowed. Upstream
reports the same signature:

- step-security/harden-runner#708 (open): on westus2 the agent records one A record per allowed domain and
  drops the others. A commenter reports that only switching `block` to `audit` unstuck CI.
- step-security/harden-runner#705 (open) and actions/runner-images#14925 (open): since 2026-10-12 westus2
  runners run a resolver GitHub describes as an experiment on some hosted runners.
- step-security/harden-runner#709 (open) is a separate defect in `audit` mode (agent memory growth on a
  process-heavy job). It is not shown in our short jobs, and it is a reason this exception expires soon.

Upstream has given **no fix date**.

## Why not solved properly

It is a vendor and platform defect outside our control. We cannot choose the region a hosted job lands in,
we cannot pin the runner's DNS behavior, a newer harden-runner (v2.22.2) does not help (arm c), and allowing
more host names does not help (arm e): the refusals are per IP, not per name. The only controls we own are
where `block` runs and how fast a broken runner is detected.

## Exact scope

Relaxed (policy follows `egress-policy-secretless`, default `audit`): the jobs below. Criteria, all four
required: no secret (no `secrets.*`, no Doppler), `permissions` of `contents: read` (a `security-events:
write` grant for a SARIF upload is the only other grant allowed), no `id-token`, no publish credential.

| Workflow | Jobs relaxed |
|---|---|
| `python-ci.yml` | `lint`, `typecheck`, `workflow-lint`, `test`, `distro`, `smoke`, `docker`, `fragment-check`, `commit-claims`, `ci-green` |
| `bash-ci.yml` | `shellcheck`, `shfmt`, `test`, `distro`, `config-lint`, `workflow-lint`, `fragment-check`, `commit-claims`, `ci-green` |
| `tofu-ci.yml` | `fmt`, `validate`, `test`, `tflint`, `trivy`, `policy`, `workflow-lint`, `ci-green` |
| `arduino-ci.yml` | `compile`, `test`, `workflow-lint`, `ci-green` |
| `security.yml` | `codeql`, `gitleaks`, `dependency-audit`, `semgrep` (SARIF upload only) |
| `dast.yml` | `scan`, `upload` (SARIF upload only; the scan account is a throwaway one) |
| `python-fuzz.yml` | `fuzz` |
| `threat-model.yml` | `check` |
| `docs-pages.yml` | `build` |
| `wiki-publish.yml` | `generate` |
| `container-release.yml` | `plan`, `dockerfile-lint` |
| `python-package-release.yml` | `pypi-unsupported` |
| `verify-published.yml` | `verify-release`, `rescan`, `verified` |

`distro` (python-ci, bash-ci) and `semgrep` (security) keep their own policy inputs as well: the job is
`audit` when either `egress-policy-secretless` or its own input says `audit`.

**Kept in `block`** (follow `egress-policy`, and get the fail-fast canary):

| Workflow | Jobs | Why |
|---|---|---|
| `artifact-release.yml` | `publish` | `contents: write`, `id-token`, attestations |
| `artifact-release.yml` | `build` | **ambiguous**: no credential, but it builds the file that is signed and published |
| `python-package-release.yml` | `github-release` | `contents: write`, `id-token`, attestations |
| `python-package-release.yml` | `build` | **ambiguous**: builds the distribution that is published |
| `container-release.yml` | `build`, `merge` | `packages: write`, `id-token`, Doppler |
| `docs-pages.yml` | `deploy` | `pages: write`, `id-token` |
| `wiki-publish.yml` | `publish` | `contents: write` |
| `python-ci.yml` | `coverage` | `id-token`, Doppler, the Codecov upload |
| `security.yml` | `snyk`, `scorecard` | `id-token`, Doppler (`SNYK_TOKEN`) |
| `security.yml` | `dependency-review` | **ambiguous**: `pull-requests: write` |
| `tofu-ci.yml` | `plan` | `id-token`, Doppler |
| `verify-published.yml` | `verify` | **ambiguous**: `packages: read` token for the registry |
| `project-sync.yml`, `dependabot-auto-merge.yml` | all | a GitHub App token, `contents: write` |
| `audit.yml` (this repository's weekly audit) | all | `id-token`, Doppler, hardcoded `block` |

Ambiguous means the job holds no stored secret but sits in a release or write path; the rule was "if
unsure, keep it in `block`". `tests/test_egress_canary.py` pins this table against the YAML: a job that
holds a secret, an OIDC token or a write grant cannot follow the secretless input.

Not in scope: this repository's own `ci.yml` jobs (already `audit` before this exception).

## Compensating controls

- Every action is pinned to a commit SHA, and zizmor (pedantic persona) enforces it in this repository's CI.
- Least-privilege `permissions` on every job; the relaxed jobs hold `contents: read` and nothing that can
  publish, push or deploy.
- No credential is in scope in the relaxed jobs, so there is nothing of that kind for a compromised step to
  send out.
- `audit` mode still logs every outbound connection to the job summary and the harden-runner insights, and
  `disable-sudo` stays on where it was.
- The jobs that stay in `block` are covered by the fail-fast egress canary, which turns the westus2 symptom
  into an immediate, named failure instead of a ten-minute hang.
- Timeouts were cut to about three times the slowest healthy p99 (python-ci 15, bash-ci 10, tofu-ci 16,
  security 15, docs-pages 10, wiki-publish 10 minutes), so a stuck job costs minutes, not half an hour.

## Residual risk

In the relaxed jobs a compromised dependency or action can now send data to any host and the job will not
stop it; it is logged, not blocked. What it can reach is the checked-out repository (a private repository's
source can leave the runner) and a read-only job token. It cannot publish, push, deploy or read a stored
secret. The relaxation applies to every region, not only westus2, because the input is static. Audit mode
also has its own open upstream defect (#709, memory growth on process-heavy jobs); none of our jobs is
shaped like the reported one, and we have not seen it.

## Expiry

Revisit and revert when step-security/harden-runner#708 or actions/runner-images#14925 is closed with a fix,
or on **2026-11-07 at the latest**, whichever is first. If the upstream defect is still open on that date the
exception is renewed only by a new dated entry in this file, with the owner's name and a new expiry.

## Review trigger

Rerun the verification below on each harden-runner release and each time either upstream issue changes
state. Any new hung-job report from a job in the "kept in block" table also triggers a review.

## Rollback

One input flip, no code change: a caller sets `egress-policy-secretless: block` on the workflow, or the
default of that input is changed from `audit` to `block` in each reusable workflow (a single line each;
`git grep -n "egress-policy-secretless" -A3 .github/workflows`). The canary then guards those jobs too.

## Verification

Rerun the experiment: a `workflow_dispatch` workflow with five job-level arms (never step-level `if:`, the
action's pre-step ignores it): no tool; `block` on the old pin; `block` on the current pin; `audit`; `block`
with `results-receiver.actions.githubusercontent.com:443` and `pipelines.actions.githubusercontent.com:443`
added. Each job: print the region, check out, `setup-python` with `cache: pip`, `pip install`, upload an
artifact. Use a `strategy.matrix` of 50 entries per arm so that westus2 is hit several times, then tabulate
(region, arm, outcome) from the job logs. The exception ends when the `block` arms pass on westus2.

The canary has been tested against stubs only (`tests/test_egress_canary.py`). It has not yet been seen on a
real broken westus2 runner; the first such failure should be checked for the diagnostics block in the job
log and attached to the GitHub Support ticket.
