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

**"Secretless" means, exactly:** no stored secret (no `secrets.*`, no Doppler), no OIDC `id-token`, no
publish-capable or write-scoped token, `contents: read` at most (and `security-events: write` only for a SARIF
upload), no token handed to an action or a `gh` call beyond the default, and no output that a privileged job
consumes verbatim. It does **not** mean the job has no credential at all: every job has the default job token,
read-scoped here. The runner mints it, harden-runner v2.22.2 takes it through its `token` input (default
`github.token`, used "to avoid github rate limiting"), and `actions/checkout` uses it even with
`persist-credentials: false`. So a read-scoped token is available to the actions that take it as an input (checkout, harden-runner) and to
any step that references it explicitly. It is not exported to `run` steps automatically.

We looked at passing `token: ''` to harden-runner. Its documented purpose is rate limiting (it fetches the
agent release from the GitHub API), so the unauthenticated form would fail on shared runner addresses
intermittently, a new flake on top of the one this exception fixes. We did not do it.

**Only on GitHub-hosted runners, decided at run time.** The exception covers GitHub-hosted runners, because that
is where the defect lives and where an `audit` job is thrown away after its run. A label cannot prove a runner
is hosted: a self-hosted runner can carry the label `ubuntu-latest`, or any other. So the control is GitHub's own
runtime context. `runner.environment` is `github-hosted` for GitHub-hosted runners and `self-hosted` for
self-hosted ones (GitHub Docs, "Contexts" reference, the `runner` context table; the page is
`content/actions/reference/workflows-and-actions/contexts.md` in github/docs, read 2026-10-24). It is available
in step contexts (`jobs.<job_id>.steps.if` and `steps.with` list `runner`) and not in `runs-on` or a job-level
`if`, so it is read in the harden-runner step's `with:` and in the canary's step-level `if:`.

For every relaxed job the effective policy is `audit` only when the policy input equals `audit` **and**
`runner.environment == 'github-hosted'`; anything else (`self-hosted`, empty, undefined) is `block`.
GitHub's `==` and `contains()` compare strings case-insensitively, so inside the expressions `AUDIT` equals `audit` and `Block` equals `block`; the expressions alone are not exact. `GitHub-Hosted` counts as hosted for
the same reason. The **exact-string control is the policy check**, not the expression: it is step 0 of every job
and fails the job on any policy value that is not exactly `audit` or `block` (so `AUDIT` and `Block` fail it),
before anything consumes the value. A test pins that dependency.

The label list is a second check, kept for the four jobs whose runner label a caller chooses (`runner`,
`runners` and `distro-runners` inputs: `bash-ci.yml` `test` and `distro`, `python-ci.yml` `distro`,
`python-fuzz.yml` `fuzz`). For those, audit needs **both** the runtime context and a label that matches one
of the standard hosted labels below, case-insensitively (`contains()` ignores case). The label check alone would not be enough; the runtime check alone is the
control. A runner-group object, a comma list, a JSON list or a larger-runner name does not match a label and
gives `block`. Every other relaxed job has a literal `runs-on` that is one of these labels; a test enforces it.

The policy check is the **first** step of every job, before harden-runner, so a value that is not exactly
`audit` or `block` fails the job before anything consumes it. It touches no network and reads only its own
inputs. (harden-runner is therefore the second step of those jobs.)

The list of hosted labels, in one place. Source: GitHub Docs, "GitHub-hosted runners" reference, section
"Standard GitHub-hosted runners" (https://docs.github.com/en/actions/reference/runners/github-hosted-runners;
the table is `data/reusables/actions/supported-github-runners.md` in github/docs, read 2026-10-24).
Larger runners have custom names and are deliberately not in the list. `tests/test_egress_canary.py` parses
this block and requires every workflow to embed exactly this list.

<!-- hosted-runner-labels:begin -->
ubuntu-latest
ubuntu-22.04
ubuntu-24.04
ubuntu-26.04
ubuntu-22.04-arm
ubuntu-24.04-arm
ubuntu-26.04-arm
ubuntu-slim
windows-latest
windows-2022
windows-2025
windows-2025-vs2026
windows-11-arm
windows-11-vs2026-arm
macos-latest
macos-14
macos-15
macos-15-intel
macos-26
macos-26-intel
<!-- hosted-runner-labels:end -->

Relaxed (policy follows `egress-policy-secretless`, default `audit`): the jobs below, and only these.

| Workflow | Jobs relaxed |
|---|---|
| `python-ci.yml` | `lint`, `typecheck`, `workflow-lint`, `distro`, `smoke`, `docker`, `fragment-check`, `commit-claims`, `ci-green` |
| `bash-ci.yml` | `shellcheck`, `shfmt`, `test`, `distro`, `config-lint`, `workflow-lint`, `fragment-check`, `commit-claims`, `ci-green` |
| `tofu-ci.yml` | `fmt`, `validate`, `test`, `tflint`, `trivy`, `policy`, `workflow-lint`, `ci-green` |
| `arduino-ci.yml` | `compile`, `test`, `workflow-lint`, `ci-green` |
| `security.yml` | `codeql`, `gitleaks`, `dependency-audit`, `semgrep` (SARIF upload with the default token only) |
| `dast.yml` | `upload` (SARIF upload only) |
| `python-fuzz.yml` | `fuzz` |
| `threat-model.yml` | `check` |
| `container-release.yml` | `dockerfile-lint` |
| `python-package-release.yml` | `pypi-unsupported` |
| `verify-published.yml` | `rescan`, `verified` |

`distro` (python-ci, bash-ci) and `semgrep` (security) keep their own policy inputs as well: the job is
`audit` when either `egress-policy-secretless` or its own input says `audit` (case-insensitively in the
expression; exactly, by the policy check that runs first).

**Kept in `block`** (follow `egress-policy`, and get the policy check and the fail-fast canary):

| Workflow | Jobs | Why |
|---|---|---|
| `artifact-release.yml` | `publish` | `contents: write`, `id-token`, attestations |
| `artifact-release.yml` | `build` | **ambiguous**: no credential, but it builds the file that is signed and published |
| `python-package-release.yml` | `github-release` | `contents: write`, `id-token`, attestations |
| `python-package-release.yml` | `build` | **ambiguous**: builds the distribution that is published |
| `container-release.yml` | `build`, `merge` | `packages: write`, `id-token`, Doppler |
| `container-release.yml` | `plan` | **ambiguous**: its outputs choose the runners and the image name of the privileged `build` |
| `docs-pages.yml` | `deploy` | `pages: write`, `id-token` |
| `docs-pages.yml` | `build` | runs caller code; its artifact is deployed verbatim by `deploy` |
| `wiki-publish.yml` | `publish` | `contents: write` |
| `wiki-publish.yml` | `generate` | runs caller code; its artifact is pushed verbatim by `publish` |
| `python-ci.yml` | `coverage` | `id-token`, Doppler, the Codecov upload |
| `python-ci.yml` | `test` | its coverage artifact is uploaded to Codecov by `coverage` |
| `dast.yml` | `scan` | its SARIF artifact is uploaded verbatim by `upload` (`security-events: write`) |
| `security.yml` | `snyk`, `scorecard` | `id-token`, Doppler (`SNYK_TOKEN`) |
| `security.yml` | `dependency-review` | **ambiguous**: `pull-requests: write` |
| `tofu-ci.yml` | `plan` | `id-token`, Doppler |
| `verify-published.yml` | `verify` | passes the job token to `gh attestation verify`; `packages: read` |
| `verify-published.yml` | `verify-release` | passes the job token to `gh release download` and `gh attestation verify` |
| `project-sync.yml`, `dependabot-auto-merge.yml` | all | a GitHub App token, `contents: write` |
| `audit.yml` (this repository's weekly audit) | all | `id-token`, Doppler, hardcoded `block` |

Ambiguous means the job holds no stored secret but sits in a release or write path; the rule was "if
unsure, keep it in `block`". Every secretless job was re-audited for `github.token`, `GITHUB_TOKEN`,
`GH_TOKEN`, `secrets.*`, a `token` or `password` in a `with:`, `gh` calls and token-consuming actions; the
result is in the pull request. `tests/test_egress_canary.py` pins the table against the YAML: a job that
holds any of those, or whose artifact or outputs feed a job kept in `block`, cannot follow the secretless
input.

Not in scope: this repository's own `ci.yml` jobs (already `audit` before this exception).

## Compensating controls

- Every action is pinned to a commit SHA, and zizmor (pedantic persona) enforces it in this repository's CI.
- Least-privilege `permissions` on every job; the relaxed jobs hold `contents: read` (and a SARIF upload
  grant in four of them) and nothing that can publish, push or deploy.
- No stored secret, no OIDC token and no publish-capable token is in scope in the relaxed jobs, so there is
  nothing of that kind for a compromised step to send out.
- `audit` mode still logs every outbound connection to the job summary and the harden-runner insights, and
  `disable-sudo` stays on where it was.
- The policy check (step 0 of every job) fails the job on any policy value that is not exactly `audit` or
  `block`, with a message naming the input and the length of the value, before anything uses it. The effective
  expressions then only matter for valid values; for a value that reaches them they are case-insensitive by
  GitHub's design, and any other value gives `block`.
- The jobs that stay in `block` are covered by the fail-fast egress canary, which turns the westus2 symptom
  into an immediate, named failure instead of a ten-minute hang.
- The canary is **Linux-only**: every copy carries `runner.os == 'Linux' &&` in its step-level `if`. It needs
  `timeout` and `getent`, which macOS lacks (`getent` is also missing in Git Bash on Windows); without the
  condition a macOS matrix leg failed with the misleading "known westus2 DNS issue" message (issue #196,
  v1.25.1). This exception concerns harden-runner `block` on Linux runners, and the canary is a diagnostic, so
  skipping it on macOS and Windows weakens no control. `tests/test_egress_canary.py` fails if a canary step
  lacks the condition.
- Timeouts were cut to about three times the slowest healthy p99 (python-ci 15, bash-ci 10, tofu-ci 16,
  security 15, docs-pages 10, wiki-publish 10 minutes), so a stuck job costs minutes, not half an hour.

## Residual risk

In the relaxed jobs a compromised dependency or action can now send data to any host and the job will not
stop it; it is logged, not blocked. What it can reach is the checked-out repository (a private repository's
source can leave the runner) and the default job token, read-scoped, which actions that take it as an input
(checkout, harden-runner) and steps that reference it explicitly can use; it is not exported to `run` steps
automatically. A read-scoped token can read
what the repository's own read access allows; it cannot publish, push, deploy or read a stored secret. The
relaxation applies to every region, not only westus2, because the input is static. Audit mode also has its
own open upstream defect (#709, memory growth on process-heavy jobs); none of our jobs is shaped like the
reported one, and we have not seen it.

The canary has a known false-positive risk: a load balancer that still lists an address that has stopped
answering fails a healthy `block` job. Each failing address is retried three more times, a second apart, so
a transient refusal passes; a persistent one costs a rerun. The logs it prints on failure contain resolver
and host addresses, so review them before attaching them to a support ticket.

## Caches and artifacts

**The cache rule.** A job whose effective policy is `audit` neither restores nor saves a cache that is not
hash-verified. Code that runs in an audit job could otherwise write a poisoned cache entry that a later
block-mode job, one holding an OIDC token or a Doppler secret included, restores in the same run or in a later
one. setup-python's pip cache key is the operating system, architecture, Python version and a hash of the
manifests; v7 (read at the pinned SHA) has no suffix or namespace option, only `cache-dependency-path`, so audit
and block cannot be kept apart by naming. Every cache input in an audit-capable job is therefore computed from
the job's own effective policy and is off unless that policy is `block`; the expression is the same one that
drives harden-runner, so the two cannot disagree. A tool-download cache (`tool-*` keys) is kept: every restore
is followed by `sha256sum -c` against a pinned hash, so a poisoned entry cannot pass.

**Performance consequence.** Audit-mode jobs install their dependencies without the pip cache and build images
without the Actions cache: a few tens of seconds per job on the short jobs measured, more on a large
dependency tree. Callers that run `block` get the caches back.

**Residual.** In block mode the secretless jobs and the jobs that stay in `block` share the pip cache namespace
(for example `python-ci` `lint`, `typecheck`, `smoke` and `test`). They run the same caller code under the same
egress filter, which is the trust level the project already extends to its own `test` job; the exception does not
widen it. This is the part a separate namespace would fix, and the action offers none.

Every cache and artifact that can cross a trust class, with the decision:

| Where | What | Decision |
|---|---|---|
| `python-ci` `lint`, `typecheck`, `smoke`, `test` | setup-python `cache: pip` | off when the job's effective policy is audit |
| `python-fuzz` `fuzz` | setup-python `cache: pip` | off when audit |
| `docs-pages` `build` | setup-python `cache: pip` | off when audit |
| `python-ci` `docker` | buildx `cache-from` and `cache-to` `type=gha` | off when audit |
| `container-release` `build` | buildx `type=gha` cache, only on a non-publishing build, scope per architecture | off when audit (it was already off for a publishing build) |
| `arduino-ci` `compile` | Actions cache of the core and library downloads (`arduino-packages-*`) | step skipped when audit |
| `arduino-ci`, `bash-ci`, `container-release`, `tofu-ci` | tool-download caches (`tool-*`) | kept: every restore is verified against a pinned SHA-256 |
| `ci.yml` (this repository's own CI, always audit) | setup-python `cache: pip` in four jobs | removed: `audit.yml` (block, Doppler) restores the same key |
| `audit.yml` | setup-python `cache: pip` | kept: both jobs are hardcoded `block` |
| `python-package-release` `build`, `artifact-release` `build` | none (a publishing build never reads a cache; a test holds this) | no change |
| artifacts: `python-ci` `test` to `coverage`, `dast` `scan` to `upload`, `docs-pages` `build` to `deploy`, `wiki-publish` `generate` to `publish`, `verify-published` `verify-release` to `rescan` | job to job within one run | the producer of each that feeds a privileged consumer is kept under `egress-policy` (see the table above); `rescan` is secretless and only reads what block-class jobs wrote |

`tests/test_egress_canary.py` collects every cache site in every workflow and requires each one to be either a
hash-verified tool cache or gated on its own job's effective policy, then evaluates the gate for audit, block,
invalid policies, every runtime environment and runner label. A cache that is left on in audit fails the test.

## What the canary prints

Only when it fails, to the live job log and nowhere else: `uname -srmo` (kernel name, release, machine and
operating system; no hostname), `/etc/resolv.conf`, the `Current DNS Server`, `DNS Servers` and `DNS Domain`
lines of `resolvectl status`, the UDP listeners on port 53 from `ss -lun` (no process names), for each of
`github.com`, `api.github.com`, `results-receiver.actions.githubusercontent.com` and
`pipelines.actions.githubusercontent.com` the `getent ahostsv4` answer and one line from `curl`
(HTTP status, remote address, connect time), and the list of unreachable addresses. Plus a one-line step
summary naming EX-0001 and those addresses. Nothing from the environment, no headers, no hostname. The
output contains resolver and host addresses, so read it before attaching it to a support ticket.

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
