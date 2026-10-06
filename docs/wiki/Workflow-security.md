# security

**What it does.** The repository's security scans in one workflow: CodeQL (the `actions` language included by default),
gitleaks over the full history, a dependency audit, dependency review on pull requests, Semgrep, optional Snyk Code and Snyk
Open Source, and optional OpenSSF Scorecard. Results land in the Security tab as SARIF. What each scan catches, where it
reports and how to dismiss a finding honestly is on [Security scanning explained](Security-scanning-explained.md); this
page is the reference for calling it.

**Why it exists.** The threat is a secret or a compromise leaving a CI job, and the ways in differ, so there is one scan per
class. Only one job is Python-shaped, and only by default: the dependency audit runs pip-audit when
`pip-audit-requirements` names a file and whatever `audit-command` names otherwise. A shell-only repository therefore calls
it with `codeql-languages: actions` and `pip-audit-requirements: ""` and changes nothing else.

## Jobs and trust boundaries

| Job | Holds | Runs on |
|---|---|---|
| CodeQL | `contents: read`, `security-events: write` | Every event |
| Secret scan (gitleaks) | `contents: read`, `security-events: write` | Every event. No `id-token`, no Doppler, no secret |
| Dependency audit | `contents: read` | Every event |
| Dependency review | `contents: read`, `pull-requests: write` | Pull requests only |
| Semgrep | `contents: read`, `security-events: write` | Every event, with its own egress policy and list |
| Snyk | `contents: read`, `security-events: write`, `id-token: write` | Never on a pull request; the weekly schedule and manual runs by default |
| Scorecard | `contents: read`, `security-events: write`, `id-token: write` | The default branch (push or schedule) only |

Snyk and Scorecard are the only jobs with an OIDC grant, and neither runs on a pull request. gitleaks lost its `id-token`
and its Doppler fetch in issue #90: the licence-gated action was replaced with the MIT binary, pinned by sha256 and checked
with `sha256sum -c` before extraction, and a canary step plants an AWS-shaped key in a scratch repository and fails the job
unless the same invocation exits 1 on it. A `.gitleaks.toml` at the repository root is honoured.

## A minimal caller

```yaml
on:
  push: { branches: [main] }
  pull_request:
  schedule:
    - cron: '0 6 * * 1'   # weekly, so new advisories surface between commits
  workflow_dispatch:

jobs:
  security:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/security.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write
      pull-requests: write
      id-token: write
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      snyk: true
      scorecard: true
      egress-policy: block
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

## Behaviour from measured trouble

- **Snyk and the free plan.** It meters tests per month across the account. Ten repositories on `push` spent a month's Snyk
  Code tests on 2026-10-04 (34 runs), so `snyk-on` defaults to `schedule`. Findings do not fail the job; Snyk failing to run
  does.
- **Snyk's pip resolver refuses a universal lock.** A `uv pip compile --universal` lock always has lines pip skips (markers
  for other Pythons), and Snyk exits 2 with "Missing required packages". `--skip-unresolved=true` changed nothing, measured on
  four repositories on 2026-10-03. The workflow therefore scans a `pip freeze` of the environment the lock installed. A
  repository with no lock names its install in `snyk-install-command`.
- **Semgrep for shell.** No `p/bash` or `p/shell` registry pack exists (the earlier default 404'd, issue #66), so shell-only
  repositories use `p/github-actions` and `p/secrets`, and [bash-ci](Workflow-bash-ci.md)'s ShellCheck covers the shell.
- **Semgrep suppression** is partly unsettled (issue #83); see the scanning page.
- **The Actions allow-list** needs subdirectory forms for `github/codeql-action/init` and `snyk/actions/setup`; see
  [The baseline and the weekly audit](Baseline-and-the-weekly-audit.md).
- **Scorecard findings** are filed as issues weekly; one open item (#87) is a `pip install` in this workflow not yet
  pinned by hash.

<!-- inputs -->

## What it refuses to do

It never runs a token-holding scan on a pull request, never fetches Doppler secrets on one (`doppler-trusted-refs-only` is on
by default), and never turns a missing token into a pass: an expired Snyk token fails the job and names itself.
