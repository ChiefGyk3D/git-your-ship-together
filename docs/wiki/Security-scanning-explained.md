# Security scanning explained

**What this is.** `security.yml` runs eight kinds of scan, plus Trivy inside the
container release. Each catches a different class of problem, and none of them
catches what another does. This page says what each one finds, where the result
lands, how to dismiss a finding without lying to yourself, and what has been
measured about the awkward parts. The inputs are on the
[security workflow page](Workflow-security.md).

## Why a stack and not one tool

The threat is a secret or a compromise leaving a CI job, and the ways in differ: a
vulnerable line of your own code, a credential committed years ago, a dependency
with a published advisory, a dependency added today under a licence you cannot
ship, a workflow file that can be injected, a project whose practices an outsider
would distrust. One tool per class, each reporting to the same place.

## The eight scans

| Scan | What it catches | Misses | Where it lands |
|---|---|---|---|
| **CodeQL** | Flaws in your own code by data flow: injection, unsafe deserialization, path traversal. The `actions` language reads your *workflow files* for the same, such as an untrusted value reaching a shell | Anything that is not a pattern its queries know; logic bugs | Code scanning, category `/language:<lang>` |
| **gitleaks** | A credential shape anywhere in the **full git history**, not just the latest commit. The pinned binary (MIT; no licence key under any account) exits 1 on a finding and uploads SARIF | A secret in a shape it has no rule for; a secret outside git | Code scanning, category `gitleaks` |
| **Dependency audit** | A dependency version with a published advisory. pip-audit reads your requirements file with `--strict`; `audit-command` runs `npm audit`, `govulncheck`, `cargo audit` or similar | An advisory not yet published; your own code | The job log and exit code (a gate) |
| **Dependency review** | On a pull request only: a dependency the change *adds or bumps* that is vulnerable at `moderate` or above, or under a denied licence (AGPL, GPL, LGPL-3.0, SSPL by default) | Anything already in the base branch | A comment on the pull request |
| **Semgrep** | Pattern rules: `p/github-actions`, `p/secrets`, and `p/python` when Python exists. Catches things like a world-writable `chmod` or a risky workflow construct | What no rule describes. There is no `p/bash` pack (measured, issue #66: a 404), so ShellCheck in [bash-ci](Workflow-bash-ci.md) covers shell | Code scanning, category `semgrep` |
| **Snyk Code** | A second opinion on your source, from a different engine | Needs `SNYK_TOKEN`; runs on a trusted ref only | Code scanning (SARIF) |
| **Snyk Open Source** | Vulnerable dependencies, scanned from a `pip freeze` of what the lock installed | Same token; see below | Code scanning (SARIF) |
| **OpenSSF Scorecard** | An outside opinion of the repository's practices: pinned dependencies, branch protection, a security policy, fuzzing, signed releases | It scores the repository, not the code | Code scanning and the public Scorecard record; default branch only |

Trivy (an image scan for CRITICAL and HIGH findings) lives in
[container-release](Workflow-container-release.md), and a configuration scan in
[tofu-ci](Workflow-tofu-ci.md); both upload SARIF too. Fuzzing is
[python-fuzz](Workflow-python-fuzz.md).

## The scan that runs the service: DAST

Everything in the table reads code or metadata. [dast](Workflow-dast.md) is the
one check that starts the service and talks to it, with OWASP ZAP, and it is three
scans in one workflow because each sees a different class of problem:

| `scan-type` | Sees | Blind to | Cost |
|---|---|---|---|
| `baseline` | What a client sees: headers, cookies, banners, information in responses. Passive; no attack traffic | What the server does with its input | About a minute |
| `full` | The baseline, then every URL and parameter the spider found under ZAP's active rules: cross-site scripting, SQL and command injection, path traversal and the rest | Operations no link reaches; anything behind a login | Minutes; bounded by `active-scan-minutes` |
| `api` | Every operation an OpenAPI, SOAP or GraphQL definition declares, under the active rules, plus unexpected status codes and content types | Operations the definition leaves out | Minutes |

The reason to run it beside CodeQL and Semgrep is that they match patterns in code
they can see, and ZAP's active scan needs no pattern: it does what an attacker does
to the running service, with its real framework, configuration and middleware in the
path. A reflected cross-site scripting hole in `fixture/dast/server.py` passes the
baseline (every header is right) and fails the full scan at `high`; that is the proof
the `dast-live` CI job holds. Findings land in code scanning under category `zap` (or the
`sarif-category` the caller sets), tagged `zap-<scan-type>` so the tab says which scan
found each one.

The scans send attack payloads, which is why the workflow refuses any target that is
not loopback: the service under test is the one the job started, never a shared
staging host and never production. A scan of a deployed environment, with
authentication and real integrations, is a different thing with different risks; it
is on the [Roadmap](Roadmap.md) as work for a self-hosted runner.

Snyk is a **reporter** here, not a gate: its findings go to the Security tab and the
job fails only when Snyk did not run (an expired token, a project it could not read).
CodeQL and the dependency audit are the gates. It runs weekly and on manual dispatch
by default (`snyk-on: schedule`): the free plan meters tests per month across the
account, and a push-triggered run in each of ten repositories spent a month's Snyk
Code tests in one day (2026-10-04, 34 runs).

## Trust boundaries

Every job has `contents: read` and a few have more:

| Job | Extra grant | Why |
|---|---|---|
| CodeQL, gitleaks, Semgrep | `security-events: write` | To upload SARIF |
| Dependency review | `pull-requests: write` | To post its summary comment |
| Snyk | `security-events: write`, `id-token: write` | SARIF, and the Doppler fetch for `SNYK_TOKEN` |
| Scorecard | `security-events: write`, `id-token: write` | SARIF, and publishing the result with the job's identity |
| Dependency audit | none | Reads a file |

gitleaks holds no `id-token` and fetches nothing from Doppler: since issue #90 it
runs the binary, not the licence-gated action, so there is no credential in that job.

## Where results land

Open the repository's **Security** tab, then **Code scanning**. Each scanner uploads a
**SARIF** file under its own **category** (`gitleaks`, `semgrep`, the CodeQL language
categories, and so on). GitHub tracks an alert per category and per ref, and closes it
only when a later analysis **of the same category and ref** omits it.

That last sentence has a consequence measured on 2026-10-04 in a repository that
had moved to this workflow: 29 alerts showed as open on `main` after every underlying
issue was fixed. 25 of them belonged to the old, deleted CodeQL workflow's categories
(`/language:python` and the like). A retired category is never analysed again, so its
alerts never close. Fix: list the open alerts' `analysis_key`, find keys of
workflows that no longer exist, and delete that category's last analysis on `main`
(`gh api -X DELETE "repos/O/R/code-scanning/analyses/<id>?confirm_delete"`). The same
README lesson: the pull request check summary says "1 configuration not found" until
the deletion has happened; trust that, not the analysis list.

## Dismissing a finding honestly

A finding has three honest outcomes: fix it, mark it as accepted with a reason, or
dismiss it as not applicable with a reason. A dismissal is a statement other people
will read months later, so it must cite the code, not the mood.

1. **Fix at the root cause, with a test that fails first.** The 2026-10-04 sweep fixed
   every real finding this way across five repositories.
2. **Dismiss in the Security tab** with one of GitHub's reasons (false positive, won't
   fix, used in tests) and a comment of at most 280 characters that names the file, the
   line and *why the pattern is intended* ("0660 because GeoClue reads this socket as a
   different user; decision D-069"). "Not a real issue" is not a reason.
3. **For Semgrep, also mark the source** so the next scan does not re-raise it.
   Measured with Semgrep 1.179 against a real rule on 2026-10-05:
   - The bare `# nosemgrep`, `# nosemgrep: <rule-id>` and the previous-line form **all
     work** and arrive in the SARIF as `suppressions: inSource`.
   - `# nosemgrep: <free text>` suppresses **nothing**: the text is read as a rule id.
     Put the reason in a separate comment.
   - An alert that was opened *before* the marker existed stays open until it is
     dismissed by hand. Add the marker with its reason, then dismiss the old alert
     citing it.
   - **Not settled:** whether GitHub opens a *new* alert for a result the SARIF marks as
     suppressed. In two callers a marker was present and an alert still appeared on the
     next run (issue #83, open). Local Semgrep honours the marker; what GitHub does with
     the `suppressions` field was not measured in the reusable workflow. Until it is, a
     caller dismisses such an alert by hand with the reason.
4. **For an advisory that cannot be fixed yet** (the newest release is the affected one),
   use the [risk register](Baseline-and-the-weekly-audit.md): a reason, what limits the
   exposure, an owner and an expiry at most 90 days out. An ignore flag in a workflow with
   no register entry fails the weekly audit.

CodeQL has no in-source suppression marker comparable to `nosemgrep` that this repository
relies on; dismissal in the Security tab is the route. Whether a dismissed CodeQL alert
re-opens after a refactor moves the line was not measured for this page.

## What this refuses to do

- It never runs Snyk (or any token-holding scanner) on a pull request.
- It never reports "skipped" as "scanned": a repository with nothing Snyk can read gets a
  warning, and a missing `fuzz/` directory for a caller that opted into fuzzing is a
  failure.
- It never skips the scan's own test: the gitleaks job plants an AWS-shaped key in a scratch
  repository first and fails if its own invocation does not exit 1 on it, because a check
  nobody can see fail is worse than none.
