# Security Workflow

`.github/workflows/security.yml` is the one security pipeline. Full input table:
[README: Security](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#security).

## What runs

| Job | Tool | Finds | Notes |
|---|---|---|---|
| `codeql` | CodeQL | Code flaws | Languages default to `python,actions`. The `actions` language scans the **workflow files themselves** and fits every repository. A repo with no Python passes `actions` alone (CodeQL fails on a language with no source) |
| `gitleaks` | gitleaks | Secrets anywhere in full git history | A pinned **binary** checked by SHA-256 (no licence, no secret, no Doppler). Honours `.gitleaks.toml`. A canary step plants a fake AWS-shaped key in a scratch repo and requires the scan to catch it, so a broken scanner cannot pass silently |
| `dependency-audit` | pip-audit, or any command you give | Known-vulnerable dependencies | `audit-command` makes it language-neutral: `npm audit`, `govulncheck ./...`, `cargo audit` |
| `dependency-review` | GitHub dependency review | New vulnerable / badly licensed dependencies | Pull requests only. Fails on a licence denylist (AGPL, GPL, SSPL...) by default |
| `semgrep` | Semgrep | Pattern-based issues | Auto-selects registry packs from the repository's content; own egress policy |
| `snyk` | Snyk Code and Open Source | Vulnerabilities | **Optional**, needs `SNYK_TOKEN` from Doppler. Never on a pull request. Weekly by default |
| `scorecard` | OpenSSF Scorecard | An outside score of your practices | **Optional**, default branch only, published with OIDC |

Results land in the repository's **Security tab** as SARIF.

## Language-neutral by design

Only one job is Python-shaped, and only by default: the dependency audit runs
`pip-audit` when `pip-audit-requirements` names a file, and whatever `audit-command`
names otherwise (or both). A shell-only repository calls it with
`codeql-languages: actions` and `pip-audit-requirements: ""` and changes nothing else.

## Things worth understanding

- **Snyk is a reporter, not a gate.** It fails the job only when Snyk *did not run*
  (expired token, unreadable project). Findings go to the Security tab. CodeQL and
  pip-audit are the gates.
- **Why Snyk is weekly:** Snyk's free plan meters tests per month across the whole
  account. Ten repositories scanning on every push spent a month of Code tests in
  one busy day. `snyk-on: push` restores per-push scans for a repository that wants them.
- **Snyk scans a `pip freeze`, not your lock file.** Snyk's pip resolver rejects
  universal locks (marker-gated lines, extras). The workflow installs the lock and
  scans what actually went in. See [Lessons Learned](Lessons-Learned).
- **Secrets only on a trusted ref.** The Snyk job gets its token from
  [Doppler](Secrets-and-Doppler) only on the default branch, a tag or a schedule.
- **Ignoring an advisory is a registered decision.** `pip-audit-extra-args:
  --ignore-vuln <id>` and `dependency-review-allow-ghsas: <id>` both require an entry
  in the [risk register](Repository-Baseline#the-risk-register): reason, mitigation,
  owner, and a review date at most 90 days away. Unregistered or expired exceptions fail
  the audit.
- **Every job has `continue-on-error` migration aids** (`*-continue-on-error`) for a
  repository cleaning up findings. They are meant to be removed.

## DAST: `dast.yml`

`security.yml` reads code. [`dast.yml`](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#dast-owasp-zap-baseline)
is the check that talks to a running service: it starts the service your repository
serves (a dashboard, an API, a docs server) on loopback, runs an OWASP ZAP **baseline** scan
against it (a spider plus ZAP's passive rules, no attack traffic), and fails the job when a finding
reaches `fail-on`. Findings go to the Security tab under category `zap`; the HTML, Markdown and JSON
reports are an artifact. A repository with no service has nothing to call it for.

How it keeps the repository's rules:

- **Two jobs.** `scan` runs *your* service and holds `contents: read` and nothing else, like a test
  job. `upload` holds `security-events: write`, checks nothing out and runs no shell.
- **Loopback only.** A `target-url` that is not `127.0.0.1`, `localhost` or `[::1]` is refused
  before anything starts, so a typo cannot aim a scanner at someone else.
- **The image, not an action.** `zaproxy/action-baseline` uses the moving tag `stable`, files issues
  with the job's token and has no SARIF. The workflow runs the same image pinned by **digest**, with no token in
  the container and `-silent`, so ZAP reaches nothing of its own: under `block` the allow-list is the
  image pull and GitHub. No action joins the allow-list for it.
- **`fail-on` is a risk level.** A page with no security headers is Medium (no CSP, no
  anti-clickjacking header), so the default `high` does not catch it; use `medium` for that.
  Accept a finding in `.zap/rules.tsv` (`IGNORE` plus a reason), never by raising the threshold.

Proving it can fail is part of the workflow's tests: `fixture/dast/server.py` serves one page with its
security headers (must pass) and, with `--insecure`, without them (must fail at `medium`, pass at
`high`). `tests/test_dast.py` runs the job's steps against canned reports, and this repository's
`dast-live` CI job runs them against the real image.

## A typical caller

```yaml
jobs:
  security:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/security.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write   # SARIF upload
      pull-requests: write     # dependency-review summary
      id-token: write          # Doppler OIDC, Scorecard
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      codeql-queries: security-extended,security-and-quality
      snyk: true
      scorecard: true
      egress-policy: block
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

Trigger it on push to the default branch, on pull requests, and on a weekly schedule
so new advisories surface between commits.
