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

## The same scan before a commit

`.githooks/pre-commit` runs the gitleaks scan on the *staged* changes, so a secret is caught before it is in history.
It uses the version and SHA-256 that `security.yml` pins (a test holds the two equal), keeps the verified release under
`~/.cache/gyst/gitleaks/<version>/`, checks it against the pin on every run, and honours `.gitleaks.toml`. A finding
refuses the commit and prints the rule, file and line, never the secret. With no cached binary and no network it warns
and allows. It only protects a checkout that ran `git config core.hooksPath .githooks`; push protection and the CI
scan are the two that always run. `scripts/new-repo.sh` copies the file byte for byte into an adopted repository and
adds that one line to its README's Developing section.

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
