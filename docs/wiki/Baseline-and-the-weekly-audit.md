# The baseline and the weekly audit

**What this is.** [BASELINE.md](../../BASELINE.md) is the list of repository
settings no workflow file can set, and `scripts/audit_baseline.py` is the script
that reads each repository's settings from the GitHub API and says PASS, FAIL or
UNKNOWN for every line. `.github/workflows/audit.yml` runs it every Monday at 07:00
UTC. Perfect workflows in a repository with an open default branch are a locked
door in an open wall; the baseline is the wall.

## Why it exists

Workflows can be reviewed in a pull request. Branch protection, the Actions
allow-list and secret scanning cannot: they are switches in a settings page, and a
switch nobody checks drifts. The audit exists so that drift is a red job on Monday
and not something somebody remembers to look at. It is run against every
repository in [`baseline/repos.txt`](../../baseline/repos.txt); a repository not on
the list is not covered.

The design rule that matters most: **UNKNOWN is never PASS.** A check the token could
not make (a 403, a 404 on an endpoint) is reported UNKNOWN and turns the run red.
"We could not check" and "it is fine" are different answers, and the exit code tells
them apart: 0 all passed, 1 at least one FAIL, 2 no FAIL but at least one UNKNOWN.

## What it requires, and why each line

The threat the baseline is written against is a secret leaving a CI job: through code
running beside it, through a person with write access, or through being stored where
it can be read back. Each section closes one of those.

| Section | Requirement | Why | Check ids |
|---|---|---|---|
| People | Only the owner can push; everyone else contributes from a fork | A fork's run never receives a secret | `collaborators` |
| Default branch | Pull request required, stale approvals dismissed, no force push or deletion, and the **`CI green` gate of every shared CI workflow the repository calls** required (`ci / CI green`, `shell / CI green`, ...) | One required name per language; a job added later is covered | `required-check`, `pull-request-required`, `history-protected` |
| Approval count | **Zero** | GitHub does not let an author approve their own pull request, so one required approval on a single-maintainer repository never produces a review; it only teaches overriding as administrator. Zero keeps the pull request and the green check required | part of `pull-request-required` |
| Auto-merge | Allowed | A Dependabot bump has cleared cooldown, gate and pull request by the time it is mergeable; the click adds nothing | `auto-merge-enabled` |
| Tags | `v*` tags immutable by ruleset | Callers pin SHAs, but Dependabot follows tags and zizmor compares a pin to the tag its comment names. A moved tag is the one way a pin and its comment disagree with no commit to show | `tag-ruleset` |
| Secrets | Doppler is the only store; the identity is scoped; no `secrets: inherit`; no GitHub Actions secrets | See [Secrets](Secrets-Doppler-and-OIDC.md) | `doppler-identity`, `workflows-pinned` |
| Workflows | Every action pinned to a SHA with a version comment; every reference to these workflows names its tag; Dependabot configured, with the `uv` ecosystem for a universal uv lock | A universal lock updated by `pip` drops marker-gated lines and then fails `--require-hashes` on part of the matrix | `workflows-pinned`, `uses-shared-workflows`, `dependabot-config`, `dependabot-ecosystem` |
| Actions settings | `GITHUB_TOKEN` read-only and unable to approve pull requests; every outside contributor's run needs approval; only GitHub-owned actions plus the named list in `baseline/selected-actions.json` may run | The pins say which commit runs; this says which actions may run at all. A pull request adding one outside the list fails at workflow start | `workflow-token-read-only`, `fork-pr-approval`, `actions-allowlist` |
| Scanning | Secret scanning, push protection, Dependabot security updates, private vulnerability reporting on | Push protection stops a known credential shape at push time, before gitleaks sees it | `secret-scanning`, `push-protection`, `dependabot-security-updates`, `private-vulnerability-reporting` |
| Risk exceptions | Every ignored advisory is in the register, for that repository, unexpired | An exception cannot be taken quietly or forgotten | `risk-exceptions` |

Each section of BASELINE.md carries the `gh api` command that sets it, and
`scripts/new-repo.sh` applies all of them.

**Lessons the allow-list taught.** An action used from a subdirectory
(`snyk/actions/setup`, `github/codeql-action/init`) needs the subdirectory form of the
pattern as well as the repository form; the repository form alone left a security run
in `startup_failure` with no annotation to say why. A composite action's own `uses:`
lines count: `aquasecurity/trivy-action` calls `aquasecurity/setup-trivy`, and without
that entry every release job failed at start. Read an action's `action.yml` for nested
`uses:` before listing it.

**Deliberately not required yet:** signed commits and tags. The maintainer's laptop signs
with a registered SSH key and verifies; cloud sessions and other machines still commit
unsigned, so a rule would only block them.

## The risk register

`baseline/risk-register.yaml` holds every advisory a pipeline is told to ignore. Taking
an exception is three steps, in this order:

1. **Enter it in the register**: the advisory id and aliases, the package and range, the
   repositories allowed to except it, which check names it, why it is accepted rather
   than fixed, what limits the exposure meanwhile, the date accepted, a `review_by` at
   most 90 days out, and an owner.
2. **Name it in the caller**, with a comment pointing at the entry (`pip-audit-extra-args:
   --ignore-vuln <id>` or `dependency-review-allow-ghsas: <id>`).
3. **Run the audit.** `risk-exceptions` fails on an ignored advisory that is not
   registered, is registered for another repository, or whose review date has passed.

`tests/test_risk_register.py` checks the file's shape and fails the day an entry expires,
and the audit's `register-issues` job opens one issue per entry within 21 days of its
review date, reusing an open one so a renewal never opens a second.

## How to read a red run

Open the job summary. Each repository lists its checks as `PASS`, `FAIL` or `UNKNOWN` with
a one-line reason, and the last line counts them.

- **FAIL** names the setting that drifted. Fix it in the repository using the command in
  BASELINE.md, or, if the baseline was wrong, change the baseline in the same pull request
  that changes the check.
- **UNKNOWN** is a check the token could not make, almost always an expired or under-scoped
  token (a 403 or 404 in the reason). Fix the token, not the check.
- A run that fails **before** the report, at the Doppler step, is a setup problem; the notice
  above it names the missing input.

Run it yourself with your own `gh auth login`:

```sh
python scripts/audit_baseline.py                  # every repository in baseline/repos.txt
python scripts/audit_baseline.py owner/repo       # just this one
python scripts/audit_baseline.py --expiring 21    # register entries due within 21 days; no token
```

## How the audit itself runs

The `audit` job runs only from `main` or the schedule, with harden-runner in `block` mode and
five hosts allowed. Its token, `AUDIT_GITHUB_TOKEN`, is fetched from Doppler over OIDC from a
**separate project** (`audit`), not the shared `ci` config, because it can read the settings of
every repository and every caller reads `ci`. The `register-issues` job holds only the
workflow's own `GITHUB_TOKEN` with `issues: write`. `tests/test_audit_baseline.py` feeds the
audit a passing repository and a broken one per criterion, so the audit that checks the fleet
is itself checked.

## The organization-level gaps

On 2026-10-05 the Hammunition suite moved to the `Renegade-Penguin` organization, and four
things surfaced that the audit cannot yet see or gets wrong. All are open issues:

- **#89: the audit cannot read organization repositories.** `AUDIT_GITHUB_TOKEN` is a
  fine-grained personal token with one resource owner, so a token for the maintainer's account
  cannot read the organization's repositories. The proposal is a GitHub App with read
  permissions, its key in the `audit` Doppler project, minted per run, so no personal token
  remains.
- **#95: the collaborators check reports an organization's owner as an outsider with write
  access.** It excludes the repository owner by login, which under an organization is the
  organization. Measured on all five organization repositories (`FAIL collaborators: others
  with write access`) after the direct grant was already removed.
- **#98: nothing audits the organization itself.** Measured the same day: two-factor
  requirement off, new-repository security defaults off until set by hand (and the transfer
  had applied those defaults to five repositories), the Actions policy unreadable with a
  repository-scoped token. Proposed checks: `org-2fa-required`, `org-new-repo-defaults`,
  `org-actions-policy`, `org-owner-collaborators`.
- **#90, closed:** gitleaks failed on every pull request of an organization-owned repository
  because the action demands a licence for organizations and Doppler is never read on a pull
  request. Fixed by running the MIT binary pinned by sha256 (see
  [Security scanning explained](Security-scanning-explained.md)).

## What this refuses to do

It never counts UNKNOWN as PASS, never writes to a repository (the token is read-only), and
never covers a repository that is not in `baseline/repos.txt`: the list is the scope, and
adding to it is how a repository joins.
