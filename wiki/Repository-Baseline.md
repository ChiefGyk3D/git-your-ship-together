# Repository Baseline

The workflows protect what runs. The **baseline** is the set of repository settings that **no YAML can
set**, and the audit that checks them. The authoritative text, with the `gh api` command that sets each item,
is [BASELINE.md](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/BASELINE.md).
Which repositories are covered:
[`baseline/repos.txt`](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/baseline/repos.txt).
**A repository that is not in the list is not covered.**

## The items, and why

| # | Area | Requirement | Why |
|---|---|---|---|
| 1 | People | Only the owner can push; everyone else contributes from a fork | A fork's run never receives a secret |
| 2 | Default branch | Protected; PR required; stale approvals dismissed; no force-push or deletion; required checks are the `CI green` gate of **each** shared CI workflow called | One gate per language, so a job added later is covered automatically |
| 2 | Approvals | Required count **zero** | A count of one on a one-writer repo only teaches overriding as admin ([why](Design-Rules-and-Why#required-review-count-is-zero-on-single-maintainer-repositories)) |
| 2 | Auto-merge | Allowed | Without it `dependabot-auto-merge.yml`'s `gh pr merge --auto` fails |
| 2 | Tags | Ruleset on `refs/tags/v*` forbids delete, move, force-push | Dependabot follows tags; a moved tag is the one way a pin and its version comment can silently disagree |
| 3 | Secrets | Doppler only; per-repo Service Account and identity; fetch on trusted refs only; no `secrets: inherit`; **no GitHub Actions secrets** | See [Secrets and Doppler](Secrets-and-Doppler) |
| 4 | Workflows | SHA pins with version comments; harden-runner `block`; shared workflows used; Dependabot configured | See [Design Rules and Why](Design-Rules-and-Why) |
| 5 | Actions settings | Token read-only and unable to approve PRs; **all** outside contributors' runs need approval; only GitHub-owned plus a named allow-list of actions may run | The pin says which commit runs; the setting says which actions may run at all |
| 6 | Scanning | Secret scanning, push protection, Dependabot security updates, private vulnerability reporting | Push protection stops a known credential shape before gitleaks ever sees it |
| 7 | Risk exceptions | Every ignored advisory is registered with a reason and expiry | An exception cannot be taken quietly or forgotten |
| 8 | Deliberately not yet | Signed commits and tags | Some machines still commit unsigned |

## What the audit checks

`scripts/audit_baseline.py` reads each repository's settings and workflow files from the GitHub API and
reports `PASS`, `FAIL` or `UNKNOWN` per check:

| Check | Verifies |
|---|---|
| `collaborators` | Nobody but the owner has push permission |
| `required-check` | Every `CI green` gate derived from the caller's workflows is a required status check |
| `pull-request-required` | A pull request is required, approval count zero, stale reviews dismissed |
| `history-protected` | Force pushes and deletion are off |
| `auto-merge-enabled` | Allow auto-merge is on |
| `tag-ruleset` | `refs/tags/v*` is immutable |
| `doppler-identity` | The `DOPPLER_IDENTITY_ID` variable exists and is a UUID (passes if the workflows never read it) |
| `workflows-pinned` | Every action is SHA-pinned; no `secrets: inherit` |
| `uses-shared-workflows` | The repository calls the shared workflows |
| `dependabot-config` | `dependabot.yml` exists with the right ecosystems |
| `dependabot-ecosystem` | A universal uv lock is updated by the `uv` ecosystem, not `pip` |
| `workflow-token-read-only` | `GITHUB_TOKEN` defaults to read and cannot approve PRs |
| `fork-pr-approval` | Every outside contributor's run needs approval |
| `actions-allowlist` | Selected actions only; GitHub-owned on, verified creators off, at least one pattern |
| `secret-scanning`, `push-protection` | Both enabled |
| `dependabot-security-updates` | Enabled |
| `private-vulnerability-reporting` | Enabled (so SECURITY.md's link works) |
| `risk-exceptions` | Every ignored advisory is registered for *this* repository and unexpired |

**`UNKNOWN` is never a pass.** A check the token could not make (a 403, a 404) is reported honestly. Exit codes:
`0` all passed, `1` at least one FAIL, `2` no FAIL but at least one UNKNOWN.

```sh
python scripts/audit_baseline.py                 # every repo in baseline/repos.txt
python scripts/audit_baseline.py owner/repo ...  # just these
python scripts/audit_baseline.py --expiring 14   # register entries due soon; no token needed
```

## The weekly audit

`.github/workflows/audit.yml` runs on **Monday 07:00 UTC** and on demand. Two jobs:

- **`audit`** runs the script over every repository and writes the report to the job summary. Red on any FAIL **and
  on any UNKNOWN**. Its token (`AUDIT_GITHUB_TOKEN`, fine-grained, read-only) lives in a **separate Doppler
  project** (`audit`), because it can read every repository's settings and the shared `ci` config is read by every
  caller. It runs only from `main` or the schedule, in `block` mode with five hosts.
- **`register-issues`** holds only the workflow's own `GITHUB_TOKEN` (`issues: write`). It opens one issue per
  risk-register entry whose `review_by` is within 21 days or past, reusing an open one (and editing its title if the
  date moved) so renewal never opens a second.

**Reading a red run:** open the job summary. A `FAIL` names the setting that drifted; fix the repository (or, if the
baseline was wrong, change baseline and check in the same PR). An `UNKNOWN` is almost always an expired or
under-scoped token: fix the token, not the check. A run failing at the Doppler step is a setup problem.

The token setup (Doppler project, service account, repository variable, fine-grained PAT permissions) is in the README's
[The weekly audit](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#the-weekly-audit).

## The risk register

Sometimes a scanner names an advisory that cannot be fixed yet (the newest release is the affected one, or it is a
transitive dependency nothing calls). Two inputs of `security.yml` can skip one. Taking an exception is **three steps,
in this order**:

1. **Enter it in
   [`baseline/risk-register.yaml`](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/baseline/risk-register.yaml)**:
   advisory ID and aliases, package and range, the repositories allowed to except it, which check names it, the reason
   it is accepted not fixed, what limits the exposure meanwhile, date accepted, a `review_by` **at most 90 days out**,
   and an owner.
2. **Name it in the caller**, with a comment pointing at the entry.
3. **Run the audit.** `risk-exceptions` fails on an ignored advisory that is unregistered, registered for another
   repository, or past its review date.

When the fix ships, remove both the caller's line and the entry. Renewing means moving `review_by` and saying why.

## Setting the baseline up on a repository

Do not do it by hand: [Adopting a Repository](Adopting-a-Repository) applies every setting for you.
