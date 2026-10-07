# Baseline: what every repository must meet

The minimum for a repository that calls these workflows. Each item says what
is required, why, and how it is checked. `scripts/audit_baseline.py` reads
every repository in `baseline/repos.txt` and reports PASS, FAIL or UNKNOWN per
item; UNKNOWN is a question the token could not ask and is never counted as a
pass. Run it from a machine whose `gh` is logged in as the owner:

```bash
python scripts/audit_baseline.py            # exit 1 on any FAIL, 2 on UNKNOWN
```

The threat this baseline is written against is a secret leaving a CI job. A
job can leak a secret in three ways: code that runs beside it (the repository's
own tests and their dependencies, a pull request's proposed changes, a
compromised action), a person with write access, or the secret being stored
somewhere it can be read back. Each item below closes one of those.

## 1. People

**Only the owner can push.** No collaborator holds write, maintain or admin.
Anyone else contributes by pull request from a fork, and a fork's workflow run
never receives a secret (no OIDC token is minted for it, and the Doppler step
refuses it regardless).

Checked: `collaborators` lists nobody but the owner with push permission.
Under an organization the repository's owner is the organization, not a
person, so the owners are the organization's owners (`role=admin` members),
who reach the repository through membership; the check looks at the direct and
outside collaborators and fails on any of them with push who is not one of
those owners. A real outside collaborator with write still fails.

## 2. The default branch, and the tags

**Protected, with one required check per language.** A pull request is
required, stale approvals are dismissed on new pushes, force pushes and
deletion are off, and the required status checks are the `CI green` gates of
every shared CI workflow the repository calls: `ci / CI green` for a job
named `ci` that uses `python-ci.yml`, `shell / CI green` for a job named
`shell` that uses `bash-ci.yml`, and so on, one caller job per language. Each
gate needs every other job in its workflow, so a job added later is covered
without editing the rule. The audit reads the caller's workflow files, derives
the set from every job whose `uses:` names a shared `*-ci.yml`, and fails on
any gate branch protection does not require. A repository that calls no
shared CI workflow is held to `ci / CI green`, so the expected name is still
stated.

**No approval count.** GitHub does not let an author approve their own pull
request, and these repositories have one person with write access, so a count
of one never produces a review: it only blocks the merge until the owner
overrides it as an administrator, which teaches the habit of overriding. Zero
keeps the pull request and the green check required and lets a Dependabot bump
merge on its own once `ci / CI green` passes. Any review that is given is
still dismissed by a new push.

Checked: `required-check`, `pull-request-required`, `history-protected`.

Set with:

```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection --input - <<'JSON'
{"required_status_checks": {"strict": false, "checks": [{"context": "ci / CI green"}]},
 "enforce_admins": false,
 "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": true},
 "restrictions": null, "required_linear_history": false,
 "allow_force_pushes": false, "allow_deletions": false, "required_conversation_resolution": false}
JSON
```

**Auto-merge is allowed.** A Dependabot bump has already cleared three
gates by the time it is mergeable: the seven-day cooldown in
`dependabot.yml`, `ci / CI green`, and the required pull request. The click
that follows adds nothing, so `dependabot-auto-merge.yml` queues the merge
and GitHub performs it when the checks pass. Without this setting the
workflow's `gh pr merge --auto` fails and the bumps pile up.

Checked: `auto-merge-enabled`.

**Version tags are immutable.** A ruleset on `refs/tags/v*` forbids deleting,
moving and force-pushing a tag. Callers pin commit SHAs, so a moved tag
changes nothing about what runs, but Dependabot follows tags and zizmor
compares a pin against the tag its comment names: a tag moved onto another
commit is the one way a pin and its comment can come to disagree with no
commit anywhere to show for it. A version cut by mistake is superseded by the
next number, not deleted and reused; that is what this rule makes the only
option. Lifting it for a genuine mistake is a deliberate edit to the ruleset.

Checked: `tag-ruleset`.

Set with:

```bash
gh api -X PATCH repos/OWNER/REPO -F allow_auto_merge=true
gh api -X POST repos/OWNER/REPO/rulesets --input - <<'JSON'
{"name": "Version tags are immutable", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
 "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}]}
JSON
```

## 3. Secrets never live in GitHub

**Doppler is the only store.** CI reads the `ci` config of the `ci` project,
shared by every repository and separate from every runtime project. It holds
only the names the pipelines use (`DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`,
`SNYK_TOKEN`; Codecov authenticates with the
job's own OIDC token and stores nothing) and never a runtime credential.
Every value in that config is exported into every CI job, so a runtime token
placed there would be a CI secret in every repository.

**The identity is scoped.** One Doppler Service Account per repository, Viewer
on the `ci` project's `ci` environment and nothing else; one OIDC identity on
it, so Doppler's log says which repository fetched. The
identity's subject must not match a pull request's token (`repo:OWNER/REPO:pull_request`).
List `repo:OWNER/REPO:ref:refs/heads/main` and the immutable form
`repo:OWNER@<owner-id>/REPO@<repo-id>:ref:refs/heads/main`, each with its
`:ref:refs/tags/*` twin: GitHub sends the immutable form from repositories
created from mid-2026 and the plain form from older ones (the repository's
`actions/oidc/customization/sub` setting says which). The identity's UUID lives
in the repository variable `DOPPLER_IDENTITY_ID`; it is an identifier, not a
secret.

**Secrets are fetched only on a trusted ref.** The shared Doppler step (every
copy of it) fetches only on a push to the default branch, a tag, or a schedule.
A pull request from anywhere and a push to any other branch get nothing, and
the job says so in a notice. This is `doppler-trusted-refs-only`, on by
default; a caller that turns it off is choosing to let a pull request's code
run beside a secret.

**No job that runs on a pull request holds an OIDC token, apart from one whose
steps are pinned actions only** (the release job's pull-request
build, whose Dockerfile runs inside containers that never see the runner's
token request). In particular the job that runs the repository's own tests has
no `id-token`; Codecov uploads happen in a separate job that never runs on a
pull request. `tests/test_workflows.py` enforces this.

**`secrets: inherit` is never used.** A caller passes `DOPPLER_TOKEN` by name,
and it may be unset.

Checked: `doppler-identity` (the variable exists and is a UUID; a repository
whose workflows never read `DOPPLER_IDENTITY_ID` has nothing to set and passes) and
`workflows-pinned` (no `secrets: inherit`). The Doppler side is checked by
hand: `doppler secrets --project P --config ci --only-names` must list only
CI names, and the identity's subject must be the tight form.

## 4. Workflows

**Every action is pinned to a commit SHA** with a version comment, and every
reference to this repository's workflows names its tag in a `# vX.Y.Z` comment
so zizmor's online audit can confirm the two agree. Dependabot moves the pins,
with a seven-day cooldown so a freshly cut release is not adopted the hour it
appears.

**Every job runs under harden-runner in `block` mode** for the CI and release
workflows, with the measured allow-list the shared workflows carry as their
default and `extra-allowed-endpoints` for a host only that repository
reaches; the security workflow's list carries the Snyk hosts from Snyk's
documentation, corrected by any `domain not allowed` line. Every job starts from
`contents: read`, and widens per job with a reason recorded in
`tests/test_workflows.py`'s `ALLOWED_WRITES`.

**Containers a job starts are outside harden-runner's view.** The `distro`
job runs a distribution's official image as root in a throwaway container to
execute the caller's own install and test commands. The container shares the
job's network namespace, so the egress block still applies to it. Nothing from
a pull request's fork can reach it, because its inputs are the caller's
workflow file. StepSecurity's "unmonitored container" finding on these jobs is
accepted for that reason.

**Commands reach the shell as environment variables**, never by template
expansion into `run:`.

**Dependabot bumps merge themselves up to a size.** Every repository calls
`dependabot-auto-merge.yml` from a `pull_request` workflow. Its default
`max-update-type: minor` leaves a major bump, and any pull request whose
update type Dependabot did not report, open for a person. The job checks
nothing out, so the write it holds never runs beside proposed code.

**A universal uv lock is updated by the `uv` ecosystem.** A lock compiled by
`uv pip compile --universal` is updated by Dependabot's `uv` ecosystem, never
`pip`, because pip re-resolves it for one interpreter and drops the
marker-gated lines. The bump then fails `pip install --require-hashes` on part
of the Python matrix. The `uv` ecosystem runs `uv pip compile` again and keeps
`--universal`, `--python-version` and `--generate-hashes` from the lock's
header. A repository whose root `requirements.txt` or `requirements-dev.txt`
carries that header, with a `pip` entry for `/` in `dependabot.yml` or no
`dependabot.yml` at all, fails.

Checked: `workflows-pinned`, `uses-shared-workflows`, `dependabot-config`,
`dependabot-ecosystem`. The
harden-runner, permissions and injection rules are properties of the shared
workflows themselves and are tested here on every commit.

## 5. Actions settings

**`GITHUB_TOKEN` defaults to read-only and cannot approve pull requests**
(Settings → Actions → General → Workflow permissions).

**Every outside contributor's workflow run needs approval**, not only a
first-time contributor's (Settings → Actions → General → Fork pull request
workflows). A fork's run holds no secret either way; this keeps a stranger's
code from consuming runner minutes or probing the workflows unattended.

**Only GitHub-owned actions and a named list of third-party ones may run**
(Settings → Actions → General → Actions permissions → "Allow OWNER, and
select non-OWNER, actions and reusable workflows"). The pins in the workflow
files say which commit of an action runs; this setting says which actions may
run at all, so a pull request that adds one outside the list fails at workflow
start whatever its pin says. Marketplace "verified creator" is not a list and
stays off. An action used from a subdirectory of its repository (Snyk's
`snyk/actions/setup`, CodeQL's `github/codeql-action/init`) needs the
subdirectory form of the pattern as well as the repository form; the
repository form alone left a security run in `startup_failure` with no
annotation to say why. A composite action's own `uses:` lines count too:
`aquasecurity/trivy-action` calls `aquasecurity/setup-trivy`, and without
that entry every release job failed at start until it was added. Before
adding an action, read its `action.yml` for nested `uses:` and list those.

Checked: `workflow-token-read-only`, `fork-pr-approval`, `actions-allowlist`
(allowed_actions is `selected`, GitHub-owned on, verified creators off, at
least one pattern).

Set with:

```bash
gh api -X PUT repos/OWNER/REPO/actions/permissions/workflow \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
gh api -X PUT repos/OWNER/REPO/actions/permissions/fork-pr-contributor-approval \
  -f approval_policy=all_external_contributors
gh api -X PUT repos/OWNER/REPO/actions/permissions -F enabled=true -f allowed_actions=selected
gh api -X PUT repos/OWNER/REPO/actions/permissions/selected-actions \
  --input baseline/selected-actions.json
```

`baseline/selected-actions.json` is the list: every third-party action the
three shared workflows use, plus `OWNER/*` so the shared workflows themselves
resolve. A new third-party action in this repository is a change to that file
and a PUT to every calling repository, which is the point.

## 6. Scanning

**Secret scanning with push protection**, **Dependabot security updates** and
**private vulnerability reporting** are on. Push protection refuses a commit
carrying a known credential shape before gitleaks ever runs; gitleaks then
scans the full history on every pull request through `security.yml`. The
byte-identical `.githooks/pre-commit` is also present in every repository;
`scripts/new-repo.sh` installs it and documents how to enable it per checkout.

Checked: `secret-scanning`, `push-protection`, `dependabot-security-updates`,
`private-vulnerability-reporting`, `pre-commit-hook`.

Set with:

```bash
gh api -X PATCH repos/OWNER/REPO \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
gh api -X PUT repos/OWNER/REPO/private-vulnerability-reporting
gh api -X PUT repos/OWNER/REPO/automated-security-fixes
```

## 7. Risk exceptions are registered

**An advisory a pipeline ignores is written down, with a reason and an expiry.**
Two inputs of `security.yml` let a caller skip an advisory: `pip-audit-extra-args:
--ignore-vuln <id>` and `dependency-review-allow-ghsas: <id>`. The usual case is
an advisory with no fixed release yet. Each ID a caller names must have an
entry in [`baseline/risk-register.yaml`](baseline/risk-register.yaml) for that
repository: the affected package, why it is accepted rather than fixed, what
limits the exposure meanwhile, the date it was accepted, a `review_by` date at
most 90 days out, and an owner. An exception that is not in the register, is
registered for another repository, or whose review date has passed, fails the
audit. `tests/test_risk_register.py` checks the file's shape and dates.

Checked: `risk-exceptions`.

## 8. What is deliberately not required yet

- **Signed commits and tags.** The laptop signs with a registered SSH key
  and its commits and tags verify. The rule is not on yet because the cloud
  sessions and the other machines still commit unsigned, and a rule would
  block them; it goes on when they sign too (roadmap item 14).

## Organizations

When a repository's owner is an organization, three things that decide its
posture live on the organization, and the audit reads the organization once per
run (not once per repository), under the heading `<org> (organization)`. A
repository under a user account has none of these lines.

- **`org-2fa-required`**: the organization requires two-factor authentication
  of its members (`two_factor_requirement_enabled`). Set under Settings,
  Authentication security.
- **`org-new-repo-defaults`**: secret scanning, push protection, Dependabot
  alerts, Dependabot security updates and the dependency graph are all on for
  new repositories (the five `*_enabled_for_new_repositories` fields). A
  repository transferred in takes these over its own settings: the 2026-10-05
  transfer of five repositories into Renegade-Penguin turned secret scanning
  and push protection off on all five because the organization's defaults were
  off. GitHub marks these fields as superseded by code security
  configurations; while it still returns them the audit reads them, and if it
  stops, the check goes UNKNOWN rather than quietly passing.
- **`org-actions-policy`**: the organization allows `selected` actions only (or
  `all`, but only when every audited repository of that organization narrows it
  itself, which `actions-allowlist` proves), and its default `GITHUB_TOKEN`
  permission is `read`.
- **`org-owner-collaborators`**: the organization's owners can be read, and
  there is at least one. This is the owner set the `collaborators` check holds
  the repositories to (see section 1); if it cannot be read, `collaborators` is
  UNKNOWN too.

A check the token could not read is UNKNOWN and names the permission it
needed: the organization endpoints need the App's **Organization
administration: read** (2FA, defaults, Actions policy) and **Members: read**
(the owner list). See the README, "The weekly audit", for the permission list.

## How the audit runs

The checks above are read from the GitHub API by `scripts/audit_baseline.py`,
which `.github/workflows/audit.yml` runs every Monday at 07:00 UTC over every
repository in `baseline/repos.txt`, with read-only GitHub App installation
tokens minted for the run, one per owner (the user account and the
organization). The App's private key is held in its own Doppler project
(`audit`), never in the shared `ci` config; no personal access token is used.
Each organization found is audited once as well. A FAIL or an
UNKNOWN makes the run red, and the same workflow opens an issue here for any
risk-register entry within 21 days of its `review_by`. Setup and the App's
permissions are in the README's "The weekly audit".

## Adding a repository

`scripts/new-repo.sh OWNER/NAME` does all of it: the caller files with one
CI job per language, the pull request, every setting above, the line in
`baseline/repos.txt`. The Doppler identity is the one step it prints for a
person. Then run the audit until it is clean. A repository that is not in the
list is not covered by the baseline.
