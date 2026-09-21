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

## 2. The default branch

**Protected, with one required check.** A pull request is required, stale
approvals are dismissed on new pushes, force pushes and deletion are off, and
the required status check is `ci / CI green`. That job needs every other job in
`python-ci.yml`, so a job added later is covered without editing the rule.

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

## 3. Secrets never live in GitHub

**Doppler is the only store.** CI reads the `ci` config of the `ci` project,
shared by every repository and separate from every runtime project. It holds
only the names the pipelines use (`DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`,
`SNYK_TOKEN`, optionally `GITLEAKS_LICENSE`; Codecov authenticates with the
job's own OIDC token and stores nothing) and never a runtime credential.
Every value in that config is exported into every CI job, so a runtime token
placed there would be a CI secret in every repository.

**The identity is scoped.** One Doppler Service Account per repository, Viewer
on the `ci` project's `ci` environment and nothing else; one OIDC identity on
it, so Doppler's log says which repository fetched. The
identity's subject must not match a pull request's token (`repo:OWNER/REPO:pull_request`).
Use `repo:OWNER/REPO:ref:refs/heads/main` (and the tag form,
`repo:OWNER/REPO:ref:refs/tags/*`, where Doppler accepts more than one subject
per identity, or a second identity if it does not). The identity's UUID lives
in the repository variable `DOPPLER_IDENTITY_ID`; it is an identifier, not a
secret.

**Secrets are fetched only on a trusted ref.** The shared Doppler step (every
copy of it) fetches only on a push to the default branch, a tag, or a schedule.
A pull request from anywhere and a push to any other branch get nothing, and
the job says so in a notice. This is `doppler-trusted-refs-only`, on by
default; a caller that turns it off is choosing to let a pull request's code
run beside a secret.

**No job that runs on a pull request holds an OIDC token, apart from two whose
steps are pinned actions only** (gitleaks, and the release job's pull-request
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
reaches. The security workflow stays in audit mode until the Snyk job has
been measured with a token in place. Every job starts from
`contents: read`, and widens per job with a reason recorded in
`tests/test_workflows.py`'s `ALLOWED_WRITES`.

**Commands reach the shell as environment variables**, never by template
expansion into `run:`.

Checked: `workflows-pinned`, `uses-shared-workflows`, `dependabot-config`. The
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
scans the full history on every pull request through `security.yml`.

Checked: `secret-scanning`, `push-protection`, `dependabot-security-updates`,
`private-vulnerability-reporting`.

Set with:

```bash
gh api -X PATCH repos/OWNER/REPO \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'
gh api -X PUT repos/OWNER/REPO/private-vulnerability-reporting
gh api -X PUT repos/OWNER/REPO/automated-security-fixes
```

## 7. What is deliberately not required yet

- **Signed commits and tags.** Worth requiring once a signing key exists on
  the maintainer's machine; none does today, so a rule would only block the
  maintainer.
- **harden-runner in `block` mode for `security.yml`.** The Snyk job's hosts
  are unmeasured until a token exists; one audit-mode run with it, then the
  default list gains them and callers switch.

## Adding a repository

Add it to `baseline/repos.txt`, call the three shared workflows as the README
shows, and run the audit until it is clean. A repository that is not in the
list is not covered by the baseline.
