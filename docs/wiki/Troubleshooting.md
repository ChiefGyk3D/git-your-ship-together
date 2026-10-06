# Troubleshooting

Symptom, likely cause, fix. Many of these cost an afternoon the first time; the stories are in
[Lessons learned](Lessons-learned.md).

## Network and egress

| Symptom | Cause | Fix |
|---|---|---|
| `domain not allowed: <host>` in a job log | `block` mode and the host is not on the list | If expected, add it to `extra-allowed-endpoints` in *your caller*. If not expected, investigate: something new is talking to the network |
| Everything is blocked, even PyPI, after you edited a list | The allow-list was written as a YAML `|` block (newlines), or contains a wildcard | One space-separated line, or a folded `>` block. No `*.example.com` |
| `fedora:*` distro job fails fetching packages | `dnf` mirrors change per run | `distro-egress-policy: audit`, or add the mirrors you observed |

## Doppler and secrets

| Symptom | Cause | Fix |
|---|---|---|
| `claim "sub" does not match identity auth config` | The Doppler identity lists only the plain subject; the repository sends the **immutable** one (default from mid-2026) | Add **both** subject forms, each with its tag twin. Doppler has no identity update: create a new identity, point `DOPPLER_IDENTITY_ID` at it, delete the old |
| Snyk, Docker Hub or project-sync step "skipped" with a notice | A pull request or non-default branch: secrets are fetched only on trusted refs | Working as designed. Test on the default branch, a tag or a schedule |
| Secret step does nothing, no error | `doppler-identity-id` unset and no `DOPPLER_TOKEN`: path 3 ("nothing") | Set `DOPPLER_IDENTITY_ID` (a repository **variable**) and pass `doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}` |
| Snyk job fails with exit 2 | Expired or revoked `SNYK_TOKEN` | Renew it with `scripts/doppler-ci-set.sh SNYK_TOKEN`. The token expires; note the date |
| `project-sync` needs a fetch on `pull_request_target` but skips | `doppler-trusted-refs-only` is `true` | Set `false` in *that caller only*; never in a caller that checks out the PR |
| `project-sync` fails on `pull_request_target` with `claim "sub" does not match` | The identity has no `:pull_request` subject, as the `ci` identity must not | Use the `projects`/`prd` scope and its own identity (`PROJECTS_DOPPLER_IDENTITY_ID`), or pass `pull-request-events: false`, or drop the trigger from the caller |
| zizmor `dangerous-triggers` on a `project-sync` caller | The trigger is the finding | Keep the two `# zizmor: ignore[dangerous-triggers]` lines from the README template, with their reason |
| `Input 'app-id' has been deprecated` | The caller passes `app-id` | Pass `client-id: ${{ vars.PROJECTS_APP_CLIENT_ID }}` instead |

## Actions settings and startup

| Symptom | Cause | Fix |
|---|---|---|
| Run ends `startup_failure` with no annotation | An action (or a *nested* action inside a composite) is not on the Actions allow-list | Read the action's `action.yml` for nested `uses:`; add both repository and **subdirectory** forms to `baseline/selected-actions.json` and PUT it |
| `uses:` line rejected / resolves oddly | Pinned to a **tag object** SHA, not a commit | Use the `^{}` (peeled) line from `git ls-remote --tags` |
| zizmor: `ref-version-mismatch` | The `# vX.Y.Z` comment names a tag that does not match, or does not exist | Fix the comment, or fetch tags and check what exists |
| Dependabot bumps pile up unmerged | *Allow auto-merge* is off, or no required status check | Enable per BASELINE.md; the audit's `auto-merge-enabled` check says so |
| Auto-merge left a PR open | It is a **major** bump, or Dependabot reported no update type (fails closed) | Review and merge by hand |
| A Dependabot bump to a universal lock breaks part of the Python matrix | The lock is being updated by the `pip` ecosystem, which re-resolves for one interpreter | Use the `uv` ecosystem for that file (audit check `dependabot-ecosystem`) |

## Scanners

| Symptom | Cause | Fix |
|---|---|---|
| Snyk: "Missing required packages" / exit 2 | Snyk's resolver refuses a universal lock | Already handled: the workflow scans a `pip freeze`. If you see it, you are on an old pin |
| Snyk "nothing to scan" warning (exit 3) | Shell-only repo, or a `pyproject.toml`-only repo with no lock | Expected for shell-only. For `pyproject.toml`, set `snyk-install-command: pip install .` |
| Trivy flags `setuptools`/`msgpack` that upgrading doesn't clear | They are **pip's vendored copies** under `pip/_vendor` | `pip uninstall -y pip` as the last build step; a runtime image has no use for it |
| CodeQL fails for a language | `codeql-languages` lists one the repository has no source for | Pass only the languages present (`actions` alone is valid) |
| Semgrep finds shell issues you expected | No Semgrep registry pack covers shell | ShellCheck (`bash-ci.yml`) is the shell coverage |
| A pip-audit/dependency-review exception fails the audit | It is not in `baseline/risk-register.yaml`, is registered for another repo, or `review_by` passed | Register it first (reason, mitigation, owner, expiry <=90 days), or renew/remove it |

## Releases

| Symptom | Cause | Fix |
|---|---|---|
| Package release refuses the tag | The tag's version disagrees with the version in the built sdist | Make them agree; `tag-prefix` controls what precedes the version |
| PyPI publish is rejected | The Trusted Publisher on PyPI does not name the **caller's** workflow filename and the `pypi` environment | Fix the Publisher entry on PyPI's *Publishing* page |
| Cosign verification fails on the identity | You matched the caller's workflow; the certificate names the **reusable** workflow | Use `--certificate-identity-regexp '^https://github.com/ChiefGyk3D/git-your-ship-together/'` |
| Temporary `<sha>-<arch>` tags clutter GHCR | Each platform job pushes one before the merge job joins them | Delete them when you no longer need them |
| Docs `deploy` fails with a Pages message | Pages source is not "GitHub Actions" | Settings, Pages, Source: GitHub Actions. `deploy: false` meanwhile |
| Wiki `publish` fails: "no first page yet" | GitHub only creates a wiki's git repo when a page is made in the UI | Create any page once, re-run ([Maintaining this wiki](Maintaining-this-wiki.md)) |

## The audit

| Symptom | Cause | Fix |
|---|---|---|
| Audit red with `UNKNOWN` | The App could not ask: a read permission missing from the App, or a repository (or owner) its installation does not include (403/404 in the reason; an `org-*` line names the permission) | Fix the **App**, not the check |
| Audit fails at the Doppler step, or at *Mint a one-hour installation token* | `AUDIT_DOPPLER_IDENTITY_ID`, the `audit` Doppler project or the identity is not set up; or `AUDIT_APP_CLIENT_ID` or the key is wrong, or the App is not installed on that owner | Setup steps in the README, "The weekly audit" |
| `FAIL` names a setting | It drifted | Fix the repository using BASELINE.md's `gh api` command; if the *baseline* was wrong, change the baseline and the check in the same PR |

## Tests (when you are contributing)

| Symptom | Cause | Fix |
|---|---|---|
| `...grants id-token: write. If intended, add it to ALLOWED_WRITES` | A new write permission | If genuinely needed, add it to `ALLOWED_WRITES` with a reason |
| An input is "not documented" | Missing README table row | Add the row |
| The inlined Doppler script differs from the action | You edited one copy | Edit `.github/actions/doppler-secrets/action.yml` and regenerate/sync every inlined copy |
| `tests/test_wiki.py` says a thing is not mentioned | The wiki has not caught up | Add it to the right page ([Maintaining this wiki](Maintaining-this-wiki.md)) |
