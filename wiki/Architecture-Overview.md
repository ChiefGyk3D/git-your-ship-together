# Architecture Overview

## What a push goes through

```
 project repo (a "caller")                 this repo (the shared pipelines)
┌─────────────────────────┐              ┌──────────────────────────────────┐
│ .github/workflows/      │   uses: @sha │ python-ci.yml / bash-ci.yml /    │
│   ci.yml        ────────┼─────────────▶│ tofu-ci.yml / arduino-ci.yml     │
│   release.yml   ────────┼─────────────▶│ container-release.yml / ...      │
│   security.yml  ────────┼─────────────▶│ security.yml                     │
│   auto-merge.yml ───────┼─────────────▶│ dependabot-auto-merge.yml        │
└─────────────────────────┘              └───────────────┬──────────────────┘
        only says what is                                │ on a trusted ref only
        specific to the project                          ▼
                                          Doppler (OIDC) ── CI credentials
```

For a push or pull request to a calling repository:

1. A **CI workflow per language** runs (`python-ci.yml`, `bash-ci.yml`,
   `tofu-ci.yml`, `arduino-ci.yml`). Each ends in a `CI green` gate.
2. The **security workflow** runs CodeQL, gitleaks, the dependency audit,
   dependency review, Semgrep, and optionally Snyk and Scorecard.
3. The **release workflow** builds, tests and scans, then, only after a push to
   the default branch or a tag, publishes, signs and attests.
4. A separate watcher handles Dependabot's own pull requests.

Branch protection requires only the `CI green` gate(s), so adding a job to a
workflow never leaves it unrequired.

## The shape of every workflow

Every reusable workflow follows the same pattern, which is what makes the
[tests](Testing-and-the-Contract) possible:

- `permissions: contents: read` at the top, widened per job.
- Every job: a timeout, its own `permissions:` block, and
  [harden-runner](Egress-Control) as the **first** step.
- Inputs for every command, passed to the shell through environment variables.
- `egress-policy` / `allowed-endpoints` / `extra-allowed-endpoints` inputs.
- Doppler credentials fetched only when the workflow genuinely needs them, and
  only on a trusted ref.
- Commands that run the **caller's code** live in a job with **no write token and
  no OIDC identity**. Publishing happens in a separate job that runs none of the
  caller's code.

That last point is the most important structural idea: *the job that runs
untrusted-ish code and the job that holds power are never the same job.* You will
see it in `python-ci.yml` (test vs coverage), `docs-pages.yml` (build vs deploy),
`wiki-publish.yml` (generate vs publish) and both release workflows (build vs
publish).

## Map of the repository

### Reusable workflows (`.github/workflows/`)

| File | Family | One line |
|---|---|---|
| `python-ci.yml` | [CI](CI-Workflows) | Lint, type check, test matrix, coverage, smoke test, container build, `CI green` |
| `bash-ci.yml` | [CI](CI-Workflows) | shellcheck, shfmt, tests, config lint, `CI green` |
| `tofu-ci.yml` | [CI](CI-Workflows) | fmt, validate, tflint, Trivy config scan, plan on default branch |
| `arduino-ci.yml` | [CI](CI-Workflows) | Compile every sketch with pinned cores, host tests |
| `python-fuzz.yml` | [CI](CI-Workflows) | Atheris fuzzing for a fixed time per target |
| `container-release.yml` | [Release](Release-Workflows) | Build, test, scan, push multi-arch, sign, SBOM, provenance |
| `python-docker-release.yml` | [Release](Release-Workflows) | Old name of the above; forwards everything |
| `verify-published.yml` | [Release](Release-Workflows) | Verify a published image from outside |
| `python-package-release.yml` | [Release](Release-Workflows) | Build, check, publish to PyPI and the GitHub release |
| `artifact-release.yml` | [Release](Release-Workflows) | Build any file, sign it, attach it to the release |
| `security.yml` | [Security](Security-Workflow) | CodeQL, gitleaks, audit, dependency review, Semgrep, Snyk, Scorecard |
| `dast.yml` | [Security](Security-Workflow) | OWASP ZAP baseline against a loopback service the caller starts, SARIF under `zap` |
| `dependabot-auto-merge.yml` | [Automation](Automation-Workflows) | Auto-merge Dependabot bumps up to a size |
| `project-sync.yml` | [Automation](Automation-Workflows) | Keep a GitHub Projects v2 board current |
| `docs-pages.yml` | [Automation](Automation-Workflows) | Build docs, deploy to GitHub Pages |
| `wiki-publish.yml` | [Automation](Automation-Workflows) | Replace a repository's wiki from a generated tree |

### This repository's own pipeline (not reusable)

| File | Purpose |
|---|---|
| `ci.yml` | actionlint, zizmor, the pytest contract, then every reusable workflow run against `fixture/` at the PR's ref |
| `security-self.yml` | `security.yml` run on this repository |
| `dependabot-auto-merge-self.yml` | `dependabot-auto-merge.yml` run on this repository's own bumps |
| `audit.yml` | The weekly [baseline audit](Repository-Baseline#the-weekly-audit) and risk-register issues |
| `wiki.yml` | Publishes this wiki; see [Maintaining This Wiki](Maintaining-This-Wiki) |

### Everything else

| Path | What it is |
|---|---|
| `.github/actions/doppler-secrets/` | Composite action: fetch a Doppler config as masked env vars. The source of the inlined copies |
| `.github/dependabot.yml` | Weekly action, pip and docker bumps with a seven-day cooldown |
| `BASELINE.md` | The settings every repository must meet, with the `gh api` command for each |
| `baseline/repos.txt` | Which repositories the baseline covers |
| `baseline/selected-actions.json` | The Actions allow-list every repository sets |
| `baseline/risk-register.yaml` | Every advisory a pipeline ignores, with reason and expiry |
| `scripts/audit_baseline.py` | Reads repository settings from the API: PASS / FAIL / UNKNOWN |
| `scripts/new-repo.sh` | Adopt or start a repository: writes callers, opens the PR, applies settings |
| `scripts/doppler-ci-set.sh` | Set one Doppler secret without the value touching a command line |
| `scripts/project_sync.py` | The logic inlined into `project-sync.yml` |
| `scripts/inline_project_sync.py` | Regenerates that inlined copy |
| `scripts/gen_wiki.py` | Builds this wiki from `wiki/` |
| `fixture/` | The smallest project that exercises every job |
| `tests/` | The [contract](Testing-and-the-Contract), as pytest |
| `docs/DESIGN.md`, `docs/ROADMAP.md` | The reasoning, and what is done and next |
| `wiki/` | The source of this wiki |

## Where each kind of change lives

| I want to... | I touch |
|---|---|
| Fix a pipeline bug for every project | The reusable workflow here, then cut a tag; callers get a Dependabot PR |
| Add a scan step | `security.yml` (and its documented input) |
| Allow a new third-party action | The workflow, `baseline/selected-actions.json`, and a PUT to each repo (the point is that this is deliberate) |
| Ignore an advisory | `baseline/risk-register.yaml` first, then the caller |
| Change what repositories must do | `BASELINE.md` and `scripts/audit_baseline.py` together |
