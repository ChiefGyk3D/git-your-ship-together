# Verify main

**What it does.** `main-verify.yml` checks, after the fact, that the head of the default branch has a green run of every
required check, and starts CI when it has none.

**Why it exists.** A push made with the job token (the Dependabot auto-merge is one) starts no workflow runs, so on 2026-11-09
commit 52592bc reached `main` with none. GitHub documents the exception this uses: `workflow_dispatch` and
`repository_dispatch` events always create workflow runs
([the GITHUB_TOKEN page](https://docs.github.com/en/actions/concepts/security/github_token), read 2026-11-09).

## What runs

It runs on a push to `main`, at minute 17 every six hours, and by hand; a run from another branch does nothing. Three jobs,
each with its own permissions, driven by `scripts/verify_main.py`:

1. **assess** (`contents`, `checks`, `actions`: read). Reads the head commit and the required checks on it. All green: one
   line and the run ends (quiet and idempotent). Any red: fails. Some reported: `pending`. None reported: waits until the
   commit is 10 minutes old, then, unless a `ci.yml` run for it is queued or running, asks for a dispatch.
2. **dispatch** (`contents: read`, `actions: write`, the only write). Dispatches `ci.yml` on the default branch, unless `main`
   has moved since assess.
3. **confirm** (read only). Waits at most 25 minutes, polling every 30 seconds, for every required check on the head to
   complete. Fails if one is red, or if any is still missing or running at the end.

The failure annotation names the red, running and missing contexts and the counts, nothing else.

## Required checks

Read from the branch protection (`required_status_checks`) when the token can; that endpoint usually wants repository admin, so
the job falls back to `FALLBACK_CONTEXTS` in the workflow (`CI green`). Keep the two equal; the weekly audit checks the
protection. A check run counts only when it comes from the app the protection names, else GitHub Actions, so another app
cannot satisfy a required name.

## Limits

- The push trigger is not created for a push made with the job token, so a bot-merged commit is caught by the six-hour schedule,
  up to six hours late. A push by a person or an app is caught at once.
- `ci.yml` must keep `workflow_dispatch`; `tests/test_verify_main.py` fails without it.
- Not reusable: a reusable form would need the script inlined and an input for the CI workflow's file name. Copy the workflow
  and `scripts/verify_main.py` into another repository and set `CI_WORKFLOW` and `FALLBACK_CONTEXTS`.
