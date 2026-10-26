# wait-ci

**What it does.** Waits for CI on one commit and says, with an exit code, whether that commit is green. It pins the head SHA when
it starts, checks only that commit, and can then squash-merge exactly that commit. It is one tested script, `scripts/wait-ci.sh`,
and a composite action, `.github/actions/wait-ci`, that wraps it. It is not a reusable workflow: a watcher belongs in the monitor
that is waiting, not in a job of the run being waited on.

**Why it exists.** Hand-written loops over `mergeStateStatus` reported a pull request clean or completed when it was not, five
times on 2026-10-25. The usual causes: a check that had not been registered yet, an aggregate gate that had not reported (the
race seen on GYST #218), and a push that moved the head under the loop. This script refuses each of those.

## The rules

- **The head is pinned.** With `--pr` the head SHA is read once and every check query names that SHA, never the branch.
  With `--sha` and `--pr` together the SHA must equal the head, or the run exits 4 before it checks anything. With `--sha` alone
  (a commit on a default branch, say) there is no head to move.
- **Green needs all three:** every required context (default `CI green`) reported on the pinned SHA and concluded `success`;
  at least `--min-checks` check runs completed; and no check run failed, was cancelled, timed out, needed action or failed to start.
- **No check runs is not green.** `--min-checks` cannot be below 1, so an empty list never passes, even with no named context.
- **A context that has not reported is not green.** Twenty passing jobs and no `CI green` yet means keep waiting.
- **Names match exactly.** The comparison is a literal string compare: `CI green (old)`, `ci green`, `CI green ` with a trailing
  space, `xCI green` and a glob such as `CI *` do not satisfy `CI green`. Skipped and neutral are not `success`.
- **Red is immediate.** A failed or cancelled check run ends the wait with exit 1 even while the gate is still running.
- **A push aborts or resets.** `--on-push abort` (the default) exits 4 when the pull request head moves. `--on-push reset`
  pins the new head and starts over; the total `--timeout` keeps running, so a stream of pushes cannot extend the wait forever.
  Once the pinned commit has verified green, a push is always exit 4: the watcher never merges what it did not verify.
- **Hung is not slow.** `--hung-after` counts seconds with no check run changing state. A slow run that keeps completing checks
  does not trip it; a run frozen on one job does, with exit 3. A failing GitHub API counts as no progress.
- **The merge is pinned.** `--merge` runs `gh pr merge N --squash --match-head-commit <verified sha>`. If it fails, the head is
  read again: moved means exit 4 with nothing merged; already merged at the verified commit means success; anything else
  (a branch policy block, a required context still arriving) is retried `--merge-retries` times, `--merge-retry-delay` seconds
  apart, then exit 1 with `merge blocked`. It never passes `--admin` or `--auto`.
- **It prints the SHA it verified:** `wait-ci: verified <sha>: green`.
- **It never prints a token.** Every line of `gh` output that reaches the log is cut to one line and has the value of `GH_TOKEN` and
  `GITHUB_TOKEN` replaced. The script does not trace (`set -x`) and does not `eval`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Green. With `--merge`, merged (or already merged at the verified commit). |
| `1` | Red: a check failed or was cancelled. Also: `--merge` ran out of retries (the output says `merge blocked`), or the head could not be read. |
| `2` | Timeout: no verdict after `--timeout` seconds. |
| `3` | Hung: no check changed for `--hung-after` seconds. |
| `4` | Head moved: the pull request head is no longer the pinned SHA (at the start, while waiting, between the last check and the merge, or during the merge). |
| `64` | Bad input; nothing was waited on and `gh` was not called. |

The timeout is tested before hung, so a run that is past both reports `2`.

## Use as a script

```sh
GH_TOKEN="$(gh auth token)" scripts/wait-ci.sh --repo OWNER/REPO --pr 123 --merge --delete-branch
echo "exit=$?"
```

Run it from a checkout of this repository at a pinned commit, or fetch the file at that commit. It needs `bash`, `gh` and `cksum`.
`GH_BIN` names a different `gh` (the tests use a fake). When `GITHUB_OUTPUT` is set it appends `result`, `sha` and `merged`.

Options: `--repo`, `--pr`, `--sha`, `--context` (repeatable; `--context ''` means no named gate), `--min-checks`, `--timeout`,
`--hung-after`, `--interval`, `--on-push`, `--merge`, `--delete-branch`, `--merge-retries`, `--merge-retry-delay`. The header of
the script lists the defaults.

## Use as an action

Pin by commit with the version comment, as every GYST caller does. Run it from a workflow that is not part of the gate it waits on:
a step in a job that `CI green` needs would wait for its own check run.

```yaml
jobs:
  merge-when-green:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    permissions:
      checks: read
      pull-requests: write
      contents: write
    steps:
      - uses: ChiefGyk3D/git-your-ship-together/.github/actions/wait-ci@<commit> # vX.Y.Z
        with:
          pr: ${{ github.event.inputs.pr }}
          merge: "true"
```

The action needs no checkout; a composite action is fetched with the repository it lives in, and the step calls
`scripts/wait-ci.sh` from there. Inputs reach the script through environment variables and quoted arguments only.
A merge made with the default workflow token does not start other workflows, which matters if a push to the base
branch is supposed to trigger a deploy; pass a different `token` when it does.

| Input | Meaning |
|---|---|
| `repo` | `OWNER/REPO`, default the current repository. |
| `pr` | Pull request number; needed for `merge`. Give this or `sha`. |
| `sha` | Full 40-character SHA to verify; with `pr` it must equal the head. |
| `context` | Required check run names, one per line, exact. Default `CI green`; empty means no named gate. |
| `min-checks` | Check runs that must be complete, at least 1. |
| `timeout` | Total seconds before exit 2. |
| `hung-after` | Seconds without change before exit 3. |
| `interval` | Seconds between polls. |
| `on-push` | `abort` or `reset`. |
| `merge` | `true` to squash-merge the verified commit; `true` or `false` only. |
| `delete-branch` | With `merge`, delete the head branch. |
| `merge-retries` | Retries after a failed merge attempt. |
| `merge-retry-delay` | Seconds between merge attempts. |
| `token` | Token for `gh`; default the workflow token. |

Outputs: `result` (`green`, `red`, `timeout`, `hung`, `head-moved`, `merge-blocked`, `error` or `usage`), `sha` (the verified commit,
empty unless green) and `merged`. The outputs are written even when the step fails, so a later `if: always()` step can read them.

## What it does not do

- It reads check runs, not the older commit statuses. A required context that only reports as a commit status is never seen.
- It does not rerun failed jobs and it does not read branch protection; name the contexts you require.
- It does not wait for checks that are not part of the gate: with the gate green and an unrelated check still running, the
  commit is green. Add the check to `context` to require it.

## How it is tested

`tests/test_wait_ci.py` runs the real script under bash against a fake `gh` (a Python program driven by a scenario) with a fake
clock, so waits cost no time and every call is on record. It covers the pinned head, abort and reset on a push, no checks, a
context that has not reported, exact matching, failed and cancelled, timeout, hung, merge retry and its bound, a head that moves
between the last check and the merge, a token that must not appear, bad input, and the action's own step run end to end.
The head pin, the required-context rule and the no-checks rule were each broken on purpose to confirm the tests go red.
