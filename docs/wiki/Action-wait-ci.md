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
- **The reporting app matters.** A check run counts toward a required context only when it came from the expected GitHub
  App (`--app-id`, default 15368, GitHub Actions). Anything that can post a check run could otherwise copy the name `CI green`.
  A same-named run from another app is ignored in both directions: it cannot satisfy the gate, and a failed one cannot turn a
  green gate red (the output says `ignored N run(s)`). If it is the only run with that name, the result is not green. A failed
  run with any other name is red whatever its app. `--any-app` switches this off and prints a warning. This is a second lock:
  merge safety also relies on branch protection or a ruleset that pins the required check to an app, because the merge itself
  is decided by GitHub, not by this script.
- **Names match exactly.** The comparison is a literal string compare: `CI green (old)`, `ci green`, `CI green ` with a trailing
  space, `xCI green` and a glob such as `CI *` do not satisfy `CI green`. Skipped and neutral are not `success`.
- **Red is immediate.** A failed or cancelled check run ends the wait with exit 1 even while the gate is still running.
- **A push aborts or resets.** `--on-push abort` (the default) exits 4 when the pull request head moves. `--on-push reset`
  pins the new head and starts over; the total `--timeout` keeps running, so a stream of pushes cannot extend the wait forever.
  Once the pinned commit has verified green, a push is always exit 4: the watcher never merges what it did not verify.
  When you give `--sha`, any head move is exit 4 whichever mode is set: an explicit SHA is never replaced, and the SHA given to
  `--match-head-commit` is the one whose checks were verified, never a re-read value. A second check just before the merge
  enforces the same rule.
- **Hung is not slow.** `--hung-after` counts seconds with no check run changing state. A slow run that keeps completing checks
  does not trip it; a run frozen on one job does, with exit 3. The default is 600 seconds; raise it for a gate whose slowest
  job runs longer. A failing GitHub API counts as no progress, and repeated errors back off (the wait between polls doubles,
  at most eight times `--interval`). `--interval` must be at least 1.
- **The merge is pinned.** `--merge` runs `gh pr merge N --squash --match-head-commit <verified sha>`. If it fails, the head is
  read again: moved means exit 4 with nothing merged; already merged at the verified commit means success. Only a policy block
  (gh's "the base branch policy prohibits the merge", or a "Required status check ... is expected") is retried,
  `--merge-retries` times, `--merge-retry-delay` seconds apart, then exit 1 with `merge blocked: policy block still in place`.
  Any other failure (a conflict, a closed pull request, a 403) is exit 1 at once with `merge blocked: not a policy block`.
  An unknown message is treated as not retryable. When gh accepts the merge but the pull request is not merged afterwards
  (a merge queue, auto-merge), the result is `queued`, exit 5, and `merged` stays `false`. It never passes `--admin` or `--auto`.
- **The list must be whole.** The check-runs endpoint shows at most the 1000 most recent check suites of a ref (GitHub's REST
  description: "If there are more than 1000 check suites on a single git reference, this endpoint will limit check runs to the
  1000 most recent check suites"). The script keeps the response's `total_count` (with `filter=latest` it equals the runs
  returned; probed against live check runs on 2026-10-26: 95 of 95, where `filter=all` gave 180) and compares it with the runs
  actually seen across the pages. If `total_count` is larger than the runs seen, or reaches 1000, or is missing, the commit is
  not green: the output says `check-run list may be truncated`, the script keeps waiting and ends in exit 2 (timeout) or 3
  (hung), never green. A run that is visibly failed is still red. The cap counts suites, not runs, and the suite count is not
  exposed, so 1000 runs is the conservative stand-in: a commit with that many check runs cannot be passed by this tool.
  Every run must also carry the pinned commit as its `head_sha`; one that does not is red.
- **Hostile names are an error.** A check run whose name contains a control character (U+0000 to U+001F, DEL, U+0085, U+2028,
  U+2029) makes the result red with exit 1, whoever posted it. Names reach bash base64-encoded, so no name can add a line or a
  field to what the script parses; a forged `completed`, `success`, `CI green` line inside a name cannot satisfy the gate.
  Only canonical base64 is accepted (exact shape, zero trailing bits), values are compared in their encoded form, and a
  malformed field is treated as hostile. The real `gh api` already rewrites control characters other than tab, newline and
  carriage return into caret notation before `--jq` runs (ESC becomes `^[`, NUL `^@`, observed with gh 2.100.0), so through
  `gh` those names arrive as harmless printable text; the check still stands for the characters `gh` leaves alone and for any
  other client.
- **Numbers are plain and bounded.** Every numeric option is digits only: no sign, no spaces, no leading zero, no hex, no
  other script's digits, at most nine digits. Anything else, or a value outside its range, is exit 64 naming the option.
  Arithmetic is forced to base 10.

| Option | Allowed |
|---|---|
| `--pr` | 1 to 999999999 |
| `--app-id` | 1 to 999999999 |
| `--min-checks` | 1 to 100000 |
| `--timeout` | 1 to 604800 seconds (seven days) |
| `--hung-after` | 1 to 604800 seconds |
| `--interval` | 1 to 3600 seconds |
| `--merge-retries` | 0 to 100 |
| `--merge-retry-delay` | 0 to 3600 seconds |

- **It prints the SHA it verified:** `wait-ci: verified <sha>: green`.
- **It never prints a token.** Every line of `gh` output that reaches the log is cut to one line and has the value of `GH_TOKEN` and
  `GITHUB_TOKEN` replaced. The script does not trace (`set -x`) and does not `eval`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Green. With `--merge`, merged (or already merged at the verified commit). |
| `1` | Red: a check failed or was cancelled, or a check run name holds a control character. Also: `--merge` could not merge (the output says `merge blocked`: a non-policy failure, or a policy block that outlasted the retries), or the head could not be read or was not a full SHA. |
| `2` | Timeout: no verdict after `--timeout` seconds. |
| `3` | Hung: no check changed for `--hung-after` seconds. |
| `4` | Head moved: the pull request head is no longer the pinned SHA (at the start, while waiting, between the last check and the merge, or during the merge). |
| `5` | Queued: the merge was accepted but the pull request is not merged yet (a merge queue or auto-merge). Not reported as merged. |
| `64` | Bad input; nothing was waited on and `gh` was not called. |

The timeout is tested before hung, so a run that is past both reports `2`.

## Use as a script

```sh
GH_TOKEN="$(gh auth token)" scripts/wait-ci.sh --repo OWNER/REPO --pr 123 --merge --delete-branch
echo "exit=$?"
```

Run it from a checkout of this repository at a pinned commit, or fetch the file at that commit. It needs `bash`, `gh` and `cksum`.
`GH_BIN` names a different `gh` (the tests use a fake). When `GITHUB_OUTPUT` is set it appends `result`, `sha` and `merged`.

Options: `--repo`, `--pr`, `--sha`, `--context` (repeatable; `--context ''` means no named gate), `--app-id`, `--any-app`, `--min-checks`, `--timeout`,
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
| `app-id` | GitHub App id whose check runs may satisfy a context; default 15368 (GitHub Actions). |
| `any-app` | `true` accepts a same-named run from any app, with a warning. |
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

Outputs: `result` (`green`, `red`, `timeout`, `hung`, `head-moved`, `merge-blocked`, `queued`, `error` or `usage`), `sha` (the verified commit: set
whenever the commit verified green, so also for `merge-blocked` and `queued`; empty otherwise) and `merged` (`true` only when the pull request
is merged at that commit). The outputs are written even when the step fails, so a later `if: always()` step can read them.

## What it does not do

- It reads check runs, not the older commit statuses. A required context that only reports as a commit status is never seen.
- The default context, `CI green`, matches the check run name exactly. A job of a reusable workflow is reported as
  `<caller job> / <called job>` (for example `ci / CI green`), which the default does not match; pass the full name
  (`--context 'ci / CI green'`, or one line of the `context` input). The gate in this repository is a direct job named exactly
  `CI green`. There is no prefix option, on purpose: a prefix is a looser match.
- It does not rerun failed jobs and it does not read branch protection; name the contexts you require.
- It does not wait for checks that are not part of the gate: with the gate green and an unrelated check still running, the
  commit is green. Add the check to `context` to require it.

## How it is tested

`tests/test_wait_ci.py` runs the real script under bash against a fake `gh` (a Python program driven by a scenario) with a fake
clock, so waits cost no time and every call is on record. It covers the pinned head, abort and reset on a push, no checks, a
context that has not reported, exact matching, hostile check run names (newline, carriage return, the field separator, NUL, DEL, U+2028 and more, through the real `jq`), pages, reruns, failed and cancelled, timeout, hung, merge retry and its bound, a head that moves
between the last check and the merge, a token that must not appear, bad input, and the action's own step run end to end.
The fake `gh` serves GitHub-shaped JSON and applies the script's real `--jq` expression with the real `jq` (a test dependency; the test run fails in CI and skips locally without it). The key cases also run a second way: the real `gh` (whose embedded gojq is what runs the expression in production) talks to a loopback TLS server serving the same scenario, using a throwaway certificate from `openssl`; those cases fail in CI and skip locally without `gh` or `openssl`. honors `per_page`, `--paginate` and `filter`, and keeps the newest run per name and app for `filter=latest`. The head pin, the required-context rule, the no-checks rule and the name encoding were each broken on purpose to confirm the tests go red. Not covered: a merge through the real `gh` (it uses GraphQL, so merges run against the fake only).
