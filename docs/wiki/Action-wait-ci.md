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
- **Green needs all four:** every required context (default `CI green`) reported on the pinned SHA and concluded `success`;
  at least `--min-checks` check runs completed; no check run failed, was cancelled, timed out, needed action or failed to start;
  and every other check run on that commit is complete.
- **The gate is not the only check.** A gate such as `CI green` covers its own workflow, not a separate one (a security scan, a
  deploy preview). After the head is pinned, every other check run on that SHA must be completed with a conclusion of `success`,
  `skipped` or `neutral`. One that is queued, waiting, pending or in progress (or completed with no conclusion) is waited for, with
  the same `--interval`, `--timeout` and `--hung-after` as everything else; the output says `waiting for N other check run(s)`.
  One that failed, was cancelled, timed out, needed action, failed to start or went stale ends the wait with exit 6 and result
  `other-red`, and nothing is merged. A failed gate stays exit 1. A run that carries a gate name but comes from another app is
  not the gate (it cannot satisfy it) and is not ignored: it is judged as an other check, so a red one is exit 6 and an open one
  is waited for. `--any-app` makes such a run count as the gate instead.
- **Reruns: the latest run decides.** Check runs are read with `filter=latest`, which keeps the newest run for each check name
  and app. A red run followed by a green rerun of the same check counts as green (the rerun is the check's current state, the
  same state GitHub shows); a green run followed by a red rerun is red; a rerun that is open is waited for. The earlier attempt
  is not consulted: the API gives no link from a rerun to the run it replaced, so a rule about "the same lineage" cannot be
  checked. A same-named run from a different app is a different check, never a rerun. If an earlier red attempt must block,
  fix the check (or record why it is flaky) rather than relying on this tool to remember it.
- **Late checks.** A check run cannot be judged before it exists, and a workflow that starts late (a `workflow_run` workflow, a
  second app) has none yet. Two measures. First, `--require-check NAME` (repeatable; input `require-check`, one name per line)
  names a further required check: it must exist, from the expected app, and succeed. One that has not reported is waited for until
  `--timeout` and then exit 2, never green; a red one is exit 1. Name every workflow you need, security scans first. Second, the
  settle rule: success is returned only when two consecutive polls, one `--interval` apart, read the identical set of check
  runs (id, status, conclusion, app, name). A name that appears between the polls restarts the wait and is then judged like any
  other check. The settle adds one interval to every green. Neither measure proves that a check which never appears does not exist:
  `--require-check` and branch protection or a ruleset are the real controls for that.
- **Allow-list, a recorded exception.** `--allow-red NAME[@APP]` (repeatable; input `allow-red`, one name per line) lets a named
  non-gate check be red. A bare `NAME` matches that name from **any** app and workflow. `NAME@APP` (APP is the reporting
  app's slug: lowercase letters, digits and hyphens, for example `github-actions`) matches only the run reported by that
  app. A name that itself ends in `@something` is read as `NAME@APP`. It is empty by default and is not a default: it needs `--allow-red-reason TEXT` (input
  `allow-red-reason`, one line), which is printed in the log as a "recorded exception". Names match exactly; a required context
  cannot be allowed (exit 64); a reason without a name, or a name without a reason, is exit 64; so is a control character (tab,
  carriage return, escape, DEL, U+0085, U+2028, U+2029, newline) in a name or the reason, in `--context` or in `--require-check`,
  so nothing that could forge a log line reaches the output. An allowed check that is still
  open is waited for, and the result counts it as `allowed red` when it passes. Use it for a known failing check that has its own
  written exception, and keep the reason pointing at that record.
- **No check runs is not green.** `--min-checks` cannot be below 1, so an empty list never passes, even with no named context.
- **A context that has not reported is not green.** Twenty passing jobs and no `CI green` yet means keep waiting.
- **The reporting app matters.** A check run counts toward a required context only when it came from the expected GitHub
  App (`--app-id`, default 15368, GitHub Actions). Anything that can post a check run could otherwise copy the name `CI green`.
  A same-named run from another app cannot satisfy the gate, and it is not ignored: it is judged as an other check, so a failed
  one is exit 6 and an open one is waited for (the output says `N run(s) named like a required check come from an app other
  than ...`). If it is the only run with that name, the gate has not reported and the result is not green. `--any-app` switches this off and prints a warning. This is a second lock:
  merge safety also relies on branch protection or a ruleset that pins the required check to an app, because the merge itself
  is decided by GitHub, not by this script.
- **Names match exactly.** The comparison is a literal string compare: `CI green (old)`, `ci green`, `CI green ` with a trailing
  space, `xCI green` and a glob such as `CI *` do not satisfy `CI green`. Skipped and neutral are not `success`.
- **Red is immediate.** A failed or cancelled check run ends the wait even while the gate is still running: exit 1 when the
  failed run is the gate, exit 6 when it is any other check.
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
- **The check state is not atomic with the merge.** Before every merge attempt (the first and each retry) the script reads the
  check runs and suite counts again and stops with exit 6 on any change. That narrows the window; it cannot close it, because
  a check can still change between that read and the moment GitHub processes the merge. The only atomic guarantee is
  GitHub-enforced required status checks (branch protection or a ruleset) or a merge queue; this script is the second line.
  Before merging it reads the base branch's rules and warns loudly when none cover the required contexts. The script option
  `--require-protection` turns that warning into exit 1.
- **The merge is pinned.** `--merge` runs `gh pr merge N --squash --match-head-commit <verified sha>`. If it fails, the head is
  read again: moved means exit 4 with nothing merged; already merged at the verified commit means success. Only a policy block
  (gh's "the base branch policy prohibits the merge", or a "Required status check ... is expected") is retried,
  `--merge-retries` times, `--merge-retry-delay` seconds apart, then exit 1 with `merge blocked: policy block still in place`.
  Any other failure (a conflict, a closed pull request, a 403) is exit 1 at once with `merge blocked: not a policy block`.
  An unknown message is treated as not retryable. When gh accepts the merge but the pull request is not merged afterwards
  (a merge queue, auto-merge), the result is `queued`, exit 5, and `merged` stays `false`, but only when the read-back is a
  successful response showing `merged` false at the verified head. If the read-back fails for any reason (an HTTP error,
  a rate limit, a malformed or invalid response), after a successful or a failed merge call, the outcome is unknown: exit 1,
  result `error`, "could not read the pull request after the merge call"; it is never `queued`, `already merged` or
  `head moved`. An unmerged pull request at a different head is exit 4. It never passes `--admin` or `--auto`.
- **The list must be whole.** GitHub's REST description for listing check runs says: "If there are more than 1000 check suites
  on a single git reference, this endpoint will limit check runs to the 1000 most recent check suites." The cap is on check
  suites, and a cut-off answer can hold far fewer than 1000 runs (several suites with one run each, suites with none), so
  counting runs cannot reveal it. Once per poll the script therefore asks for the suite count, `GET
  /repos/{repo}/commits/{sha}/check-suites?per_page=1`, and reads its `total_count` (an integer, required in the response; it
  counts every suite on the ref, also those without runs: 12 suites behind 3 with runs on live data, probed 2026-10-26).
  A suite count of 1000 or more, or one that is missing, null, a string, negative, fractional, huge or unobtainable, makes the
  commit not green: the output says `check-run list may be truncated`, the script keeps waiting and ends in exit 2 (timeout)
  or 3 (hung), never green. Two guards on the runs stay: the check-runs `total_count` (with `filter=latest` it equals the runs
  returned; probed live, 95 of 95 where `filter=all` gave 180) must not exceed the runs actually seen across the pages, and
  must stay under 1000. A run that is visibly failed is still red. What this does and does not rule out: while the suite
  count is under 1000 the cap GitHub describes does not apply, so no suite can have been displaced; this rests on the
  documented behavior, not on anything the script can observe. The suite call is a separate request, so a suite created
  between the two calls is not in the run list; it can only add to the count, and the next poll sees it. A commit with 1000
  or more suites cannot be passed by this tool. Every run must also carry the pinned commit as its `head_sha`; one that does
  not is red.
- **The list must hold still.** Check runs come from an offset-paged collection that can change between two page requests: a
  rerun inserts its replacement ahead of a run already returned and drops its old entry, so one run can appear on two pages
  while a current failed run is skipped, and the counts can still add up. The script therefore requests the pages one by
  one (`page=1`, `2`, ... at most twelve, never by following links, so a repeating cursor cannot loop) and accepts a read only
  when every page reports the same `total_count`, no run `id` appears twice, and the distinct ids equal `total_count`
  exactly (more or fewer). Each run's `id` crosses the boundary as plain digits and must be a plain integer, else the run is
  hostile (red). A read that contradicts itself is not a snapshot: the output says `check-run list changed while it was
  read`, the script waits and tries again on the next poll.
- **Two reads agree before green.** When a read looks green the whole read is made a second time. The sorted set of (run id,
  status, conclusion) must be identical and so must the suite counts; otherwise the script says `waiting for a stable
  snapshot` and keeps going. A collection that never holds still is never green (exit 2 or 3).
- **The suite count is read before and after.** In each read the check-suite count is asked first, then the run pages, then the
  suite count again (so the confirming read asks twice more). Both must be readable, equal to each other, and under 1000, or
  the read is not trusted; a count that moves during a read says `check suite count changed while reading`. This closes the
  window in which a suite could be deleted, or created, between the run list and a single later count.
- **Cost.** A green takes two polls (the settle rule), so the figures below double for the final answer. One read is two suite-count requests plus one request per hundred runs: three for a commit with up to 100 runs, twelve
  for one with 1000 (ten pages). A poll that finds nothing yet does one read; a poll that looks green does two, so six and
  twenty-four requests, plus the pull request reads (one per poll and one before the merge). Against the 5000 requests an
  hour a workflow token has, a 20 second interval on a 100-run commit is about 540 an hour.
- **A merge belongs to the head it merged.** After any merge attempt, successful or not, `merged`, `head.sha` and
  `merge_commit_sha` are read from ONE response of `GET /repos/{repo}/pulls/{n}`. The merge counts as the verified commit's only
  when `merged` is true and that response's `head.sha` is the verified SHA. A pull request that reads as merged at any other
  head (another push, then a merge of it) is exit 4 with `merged at a different head`, `merged` stays `false`, and nothing is
  attributed to the verified commit. A merge that gh reports as successful but that leaves the pull request unmerged is
  exit 5 as before.
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
| `1` | Red: the gate (a required context) failed or was cancelled, or a check run name holds a control character. Also: `--merge` could not merge (the output says `merge blocked`: a non-policy failure, or a policy block that outlasted the retries), or the head could not be read or was not a full SHA, or the pull request could not be read after the merge call (`result` is `error`, `merged` stays `false`). |
| `2` | Timeout: no verdict after `--timeout` seconds. |
| `3` | Hung: no check changed for `--hung-after` seconds. |
| `4` | Head moved: the pull request head is no longer the pinned SHA (at the start, while waiting, between the last check and the merge, or during the merge). |
| `5` | Queued: the merge was accepted and the pull request, read back, is positively not merged yet at the verified head (a merge queue or auto-merge). Not reported as merged. A pull request that cannot be read back is exit `1`, never `5`. |
| `6` | Other checks red: the gate did not fail, but another check run on the pinned commit failed, was cancelled, timed out, needed action, failed to start or went stale, and is not in `--allow-red`. `result` is `other-red`. Nothing is merged. |
| `64` | Bad input; nothing was waited on and `gh` was not called. |

The timeout is tested before hung, so a run that is past both reports `2`.

## Use as a script

```sh
GH_TOKEN="$(gh auth token)" scripts/wait-ci.sh --repo OWNER/REPO --pr 123 --merge --delete-branch
echo "exit=$?"
```

Run it from a checkout of this repository at a pinned commit, or fetch the file at that commit. It needs `bash`, `gh` and `cksum`.
`GH_BIN` names a different `gh` (the tests use a fake). When `GITHUB_OUTPUT` is set it appends `result`, `sha` and `merged`.

Options: `--repo`, `--pr`, `--sha`, `--context` (repeatable; `--context ''` means no named gate), `--require-check`, `--app-id`, `--any-app`, `--min-checks`, `--timeout`,
`--hung-after`, `--interval`, `--allow-red`, `--allow-red-reason`, `--on-push`, `--merge`, `--delete-branch`, `--require-protection`, `--merge-retries`, `--merge-retry-delay`. The header of
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
| `require-check` | Further required check names, one per line, exact, from the expected app; each must exist and succeed. Covers a workflow that starts late. |
| `allow-red` | Non-gate check names that may be red, one per line, exact (`NAME@APP` scopes to an app slug; bare matches any app). Empty by default; a recorded exception that needs `allow-red-reason`. |
| `allow-red-reason` | Why those checks may be red, on one line; printed in the log. |
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

Outputs: `result` (`green`, `red`, `other-red`, `timeout`, `hung`, `head-moved`, `merge-blocked`, `queued`, `error` or `usage`), `sha` (the verified commit: set
whenever the commit verified green, so also for `merge-blocked` and `queued`; empty otherwise) and `merged` (`true` only when the pull request
is merged at that commit). The outputs are written even when the step fails, so a later `if: always()` step can read them.

## What it does not do

- It reads check runs, not the older commit statuses. A required context that only reports as a commit status is never seen.
- The default context, `CI green`, matches the check run name exactly. A job of a reusable workflow is reported as
  `<caller job> / <called job>` (for example `ci / CI green`), which the default does not match; pass the full name
  (`--context 'ci / CI green'`, or one line of the `context` input). The gate in this repository is a direct job named exactly
  `CI green`. There is no prefix option, on purpose: a prefix is a looser match.
- It does not rerun failed jobs and it does not read branch protection; name the contexts you require.
- It only sees check runs that exist when it reads. A workflow that has not started yet (for example one triggered late) has no
  check run, so it cannot be waited for unless you name it: add it with `--require-check` (or `context`) to make the commit not
  green until it reports. The settle rule narrows the window but cannot close it.

## How it is tested

`tests/test_wait_ci.py` runs the real script under bash against a fake `gh` (a Python program driven by a scenario) with a fake
clock, so waits cost no time and every call is on record. It covers the pinned head, abort and reset on a push, no checks, a
context that has not reported, exact matching, hostile check run names (newline, carriage return, the field separator, NUL, DEL, U+2028 and more, through the real `jq`), pages, reruns, failed and cancelled, timeout, hung, merge retry and its bound, a head that moves
between the last check and the merge, a token that must not appear, bad input, and the action's own step run end to end.
The fake `gh` serves GitHub-shaped JSON and applies the script's real `--jq` expression with the real `jq` (a test dependency; the test run fails in CI and skips locally without it). A scripted-sequence capability lets a test make the collection change between the page requests of one read (a different response per request for the check runs, the suite count and the pull request), which is how the shifting-offset repro, the confirming read and the before/after suite counts are tested. The key cases also run a second way: the real `gh` (whose embedded gojq is what runs the expression in production) talks to a loopback TLS server serving the same scenario, using a throwaway certificate from `openssl`; those cases fail in CI and skip locally without `gh` or `openssl`. honors `per_page`, `--paginate` and `filter`, and keeps the newest run per name and app for `filter=latest`. The head pin, the required-context rule, the no-checks rule and the name encoding were each broken on purpose to confirm the tests go red. Not covered: a merge through the real `gh` (it uses GraphQL, so merges run against the fake only).
