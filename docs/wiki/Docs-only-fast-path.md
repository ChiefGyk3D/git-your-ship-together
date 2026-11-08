# Docs-only fast path and parallel CI

**What it does.** Three opt-in pieces that make a caller's CI faster without making `CI green` easier to pass. Each is off by
default, so a caller that sets nothing sees no change after it re-pins.

1. `tofu-ci.yml` input **`test-matrix`**: `tofu test` runs as one job per directory instead of every directory one after
   another in one job.
2. `python-ci.yml` input **`xdist`**: the `test` job's pytest runs in parallel with pytest-xdist.
3. Two composite actions, **`classify-changes`** and **`ci-gate`**: a pull request that changes only docs and tests leaves a
   named job (the tofu job, say) out on purpose, and the caller's own `CI green` job counts that skip, and only that skip, as
   a pass.

**Why it exists.** Clouds-Against-Humanity measured a pull request run at 5 min 15 s, its critical path the `tofu / test` job
at 286 s (17 directories, one after another), then the Python test jobs at 209 s and 139 s with plain pytest. A lesson that
touches only `docs/` waited for all of it (issues Clouds-Against-Humanity#519 and #520, GYST #331).

## `test-matrix` in tofu-ci

With `test: true` and `test-matrix: true`, a small `test-dirs` job lists one matrix leg per directory and `test` runs the legs
at once with `fail-fast: false`, so one failing directory does not hide another. Each leg is named `test (<directory>)`.
With `test-matrix` off, `test-dirs` produces a single leg named `test` that holds every directory, so the job is what it always
was, name included.

The `ci-green` job still reports one result. GitHub gives a matrix job the result `failure` if any leg failed, `cancelled` if
any leg was cancelled, and `success` only when every leg succeeded. `ci-green` fails on anything but `success` for `test` and
for `test-dirs` when `test` was asked for, so a skipped matrix (for instance because the leg list failed) is a missing check, not
a pass. `tests/test_docs_only_fast_path.py` runs that shell for every result.

Cost: every leg repeats the runner start, harden-runner, the egress canary, checkout and the tofu install, about 40 to 60
seconds. That is why it is a choice. It pays when the directories' `tofu test` time dominates, as it does for a repository with
many stacks and modules.

## `xdist` in python-ci

With `xdist: true` the `test` job installs `pytest-xdist` after `install-command` and sets
`PYTEST_ADDOPTS=-n <xdist-workers>` for the `test-command` step. `PYTEST_ADDOPTS` is read by pytest itself, so:

- the caller's `test-command` runs exactly as written: a command that chains scripts and gates before `pytest` keeps its
  semantics, and the `-n` reaches every `pytest` in it (`pytest`, `python -m pytest`, `python -I -m pytest`) and no other program;
- the `distro` job runs the command as written, without it;
- the install is `pip install --require-hashes --no-deps --only-binary=:all:` from a lock that travels inside `python-ci.yml`
  (source: `.github/requirements/pytest-xdist.{in,txt}`, copied in by `scripts/tool_locks.py`), holding `pytest-xdist` and its
  one dependency `execnet` with hashes. There is no version input: a free-form version cannot coexist with a hash lock, so the
  locked release is the only one and a bump is a change to the lock. pytest itself is the caller's and is not locked here;
- `xdist-workers` is `auto`, `logical` or a whole number, checked before it can reach pytest.

Under xdist, tests must not share state (a fixed port, one scratch path), and test ids must be identical on every worker.
A `parametrize` over a bare `object()` puts a memory address in the id and makes xdist stop with "Different tests were
collected"; give such a case an explicit `ids=`.

## The docs-only fast path

Two actions and one rule.

**Wiring (the caller's `ci.yml`).**

```yaml
jobs:
  classify:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
      pull-requests: read
    outputs:
      docs-only: ${{ steps.c.outputs.docs-only }}
    steps:
      - id: c
        uses: ChiefGyk3D/git-your-ship-together/.github/actions/classify-changes@<sha> # vX.Y.Z
        with:
          docs-only-patterns: |
            docs/**
            tests/**
            *.md

  tofu:
    needs: classify
    if: needs.classify.outputs.docs-only != 'true'
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/tofu-ci.yml@<sha> # vX.Y.Z
    # permissions and with: as before

  ci-green:
    name: CI green
    if: ${{ always() }}
    needs: [classify, tofu, python, security]
    runs-on: ubuntu-latest
    permissions: {}
    steps:
      - uses: ChiefGyk3D/git-your-ship-together/.github/actions/ci-gate@<sha> # vX.Y.Z
        with:
          needs: ${{ toJSON(needs) }}
          required-jobs: classify tofu python security
          skippable-jobs: tofu
          classifier-job: classify
```

**The decision rules.**

1. A pull request is docs only when every path it changes matches `docs-only-patterns` and none is under `.github/` or on
   `never-skip-patterns`. One path outside the list, such as `stacks/` or `modules/`, makes the whole change a normal one and
   the job runs. A mixed docs and code pull request runs the job.
2. Patterns are anchored at the repository root and matched against the whole path. `*` does not cross `/`; `**` does;
   `**/` is zero or more directories. So `*.md` is the root-level Markdown files, and `**/*.md` is every one. A pattern
   that matches every path (`**`, `*`, `**/*`), starts with `/` or `!`, or contains `..` fails the step.
3. A rename counts both names: `git mv stacks/a/main.tf docs/main.tf` removes code and is not docs only.
4. Anything the step cannot confirm is `docs-only=false`, and the job runs: the event is not a `pull_request`, the pull request
   head is no longer the commit the run started for, the API's file list is a different size from the event's own count, the
   list is at the API's 3,000-file limit, or the API call failed. A push to the default branch, a schedule, a dispatch and a
   merge queue run are never docs only.
5. `CI green` passes a job only when its result is `success`. The one exception is a job named in `skippable-jobs` that is
   `skipped` while the `classifier-job` itself succeeded with `docs-only=true`. A job skipped for any other reason (an
   upstream failure, a mistyped `if:`, a classifier that failed or said `false`), a failure, a cancellation or a job left out
   of `needs` fails. `required-jobs` makes a job dropped from `needs:` a failure too.

## Threat notes

The fast path is a way to run less, so the question is what an attacker gains by making the check run less. Each row names the
route and what closes it.

| Route | What closes it |
|---|---|
| The changed-file list is read from the pull request's own checkout, which its author controls | It is read from the REST API (`pulls/{n}/files`), which GitHub computes. The checkout is not consulted |
| The list is truncated, stale or hides files | The head the API reports must equal the head the event started for, the count must equal the event's `changed_files`, and a list at the 3,000-file limit is refused. Any mismatch is `false` |
| A pull request edits the rule (the patterns, the workflow, this action's wiring) | `.github/**` is never docs only, whatever the patterns say, and `never-skip-patterns` adds the caller's other rule files. Such a pull request runs every job. Residual: a pull request's own workflow file runs from the pull request, so it can also remove the check outright. That is true of every CI job and is closed by what guards `.github/` (code owner review, a required `CI green` that the base branch's rules produce), not by this step |
| A change that mixes docs and code | One path off the list fails the whole classification, so the code runs |
| A rename that moves code into a docs path | Both the old and the new name are classified |
| A path with `..`, `.`, an empty segment or a leading `/` | Not a normal repository path; the classification is `false` |
| A pattern that widens the list to everything | Catch-all patterns, a leading `/` or `!`, and `..` fail the step. A narrower but wrong list (for example `scripts/**`) is a caller decision, and only reachable by editing `.github/`, which runs everything |
| A push lands while the file pages are being fetched | The pull request is read again after the last page. The head must still be the commit the run started for, and the file count must agree three ways (the event, the listing, the final read). Same count and paths on a different head still fail closed |
| A test hook that ships in the action | There is none. The script reads the API through `gh` only; an environment variable cannot substitute a file list (`CC_FILES_JSON` was removed, and a test pins that setting it changes nothing) |
| A `directories` entry that leaves the repository (tofu-ci `test-matrix`) | Each entry is checked before any leg exists: no absolute path, no leading `-`, no `..` or empty segment, only `A-Z a-z 0-9 _ . / -`. The same check runs with `test-matrix` off |
| A fork pull request | The step needs only `pull-requests: read`, which a fork's token has. It checks out nothing and runs none of the fork's code. A fork cannot reach a secret through it |
| A skipped job passes for the wrong reason | The gate counts a skip only for a named job and only when the classifier succeeded with `docs-only=true`. Skipped because an upstream failed, skipped by a typo, or skipped with a `false` verdict all fail |
| Output injection through a file name | Values go to `$GITHUB_OUTPUT` on one line each, with whitespace collapsed and the path quoted |
| The classifier is itself skipped or fails | The gate fails: `classify` is in `needs` and must be `success` for a skip to count |
| An expression injection | Every input reaches the scripts through the environment, never by interpolation into the script text |

Not covered: a repository that does not require review on `.github/`. A pull request that rewrites `ci.yml` to skip a job
needs a reviewer to see it, with or without this feature.

## The fork excuse in `ci-gate`

A job that needs a token a fork's pull request does not get (a publishing job's grants, a SARIF upload) is skipped on a fork
by its own `if:`. Two optional inputs of `ci-gate` let the caller's `CI green` accept exactly that and nothing wider:
`fork-skippable-jobs` names the jobs, and `fork-pull-request` is the caller's own expression,
`${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name != github.repository }}`. A named job
may be `skipped` only when that is the string `true`; a failure or a cancellation still fails, and a job that is not named
still fails when skipped. Unset, the action behaves as before.

## This repository's own `ci.yml` (issues #307, #308)

`ci.yml` runs about a hundred jobs. It uses the same two actions: a `changes` job runs `classify-changes` with
`docs/**`, `tests/**` and `CHANGELOG.md` (not `README.md`: `tests/test_sbom.py` reads it), and every job except `actionlint`, `zizmor`, `test` (the suite reads `tests/`), `changes`
and `CI green` carry `needs: changes` and `if: needs.changes.outputs.docs-only != 'true'`. `CI green` is the `ci-gate`
action over all of them, with `skippable-jobs` set to exactly those jobs, `required-jobs` set to every job, and the
fork excuse above for the jobs that already skipped on a fork. `tests/test_path_aware_gating.py` holds the three lists
together: add a job to `ci.yml` without gating it and the test names it.

**Tests a gated job runs (the rule that keeps this honest).** `tests/**` is on the docs-only list because the suite reads it
and is never skipped, but a gated job also runs some test files: `fixture-sbom` runs `tests/test_sbom.py`, `rescan-live` runs
`tests/test_verify_published.py`, and `dast-live` runs `tests/test_dast.py`, which imports `tests/test_workflows.py`. Those, and
`tests/fixtures/**`, are on `never-skip-patterns`, so a change to one runs the jobs that depend on it even beside docs.
`tests/test_path_aware_gating.py` reads every gated job, follows the test files it runs and the local modules and root Markdown
files they name, and fails if any of those paths alone would be classified docs only.

**The live jobs and the nightly run (issue #308).** `rescan-live` (real Trivy) and `dast-live` (real ZAP image, about 450
seconds, the long pole) are gated the same way. `ci.yml` also has a `schedule` trigger, every
night on the default branch. The classifier says `false` for anything but a pull request, so the nightly run is the full run:
the live jobs, the jobs that read the published image and today's vulnerability database, everything. A job that wants to opt
out of the nightly run is a test failure (`tests/test_path_aware_gating.py`).

Docs-only means every changed path is documentation or a test file nothing else reads. A change under `.github/`,
`scripts/`, `fixture/`, `.github/actions/`, a requirements file, or any path the patterns do not name runs everything, as does a
push to `main`, the nightly schedule and a manual run (the classifier is `false` for anything but a pull request).

## Where it runs

`scripts/classify_changes.py` and `scripts/ci_gate.py` are the whole logic; the actions only pass the environment. Both are
tested in `tests/test_docs_only_fast_path.py` with a fake `gh`.
