# parallel-ci

**What it does.** Runs a project's build once, then its checks as separate jobs that share the build, and ends in one
`CI green` gate. A project whose CI is a single long job (build, then a dozen checks and test scripts one after another)
finishes in the build plus its slowest check instead of the sum. It holds no token.

**Why it exists.** The blog behind the first caller spent 16 to 19 minutes in one sequential job. Nothing could be dropped (every
check and pin stays), so the answer is to run the same commands side by side. The generic part is here: a build artifact, a
matrix over a list of commands, path rules, caches and a gate. Everything specific to the project stays in the caller.

## The jobs

| Job | What it does |
|---|---|
| `changes` | Validates every input (failing the run on a bad one) and decides which checks this change needs |
| `build` | Runs `build-command` once; uploads `build-output-path` as a one-day artifact named with the run attempt |
| `checks` | A matrix over the selected `jobs`; each leg downloads the build and runs its command |
| `ci-green` | `CI green`: red on any failed, cancelled or unexplained-skipped job |

## Which checks run

Give `areas` as a JSON object from an area name to glob patterns, and a job a list of `areas`. On a pull request the change is
`git diff --no-renames --name-only` between the base and the merge result; each path takes the first area that matches. A job
with `areas` runs only when the change touches one of them.

It fails **closed**. A push, a schedule, a manual run, an empty diff, a diff that could not be taken, a path no rule matches and
a path with a control character or invalid UTF-8 in its name all run every job. Moving a file out of a protected path shows the
old path too (`--no-renames`), so it is not a docs-only change. Put a catch-all last (`"site": ["*"]`).

## The gate

`ci-green` needs every other job and runs `if: always()`. A job is green only if it is `success`. The one skip it accepts is the
`checks` job when `changes` succeeded and the rules selected no check at all; a `checks` job skipped because the build failed is
a failure. There is no `continue-on-error` and no `|| true` in the workflow.

## Setup, PATH and caches

`setup-command` runs in the same shell as the command that needs it, so `export PATH=...` there reaches that command and nothing
else. The workflow never writes `$GITHUB_PATH` or `$GITHUB_ENV`. A setup that exits early cannot make a step pass.

`cache-pip-files` and `cache-tool-path` with `cache-tool-key-files` cache downloads only, keyed on a hash of the files you name,
and only where the egress policy is `block`. Keep `--require-hashes` on installs and verify a downloaded tool against a checksum
fetched fresh every run.

## A minimal caller

```yaml
jobs:
  ci:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/parallel-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    with:
      build-command: hugo --minify --gc
      build-output-path: public
      areas: '{"docs": ["docs/*.md", "README.md"], "site": ["*"]}'
      jobs: |
        [
          {"name": "output checks", "command": "scripts/check-output.sh public"},
          {"name": "size budget", "command": "scripts/check-budget.sh public", "areas": ["site"]}
        ]
```

The check run is `ci / CI green`. With other workflows beside it, put [ci-gate](Workflow-ci-gate.md) over all of them.

<!-- inputs -->

## What it refuses to do

It never runs a caller value as part of a shell script it wrote (values arrive in environment variables), never passes a gate
over nothing, never skips a check on an unreadable change, and never gives a job more than `contents: read`.
