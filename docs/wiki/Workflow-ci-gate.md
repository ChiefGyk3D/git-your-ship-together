# ci-gate

**What it does.** One job, `CI green`, that is green only when every job it is handed succeeded or was skipped on purpose.
Use it when several workflows run side by side ([parallel-ci](Workflow-parallel-ci.md), [bash-ci](Workflow-bash-ci.md),
[security](Workflow-security.md), a job of your own) and branch protection should require one result. It holds no token and
checks nothing out.

## The rule

A job counts only with the result `success`. `skipped` counts only for a job named in `deliberate-skips`, a JSON list of job
ids. `failure`, `cancelled`, an unknown result, a missing result, no jobs at all and a deliberate skip that names no needed
job all fail. A skip nobody asked for, such as everything downstream of a failed build, is a failure.

## A security-only repository

`security.yml` produces no gate, so a repository whose only caller is the security one hands it to this workflow:
`gate: { if: always(), needs: [security], uses: ...ci-gate.yml@<sha>, permissions: {}, with: { needs-json: ${{ toJSON(needs) }} } }`.
The check is `gate / CI green`; require it in branch protection. The weekly audit derives that check from the `ci-gate.yml` call.

## A caller

```yaml
jobs:
  ci:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/parallel-ci.yml@<sha> # vX.Y.Z
    # ...
  shell:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/bash-ci.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
  gate:
    if: always()
    needs: [ci, shell]
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/ci-gate.yml@<sha> # vX.Y.Z
    permissions: {}
    with:
      needs-json: ${{ toJSON(needs) }}
```

`if: always()` on the calling job is required: without it the gate is skipped when a job it needs fails, and branch protection
reads a skipped required check as passed. The value is read from an environment variable, so pass a small result map when the
needed jobs have large outputs.

<!-- inputs -->

## What it refuses to do

It never passes with nothing to judge, never treats an unknown result as green, and never echoes a job id raw into the log.
