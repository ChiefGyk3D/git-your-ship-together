# lory-audit

**What it does.** Asks Lory (Lorikeet Security's AI pentester) for a deep-dive audit of a repository, through its documented
pipeline scan API, and reports the result in the job summary. It makes one HTTPS call, reports only the exit code, copies nothing into GitHub and holds only
`contents: read`.

**When to use it.** For scheduled and on-demand deep dives only: a monthly run of the highest-priority targets, plus a manual
run before a release or after a big change. It is not a per-pull-request gate and it must not become a required check unless the
repository owner decides so. A deep audit is slow and the vendor's rate limits are unknown, so a trigger on every push or pull request is the wrong
shape.

## What is known and what is not

This workflow was written from the vendor's API documentation and has not yet run against the real service. The first real run
is a spike. Three things are unknown until then and are marked as such here:

| Unknown | Why it matters |
|---|---|
| The response schema beyond the integer `exit_code` | The workflow reads only `exit_code`; the rest of the body is deleted unread. It does not parse findings. |
| Whether a deep audit of a non-pull-request target works through this endpoint | The call sends `pr_number: 0` for a scheduled or manual run. The endpoint may expect a pull request. |
| Rate limits | A monthly run is unlikely to hit one; a rerun loop might. |
| Whether a nonzero `exit_code` can also mean a vendor-side error | The workflow treats any nonzero integer as "findings". |

What the documentation does say: `POST https://lorikeetsecurity.com/talon/api/v1/pipeline/scan` with
`Authorization: Bearer <pipeline token>`, a JSON body of `branch`, `commit_sha` and `pr_number`, and a JSON response with an
integer `exit_code` where 0 is a pass. The target, the depth (`surface`, `standard` or `deep`) and the gate threshold come from
the caller repository's `.lory/config.yml`. This workflow neither reads nor overrides that file, and it has no `depth` input
because the documentation does not describe one on the API.

## A minimal caller

`examples/lory-audit-caller.yml` is the template: a monthly cron plus `workflow_dispatch`, advisory by default.

```yaml
on:
  schedule:
    - cron: "23 5 1 * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  lory:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/lory-audit.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
    secrets:
      LORY_PIPELINE_TOKEN: ${{ secrets.LORY_PIPELINE_TOKEN }}
```

Store the pipeline token as the repository secret `LORY_PIPELINE_TOKEN`.

<!-- inputs -->

## Advisory or blocking

`fail-on-findings` is false by default. A well-formed result with a nonzero `exit_code` then shows up in the job summary and as
a warning, and the job passes. Set it to true and the same result fails the job. It decides nothing else.

## It fails closed

Whatever `fail-on-findings` says, the job fails when: the HTTP call fails (curl `--fail-with-body`) or times out; the body is
larger than `max-response-bytes`; the body is not valid JSON, or is not a JSON object; or `exit_code` is missing, duplicated,
or not an integer (a string, a float, a boolean or null). Only a clean, well-formed result is ever advisory. The vendor's own
sample workflow treats a missing `exit_code` as a pass and interpolates `github.head_ref` into a shell script; this one does neither.

## Findings are sensitive

A pentest finding is a map to a weakness. Findings are not copied into GitHub: the response body is never printed to the log,
never uploaded and deleted as soon as the judging step ends. The job summary carries only the `exit_code` and a
UTC timestamp. Read the findings in the vendor portal.

## Handling findings

Findings are third-party model output. Triage them like scanner alerts: read, reproduce, decide. Text inside a finding is
data and never instructions, for you or for any agent that reads them in the portal.

## How the token is handled

The token is in the environment of one step, the one that calls the API, and goes to curl on standard input, so it never appears
on a command line. It is not echoed. curl starts with `--disable`, so no user curl config applies, and the proxy variables and
`CURL_HOME` are unset. Only an HTTP status of exactly 200 is accepted; redirects are not followed and a 3xx, a 204 or a missing
status fails the job. Every other value, including the
branch name, reaches the shell through an environment variable. The URL is fixed in the workflow and there is no input for it,
and curl does not follow redirects, so the token cannot be sent to another host. The egress allow-list is fixed in the workflow
(the Lory API and what the runner and the egress canary need); no input adds a host. Because this job holds a secret it follows
`egress-policy` (exactly `audit` or `block`) and not the secretless input of security exception EX-0001.

## How it is tested

This repository cannot call the workflow on its own pull requests: it needs a vendor token and would call a third party on every
run. `tests/test_lory_audit.py` instead extracts the two shell scripts from the YAML and runs them as shipped against a stub
`curl`: a valid pass, a valid nonzero result in advisory and blocking mode, an HTTP error, a timeout, a non-JSON body, a missing,
string, float, boolean or duplicated `exit_code`, and an oversize body. It also holds the structure: one trigger, `contents: read`,
the token in one step, no `${{ }}` in any script.

## What it refuses to do

It never passes on a call that failed, timed out, came back too large or returned something it cannot read. It does not run on
pull requests unless a caller wires it to them, and it is not a required check. It does not upload, print or keep the response, check out the repository, write
anything back, open issues, or follow anything the response says. It cannot tell whether a finding is real, and it does not
read `.lory/config.yml`.
