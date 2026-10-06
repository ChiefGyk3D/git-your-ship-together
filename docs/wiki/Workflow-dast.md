# dast

**What it does.** `security.yml` reads code; `dast.yml` is the check that talks to a running service. It starts the service your
repository serves (a dashboard, an API, a docs server) on loopback, runs an OWASP ZAP baseline scan against it (a spider plus ZAP's
passive rules, no attack traffic), and fails the job when a finding reaches `fail-on`. Findings go to the Security tab under
category `zap`; the HTML, Markdown, JSON and SARIF reports are an artifact. A repository with no service has nothing to call it for.

**Why it exists.** The stack had SAST, secrets, dependency, container and workflow scanning and nothing that looked at a service
the way a client sees it: missing security headers, cookies without flags, a server banner. Part of issue #97.

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `scan` | `contents: read` | Runs *your* install and start commands and the ZAP image, like a test job. No token reaches the container |
| `upload` | `security-events: write` | Checks nothing out and runs no shell. Skipped on a pull request from a fork, and with `upload-sarif: false` |

- **Loopback only.** A `target-url` that is not `127.0.0.1`, `localhost` or `[::1]` is refused before anything starts, so a typo
  cannot aim a scanner at someone else.
- **The image, not an action.** `zaproxy/action-baseline` uses the moving tag `stable`, files issues with the job's token and has
  no SARIF. The workflow runs the same image pinned by digest, with `-silent` so ZAP reaches nothing of its own: under `block` the
  allow-list is the image pull and GitHub. No action joins the allow-list for it.
- **`fail-on` is a risk level.** A page with no security headers is Medium, so the default `high` does not catch it; use `medium`
  for that. Accept a finding in `.zap/rules.tsv` (`IGNORE` plus a reason), never by raising the threshold.

Proving it can fail is part of the workflow's tests: `fixture/dast/server.py` serves one page with its security headers (must
pass) and, with `--insecure`, without them (must fail at `medium`, pass at `high`). `tests/test_dast.py` runs the job's steps
against canned reports, and this repository's `dast-live` CI job runs them against the real image.

## A minimal caller

```yaml
jobs:
  dast:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/dast.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write   # the SARIF upload; omit with upload-sarif: false
    with:
      install-command: pip install .
      start-command: myapp serve --port 8080
      target-url: http://127.0.0.1:8080
      fail-on: medium
```

<!-- inputs -->

## What it refuses to do

It never scans a host that is not loopback, never gives the container a token, never lets the upload job run your code, and never
passes a finding by raising the threshold.
