# dast

**What it does.** `security.yml` reads code; `dast.yml` is the check that talks to a running service. It starts the service your
repository serves (a dashboard, an API, a docs server) on loopback and runs one of [OWASP ZAP](https://www.zaproxy.org/)'s three
packaged scans against it, chosen by `scan-type`, failing the job when a finding reaches `fail-on`. Findings go to the Security
tab under category `zap` (or `sarif-category`), tagged with the scan type; the HTML, Markdown, JSON and SARIF reports are an
artifact. A repository with no service has nothing to call it for.

| `scan-type` | What ZAP does | What it finds | What it cannot find |
|---|---|---|---|
| `baseline` (default) | Spiders the service and runs the passive rules over every response. No attack traffic | Missing or weak security headers, cookies without flags, server banners, information leaking in responses | Anything the server does with its input |
| `full` | The baseline, then ZAP's active rules against every URL and parameter the spider found | Reflected and persistent cross-site scripting, SQL and command injection, path traversal, remote file inclusion and the rest of the active rules, plus everything the baseline finds | Operations no link reaches; anything behind a login |
| `api` | Imports `api-definition` (OpenAPI, SOAP or GraphQL), sends every operation with the parameters it declares, runs the active rules of the API-Minimal policy and alerts on unexpected status codes and content types | The same classes of hole in an API, including operations no page links to, since the definition is the map | Operations the definition leaves out |

**Why it exists.** The stack had SAST, secrets, dependency, container and workflow scanning and nothing that looked at a service
the way a client sees it: missing security headers, cookies without flags, a server banner. That was the baseline, part of
issue #97. The full and api scans came next because the baseline, by design, cannot see the holes that matter most: a page that
reflects its query unescaped has perfect headers and passes it. Static analysis finds some of those; the active scan finds them
by doing what an attacker does, against the running code, and is the one check here with no static substitute.

Start with `baseline` and get it to pass at `medium`; its findings are the ones a reverse proxy fixes in an afternoon. Then switch
to `full`, with `active-scan-minutes` and `timeout-minutes` set together. Give an API its own call with `scan-type: api`, a
second `artifact-name` and a second `sarif-category`, so the two uploads do not close each other's alerts.

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `scan` | `contents: read` | Runs *your* install and start commands and the ZAP image, like a test job. No token reaches the container |
| `upload` | `security-events: write` | Checks nothing out and runs no shell. Skipped on a pull request from a fork, and with `upload-sarif: false` |

- **Loopback only, and the active scans are why.** The `full` and `api` scans send attack payloads. A `target-url` or an
  `api-definition` URL that is not `127.0.0.1`, `localhost` or `[::1]` is refused before anything starts, so a typo cannot aim an
  attack at someone else. For `openapi` the definition's `servers` are overridden with `target-url`, so a definition that names
  production still scans the loopback service; `soap` and `graphql` take the definition's own addresses, which must be loopback.
- **The image, not an action.** `zaproxy/action-baseline`, `action-full-scan` and `action-api-scan` use the moving tag `stable`,
  file issues with the job's token and have no SARIF. The workflow runs the same image pinned by digest, with `-silent` so ZAP
  reaches nothing of its own: under `block` the allow-list is the image pull and GitHub. No action joins the allow-list for it.
- **`fail-on` is a risk level.** A page with no security headers is Medium, so the default `high` does not catch it; use `medium`
  for that. A reflected cross-site scripting hole is High, so the default catches it in a `full` or `api` scan. Accept a finding
  in `.zap/rules.tsv` (`IGNORE` plus a reason), never by raising the threshold.
- **A bounded active scan.** `active-scan-minutes` is ZAP's own maximum scan duration; `0` is no limit. A large service with
  many parameters can keep the active rules busy for a long time, so set it, and raise `timeout-minutes` to match.

Proving it can fail is part of the workflow's tests, one proof per scan type. `fixture/dast/server.py` serves a page with its
security headers (the baseline must pass), without them (`--insecure`: the baseline must fail at `medium`, pass at `high`), and
with a `/search` that echoes its query unescaped (`--vulnerable`: the baseline must pass, because nothing in the headers is
wrong, and the full scan must fail at `high` naming the cross-site scripting). It also serves a small JSON API with an OpenAPI
definition whose server is a host that does not exist, so the api scan can only find anything if the workflow redirected it to
loopback. `tests/test_dast.py` runs the job's steps against canned reports and against a fake `docker` that records which ZAP
script and flags each `scan-type` produces, and this repository's `dast-live` CI job runs all of it against the real image.

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
      scan-type: full          # baseline (default), full or api
      fail-on: medium
```

And for the API the same service exposes:

```yaml
  dast-api:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/dast.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write
    with:
      install-command: pip install .
      start-command: myapp serve --port 8080
      target-url: http://127.0.0.1:8080
      scan-type: api
      api-definition: openapi/myapp.yaml   # or http://127.0.0.1:8080/openapi.json
      fail-on: medium
      artifact-name: zap-api-reports
      sarif-category: zap-api
```

<!-- inputs -->

## What it refuses to do

It never scans a host that is not loopback, never gives the container a token, never lets the upload job run your code, never
reads `api-definition` for a scan type that would not use it (a silent no-op is how a check stops checking), and never passes a
finding by raising the threshold.
