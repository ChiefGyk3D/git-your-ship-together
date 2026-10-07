# dast

**What it does.** `security.yml` reads code; `dast.yml` is the check that talks to a running service. It starts the service your
repository serves (a dashboard, an API, a docs server) on loopback and runs one of [OWASP ZAP](https://www.zaproxy.org/)'s three
packaged scans against it, chosen by `scan-type`, failing the job when a finding reaches `fail-on`. Findings go to the Security
tab under category `zap` (or `sarif-category`), tagged with the scan type; the HTML, Markdown, JSON and SARIF reports are an
artifact. A repository with no service has nothing to call it for.

| `scan-type` | What ZAP does | What it finds | What it cannot find |
|---|---|---|---|
| `baseline` (default) | Spiders the service and runs the passive rules over every response. No attack traffic | Missing or weak security headers, cookies without flags, server banners, information leaking in responses | Anything the server does with its input |
| `full` | The baseline, then ZAP's active rules against every URL and parameter the spider found | Reflected and persistent cross-site scripting, SQL and command injection, path traversal, remote file inclusion and the rest of the active rules, plus everything the baseline finds | Operations no link reaches; anything behind a login unless `context-file` and `context-user` sign the scan in |
| `api` | Imports `api-definition` (OpenAPI, SOAP or GraphQL), sends every operation with the parameters it declares, runs the active rules of the API-Minimal policy and alerts on unexpected status codes and content types | The same classes of hole in an API, including operations no page links to, since the definition is the map | Operations the definition leaves out |

**Why it exists.** The stack had SAST, secrets, dependency, container and workflow scanning and nothing that looked at a service
the way a client sees it: missing security headers, cookies without flags, a server banner. That was the baseline, part of
issue #97. The full and api scans came next because the baseline, by design, cannot see the holes that matter most: a page that
reflects its query unescaped has perfect headers and passes it. Static analysis finds some of those; the active scan finds them
by doing what an attacker does, against the running code, and is the one check here with no static substitute.

Start with `baseline` and get it to pass at `medium`; its findings are the ones a reverse proxy fixes in an afternoon. Then switch
to `full`, with `active-scan-minutes` and `timeout-minutes` set together. Give an API its own call with `scan-type: api`, a
second `artifact-name` and a second `sarif-category`, so the two uploads do not close each other's alerts.

## Behind a login

The anonymous spider reaches what a link on a public page reaches. A form login in front of the rest stops it, and the pages
behind a login are where an application keeps most of what is worth attacking. `context-file` and `context-user` pass ZAP's
own `-n` and `-U`: the repository keeps a ZAP context (the URLs in scope, the login method, the users), exported from ZAP and
committed, and `context-user` names which of its users to scan as. The spider signs in as that user, and for `full` so does the
active scan, so the active rules reach the pages and parameters behind the login. `-U` without `-n` is refused, since a user
lives in a context, and a user the context does not hold fails the scan before it starts.

**All three scan types take them.** This was decided by reading the scripts in the pinned image, not by assumption:
`zap-baseline.py`, `zap-full-scan.py` and `zap-api-scan.py` each accept `-n` and `-U`, load the context before the first
request and look the user up in it, and the shared `zap_common.py` runs the spider as that user (`spider.scan_as_user`, and the
AJAX and client spiders the same way) and the active scan as that user. So the baseline's passive rules see the signed-in pages
too, and nothing is refused by scan type. A live test shows it rather than trusting the read: the baseline over the login
fixture without its headers alerts on `/account` only when given the context and the user.

What goes in the context file matters more than the scan:

- **The credentials are a throwaway account's.** The file is committed, so what it holds is public to everyone who can read the
  repository. The service is the one this job starts on loopback, with a recorded dataset, so the account opens nothing real.
  A credential that opens anything else does not belong in a context file; this workflow has no input for a secret, on purpose.
- **The port in it must match `target-url`.** A context names its login URL in full; a mismatch is a scan that never signs in.
  A login, login page or poll URL that is not loopback is refused before anything starts, so the credentials are never posted to
  another host.
- **The logged-in indicator is yours to get right.** It is the text of a page only a signed-in session sees. The fixture's is
  `Signed in as`, and a test checks that it matches the page a login lands on and not the login page.

What it cannot do: sign in through a login ZAP's authentication methods do not cover, or reach a deployed environment. That
stays refused with every other host that is not loopback; see the [Roadmap](Roadmap.md).

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

Proving it can fail is part of the workflow's tests, one proof per scan type, and one for the login. `fixture/dast/server.py` serves a page with its
security headers (the baseline must pass), without them (`--insecure`: the baseline must fail at `medium`, pass at `high`), and
with a `/search` that echoes its query unescaped (`--vulnerable`: the baseline must pass, because nothing in the headers is
wrong, and the full scan must fail at `high` naming the cross-site scripting). It also serves a small JSON API with an OpenAPI
definition whose server is a host that does not exist, so the api scan can only find anything if the workflow redirected it to
loopback. With `--login` the server adds a form login with throwaway credentials and, only behind it, the same unescaped echo
at `/account/search`; the public pages stay escaped. The full scan with no context passes that service at `high`, and the same
scan with `fixture/dast/login.context` and `context-user: throwaway` fails at `high` naming the cross-site scripting. Both
halves are tests, because a check that only passes proves nothing. `tests/test_dast.py` runs the job's steps against canned reports and against a fake `docker` that records which ZAP
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

And the pages behind the login, signed in as a throwaway user of the same service:

```yaml
  dast-signed-in:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/dast.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      security-events: write
    with:
      install-command: pip install .
      start-command: myapp serve --port 8080 --seed-test-user
      target-url: http://127.0.0.1:8080
      scan-type: full
      context-file: .zap/app.context       # exported from ZAP, committed; throwaway credentials only
      context-user: scan-user
      fail-on: medium
      artifact-name: zap-signed-in-reports
      sarif-category: zap-signed-in
```

<!-- inputs -->

## What it refuses to do

It never scans a host that is not loopback, never gives the container a token, never lets the upload job run your code, never
reads `api-definition` for a scan type that would not use it (a silent no-op is how a check stops checking), never accepts a `context-user` with no context to find it in, and never passes a
finding by raising the threshold.
