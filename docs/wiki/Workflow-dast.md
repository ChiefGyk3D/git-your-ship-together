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
lives in a context, and so is a user the context does not hold, before the service starts, so a typo cannot become an
anonymous scan that passes.

**All three scan types take them.** This was decided by reading the scripts in the pinned image, not by assumption:
`zap-baseline.py`, `zap-full-scan.py` and `zap-api-scan.py` each accept `-n` and `-U`, load the context before the first
request and look the user up in it, and the shared `zap_common.py` runs the spider as that user (`spider.scan_as_user`, and the
AJAX and client spiders the same way) and the active scan as that user. So the baseline's passive rules see the signed-in pages
too, and nothing is refused by scan type. A live test shows it rather than trusting the read: the baseline over the login
fixture without its headers alerts on `/account` only when given the context and the user.

What goes in the context file matters more than the scan, because ZAP sends the user's credentials to the URLs the file names.

- **The credentials are a throwaway account's.** The file is committed, so what it holds is public to everyone who can read the
  repository. The service is the one this job starts on loopback, with a recorded dataset, so the account opens nothing real.
  A credential that opens anything else does not belong in a context file; this workflow has no input for a secret, on purpose.
- **The port in it must match `target-url`.** A context names its login URL in full; a mismatch is a scan that never signs in.
- **The logged-out indicator is yours to get right.** ZAP checks every response against it, and a hit makes it sign in again.
  The fixture's matches the redirect to `/login` and the sign-in page and nothing a signed-in session sees. A logged-in indicator
  that the login's own redirect does not carry is worse than none: ZAP counted every sign-in as failed and shut itself down
  while this was being built.

### What the context guard checks

The guard is a step that runs before the service starts. It parses the file as XML, never with a pattern: CDATA, character
references and entities hide a URL from a pattern over the text (an earlier version of the guard was a `grep`, and
`<loginurl><![CDATA[https://example.com/login]]></loginurl>` matched nothing). It refuses the file unless:

- it declares no DOCTYPE or entity, is UTF-8 and holds exactly one `<context>`, and no element the guard reads has child
  elements inside it. ZAP's configuration reader returns only an element's own text, so
  `<loginurl>http://<x>127.0.0.1:8080/</x>evil.example/login</loginurl>` reads as loopback to a parser that joins the children
  and as `http://evil.example/login` to ZAP (measured with ZAP 2.17.0's own reader in the security review). The guard reads
  exactly the element's own text and refuses mixed content;
- every `loginurl`, `loginpageurl` and `pollurl`, decoded, is an absolute `http` or `https` URL whose host is loopback once
  normalised: `localhost`, an address in `127.0.0.0/8`, or `::1`. Case is normalised, so `HTTP://LocalHost:8080` passes. Decimal,
  octal, hex and short IPv4 (`2130706433`, `0x7f.0.0.1`, `0177.0.0.1`, `127.1`), `0.0.0.0`, `::`, IPv4-mapped IPv6, zone ids,
  `localhost.` and look-alikes such as `127.0.0.1.evil.example` are refused: a resolver may accept them, so the check does not;
- none of those URLs has user information (`http://127.0.0.1@evil.example`), a fragment, a backslash, whitespace (parsers
  disagree about them) or a `${...}` interpolation (ZAP expands them), a `{%username%}` or `{%password%}` token, a query parameter named like a credential, or a user's
  credential in it. ZAP substitutes the tokens into a login URL, which would put the credential in the URL and in every log and
  report that records it; they belong in `loginbody`, the POST body;
- the authentication is manual (type 0), form-based (2) or JSON-based (5), with only the elements ZAP's export writes. HTTP,
  script, browser-based and auto-detect authentication can sign in at hosts or run code the guard cannot read, so they are
  refused rather than let through, as is session management other than cookies. These are the type numbers of ZAP 2.17.0,
  read from an export of each;
- every `incregexes` entry fits a whitelist grammar, because Java matches the whole URL against it (`Context.isInContext` in the
  2.17.0 jar) and anything loose is a second scope: an escaped loopback origin (dots as `\.`, IPv6 as `\[::1\]`; an unescaped
  dot is a wildcard, so `http://127.0.0.1:8080/.*` matches `http://127505051:8080/x`, and an unescaped `[::1]` is a character
  class), an optional port of digits, then the end or a literal `/`, literal path characters (letters, digits, `-`, `_`, `~`,
  `/`, `\.`) and at most one trailing `.*` or `$`. `http://127\.0\.0\.1:8080` and `http://127\.0\.0\.1:8080/.*` pass. Anything
  else is refused as a form the guard cannot prove safe, and the message says so and shows the form to use. `/?.*` and `/*.*`
  make the slash optional, so they match `http://127.0.0.1:8080@evil.example/x`, as does `:8080.*`; ZAP's own default
  `\Q...\E.*` is refused too. No other quantifier, group, class or alternation;
- when `context-user` is set, the context holds a user of that name. A context with no users at all is refused.

The bytes the guard validated are the bytes ZAP is given: the guard copies them to the runner's temporary directory with their
SHA-256, and the scan step copies and checks that file, never the path in the workspace, which the install and start commands
run after the guard and could have rewritten. This is not a lock: the start command runs with access to the context, so treat its
credentials as visible to it. A background process of the caller can still swap the file between the digest check and the copy
(measured: a loop writer got 28 of 300 hand-offs through), and such a process could read the throwaway credentials directly, so
the swap adds no exposure. It closes the install and start commands rewriting the file, not hostile concurrent caller code.

An error names the element and the rule and never prints the value it refused, because the value may be the credential.

### Credentials stay out of the output

The users' names and credentials are masked in the job log in every shape they take (raw, URL-encoded, HTML-escaped,
JSON-escaped, base64), each escaped the way the runner reads a workflow command (`%` as `%25`, a line break as `%0D` or `%0A`),
so a password that contains `%0A` is masked as itself and not as a newline; a credential with a real line break is refused. A step that runs whether or not the scan passed then removes them from `report.json`, `report.html`,
`report.md` and the SARIF before the report step builds the summary and before the artifact upload, and deletes the copy of the
context file from the work directory. If it cannot redact and check, it deletes the reports instead of uploading them. The JSON reports
are redacted by value after parsing and never by key, so a password that equals a report key (`alerts`) cannot rename the key
and turn the `fail-on` gate green; a report that does not parse is deleted. A credential
that is a slice of the `[redacted]` placeholder (`redacted`) is redacted in one pass and checked with the placeholder removed, so
it does not fail the job. A value
under four characters cannot be redacted without mangling the reports, so such a context is refused. The summary says a scan
was signed in, not as whom.

### Request-time enforcement: not required

The guard is static, and `egress-policy: block` is the request-time control; the workflow does not require it for `context-file`.
ZAP's own requests are fixed by the context: it signs in only at the vetted URLs, spiders only what the vetted include regexes
allow and attacks only `target-url`. What the guard cannot see is the service redirecting off host. That service is the
caller's own code, which already runs in this job with the same network, so it needs no ZAP to reach out, and `block` is the
control for it (this repository's own `fixture dast` job runs under `block`). Requiring `block` for `context-file` would make
the feature unusable on the default and add no check that has been measured: harden-runner's enforcement on a container with
host networking was not measured here. Use `block` for a signed-in scan. A test pins that both policies pass the same static
check.

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
halves are tests, because a check that only passes proves nothing. So is every way a context can hide an off-host URL or put a
credential in one: each is a refused case, and the refusal is checked to print nothing it refused. `tests/test_dast.py` runs the job's steps against canned reports and against a fake `docker` that records which ZAP
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
reads `api-definition` for a scan type that would not use it (a silent no-op is how a check stops checking), never accepts a `context-user` with no context to find it in, never lets a context file point ZAP's sign-in at a host that is not loopback or carry a credential in a URL, never prints a value it refused, never uploads a report that still holds the context's credentials, and never passes a
finding by raising the threshold.
