# Testing and the contract

The tests are the **contract**: every rule in [Design rules](Design-rules.md) is a
test, so a pull request that breaks one fails before review. This is most of the repository's value:
it is what turns "we pin our actions" from a habit into a build failure.

## Two kinds of verification

| Kind | Question it answers | Where |
|---|---|---|
| **Structural** | Does the YAML have the right *shape*? (pins, permissions, harden-runner first, no unsafe interpolation...) | `tests/` (pytest) |
| **Dogfooding** | Does the workflow actually *run* against a real project? | `fixture/` plus `ci.yml`, `security-self.yml`, `dependabot-auto-merge-self.yml` |

You need both. A structural test can pass on a workflow that fails at startup; a green run proves little about
a rule nobody checks. A test (`test_every_reusable_workflow_is_run_from_this_repository_at_the_pull_requests_ref`)
even insists that **every reusable workflow is called from this repository at the PR's own ref**, so a new one
cannot ship untried.

## The fixture

`fixture/` is the smallest project that exercises every job: a Python package with a console script, a test, a
linted tree, a non-root Dockerfile, a hash-pinned `requirements.txt`, an OpenTofu module with no provider (so `init`
needs no network), an Arduino sketch, a shell script with its own test, a site source, and an Atheris target. It is
**not an example to copy** (the real callers are); it is a test subject. `fixture/README.md` says how to regenerate the
lock.

## What each test file holds still

| File | Holds |
|---|---|
| `tests/test_workflows.py` | The core contract: SHA pins with version comments; no reference to this repository by branch; no workflow here triggers on `pull_request_target` (only a *caller* of `project-sync.yml` does); the write-permission allow-list; per-job permissions and timeouts; harden-runner first; `persist-credentials: false`; no untrusted interpolation; the inlined Doppler script identical to the composite action; no OIDC token on a job a pull request can run; every input declared, defaulted, used and documented; `CI green` needing every other job; signing only after a push; no Actions cache on a publishing build; allow-lists as one sorted line; every reusable workflow dogfooded; every README caller example granting each permission the called workflow's jobs declare (the lint behind the startup-failure row in [Troubleshooting](Troubleshooting.md)) |
| `tests/test_hygiene.py` | `disable-sudo`, concurrency rules, tool-download caching with hash checks, type-check and coverage-threshold behaviour |
| `tests/test_doppler_gate.py` | The Doppler "decide" script run under bash for every event and ref shape: trusted refs fetch, untrusted get a notice and never fail, forks never fetch |
| `tests/test_audit_baseline.py` | The audit fed a passing repository and a broken one per criterion; a 403 is UNKNOWN, never PASS |
| `tests/test_audit_workflow.py` | The weekly audit workflow's shape and token handling |
| `tests/test_risk_register.py` | The register's shape and dates; no duplicates; every repository named is in the baseline list; **no entry has expired** |
| `tests/test_fuzz.py` | `python-fuzz.yml`: its pin, and its run step executed against tiny targets (missing dir, no match, passing, crashing, hanging) |
| `tests/test_dast.py` | `dast.yml`: the contract (digest-pinned image, a read-only scan job, an upload job with no shell), its steps run under bash (every refusal, a service that blocks, detaches, dies or never answers, the `fail-on` threshold and the SARIF against canned ZAP reports), the scan step against a fake `docker` that records which ZAP script and flags each `scan-type` produces, and, in the `dast-live` CI job only, the real ZAP image against `fixture/dast/server.py`: the baseline passes with its headers and fails at `medium` without them; the page that reflects its query passes the baseline and fails the full scan at `high`; the escaping page passes the full scan at `medium`; the api scan imports the committed OpenAPI definition and scans the loopback service; with `--login`, the same service passes the anonymous full scan at `high` and fails it signed in with `fixture/dast/login.context` and `context-user` (and a headerless baseline alerts on `/account` only when signed in); the context guard has a refusal test per way a URL can hide or point off host (CDATA, entities, character references, mixed case, odd IPv4 and IPv6 forms, userinfo, tokens and credentials in a URL, unvetted authentication kinds, mixed content inside a URL element, include-regex alternations, a context with no users) that also checks the refusal prints nothing it refused, a signed-in scan must be proved by asking a protected page as the user and anonymously, before the attack and after the scan (its hook is run against a stand-in for ZAP's API, its report step with fifteen kinds of failed or missing evidence, and live: wrong credentials, a wrong login URL, an indicator no page contains and a login whose cookie the protected page never receives all fail and are never tagged authenticated), and a planted-credential test checks the SARIF, summary, log and reports come out clean |
| `tests/test_tool_locks.py` | No workflow runs an unhashed `pip install`; `security.yml`'s inline pip-audit and Semgrep locks equal `.github/requirements/*.txt`; the Snyk install refuses a lock without hashes |
| `tests/test_security_jobs.py` | Semgrep defaults and content-driven config; the gitleaks job as a pinned binary with its canary |
| `tests/test_image_hardening.py` | The container-release image checks (non-root, read-only probe) |
| `tests/test_verify_published.py` | `verify-published.yml`'s steps and gate, image and release halves |
| `tests/test_sbom.py` | The package release's SBOMs: the one syft pin, the SBOMs kept out of the PyPI upload and into the checksums and provenance; the CycloneDX file validated against its own schema version (the committed sample, or the fixture job's real output) |
| `tests/test_docs_wiki.py` | `docs-pages.yml` and `wiki-publish.yml`: where the write grants sit, default-branch-only, and the publish script itself run against a local git repository |
| `tests/test_project_sync.py` | `project-sync.yml` and `scripts/project_sync.py` against recorded API responses |
| `tests/test_pre_commit_hook.py` | The gitleaks pre-commit hook: same pin as `security.yml`, refuses a planted key without printing it, allows offline with a warning, copied byte for byte by `new-repo.sh` |
| `tests/test_new_repo.py` | `scripts/new-repo.sh --dry-run` over synthetic trees |
| `tests/test_fixture.py` | Every fixture requirement carries a hash; direct dependencies are in the lock; the fixture image is non-root |
| `tests/test_wiki.py` | **This wiki**: every reusable workflow has a page whose generated table follows its YAML; regenerating is a no-op and a stale tree is caught; links resolve and cited tests exist; and every workflow, script, composite action, audit check, test file and baseline file is mentioned somewhere |
| `tests/test_wiki_release_facts.py` | **Version facts in the wiki are generated**: the release placeholders render from a temp repository's tags (newest by version, the peeled commit SHA, the date, the merges since), and no hand page types a 40-hex SHA or a `# vX.Y.Z` pin comment |

(The exact set of files is whatever is in `tests/`; `test_wiki.py` is what catches a new one the wiki
has not mentioned.)

## Reading a failure

The messages are written to name the fix:

```
python-ci.yml: job 'foo' grants id-token: write. If intended, add it to ALLOWED_WRITES with a reason.
```

That is deliberate: a new write permission is a **review decision**, recorded with a reason, not an accident.

## Run them

```sh
pip install -r requirements-dev.txt
pytest
ruff check tests/ scripts/ fixture/ && ruff format --check tests/ fixture/
actionlint          # https://github.com/rhysd/actionlint
zizmor --offline .  # https://docs.zizmor.sh
```

Two tests do real network work when online (the gitleaks canary and the pre-commit hook tests download the pinned release; the Semgrep registry
resolution is opt-in with `GYST_TEST_SEMGREP_REGISTRY=1`). The default run stays hermetic where it can.

## A good exercise

Write a new rule as a test (for example, "every reusable workflow input has a description") and watch it fail honestly on whatever
breaks it. Reading how `REUSABLE` and `jobs()` are used to parametrise tests teaches the pattern faster than describing it.
