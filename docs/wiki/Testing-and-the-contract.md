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
needs no network) and a `tofu test` file for it, a Rego policy with its tests, an Arduino sketch, a shell script with its own test, a site source, and an Atheris target. It is
**not an example to copy** (the real callers are); it is a test subject. `fixture/README.md` says how to regenerate the
lock.

## What each test file holds still

| File | Holds |
|---|---|
| `tests/test_workflows.py` | The core contract: SHA pins with version comments; no reference to this repository by branch; no workflow here triggers on `pull_request_target` (only a *caller* of `project-sync.yml` does); the write-permission allow-list; per-job permissions and timeouts; harden-runner first; `persist-credentials: false`; no untrusted interpolation; the inlined Doppler script identical to the composite action; no OIDC token on a job a pull request can run; every input declared, defaulted, used and documented; `CI green` needing every other job; signing only after a push; no Actions cache on a publishing build; allow-lists as one sorted line; every reusable workflow dogfooded; every README caller example granting each permission the called workflow's jobs declare (the lint behind the startup-failure row in [Troubleshooting](Troubleshooting.md)) |
| `tests/test_hygiene.py` | `disable-sudo`, concurrency rules, tool-download caching with hash checks, type-check and coverage-threshold behaviour |
| `tests/test_egress_canary.py` | The egress canary script run under bash with a stubbed resolver and connect (healthy runner quiet, one dropped address fails with diagnostics, retry, union of lookups, real probes cannot hang), every inlined copy identical to `.github/actions/egress-canary`, and which jobs may follow `egress-policy-secretless` |
| `tests/test_fetch_release.py` | `scripts/fetch-release.sh` run under bash against a fake `curl` and `sleep`: the 5-try and 170 s bounds, backoff with jitter, a missing or mismatched SHA-256 fatal and never retried, the token only on github.com and never in argv or a `set -x` trace, every inlined copy identical to the script, and no step curling a release URL outside the helper |
| `tests/test_trivy_sarif_summary.py` | `scripts/trivy_sarif_summary.py` on fixture SARIF: secret hits under site-packages (table and hint), in app code and mixed (no hint), CVE-only, missing, empty and malformed files (exit 0), no message, snippet or help text in the output, hostile ids and paths escaped, a bounded table; both inlined copies identical, and the step runs only after a failure and cannot change the verdict |
| `tests/test_repin.py` | `scripts/repin.sh` run under bash against a fake `gh` and real git with a local remote: the pin-only rewrite, all-or-nothing refusals, downgrade, hostile API values, the pull request mode and the Dependabot template |
| `tests/test_wait_ci.py` | `scripts/wait-ci.sh` run under bash against a fake `gh` and a fake clock: the pinned head, abort and reset on a push, no checks and a context that has not reported are not green, exact context matching, failed and cancelled are red, another workflow's red or open check refuses or waits (with an allow-list), timeout, hung, a pinned squash merge with a bounded retry, a head that moves between the last check and the merge, the token never printed, bad input, and the composite action's step run end to end |
| `tests/test_distro_apt_retry.py` | the default `distro-setup-command` of `bash-ci.yml` and `python-ci.yml` run under bash against a fake `apt-get`: a healthy mirror takes one pass with no pause, a mirror mid-sync (Kali's "File has unexpected size") is retried up to six times with the lists cleared and a 20 to 60 s pause, and one that never settles exits non-zero with apt's error shown |
| `tests/test_doppler_gate.py` | The Doppler "decide" script run under bash for push, schedule, dispatch, pull request and other non-PR events across the ref shapes it lists: trusted refs fetch, untrusted get a notice and never fail, a fork's `pull_request` never fetches (`pull_request_target` with the gate off is pinned as it is), a refused tag fails a job that asked for a secret |
| `tests/test_doppler_outputs.py` | The Doppler action's `export` and `names` inputs run under bash against a stub `curl`: `outputs` mode writes nothing to `GITHUB_ENV`, the allow-list exports only what is named, a missing name fails, values are masked before they are written, and awkward values (multi-line, quotes, `$`, backticks, `::`) neither break the JSON nor inject a command |
| `tests/test_audit_baseline.py` | The audit fed a passing repository and a broken one per criterion; a 403 is UNKNOWN, never PASS |
| `tests/test_audit_workflow.py` | The weekly audit workflow's shape and token handling |
| `tests/test_risk_register.py` | The register's shape and dates; no duplicates; every repository named is in the baseline list; **no entry has expired** |
| `tests/test_fuzz.py` | `python-fuzz.yml`: its pin, and its run step executed against tiny targets (missing dir, no match, passing, crashing, hanging) |
| `tests/test_dast.py` | `dast.yml`: the contract (digest-pinned image, a read-only scan job, an upload job with no shell), its steps run under bash (every refusal, a service that blocks, detaches, dies or never answers, the `fail-on` threshold and the SARIF against canned ZAP reports), the scan step against a fake `docker` that records which ZAP script and flags each `scan-type` produces, and, in the `dast-live` CI job only, the real ZAP image against `fixture/dast/server.py`: the baseline passes with its headers and fails at `medium` without them; the page that reflects its query passes the baseline and fails the full scan at `high`; the escaping page passes the full scan at `medium`; the api scan imports the committed OpenAPI definition and scans the loopback service; with `--login`, the same service passes the anonymous full scan at `high` and fails it signed in with `fixture/dast/login.context` and `context-user` (and a headerless baseline alerts on `/account` only when signed in); the context guard has a refusal test per way a URL can hide or point off host (CDATA, entities, character references, mixed case, odd IPv4 and IPv6 forms, userinfo, tokens and credentials in a URL, unvetted authentication kinds, mixed content inside a URL element, include-regex alternations, a context with no users) that also checks the refusal prints nothing it refused, a signed-in scan must be proved by asking a protected page as the user and anonymously, before the attack and after the scan (its hook is run against a stand-in for ZAP's API, its report step with fifteen kinds of failed or missing evidence, and live: wrong credentials, a wrong login URL, an indicator no page contains and a login whose cookie the protected page never receives all fail and are never tagged authenticated), and a planted-credential test checks the SARIF, summary, log and reports come out clean |
| `tests/test_python_support.py` | `.github/python-support.json` is the one list of supported CPython versions with their security-support end dates; the `python-ci.yml` default matrix, `scripts/new-repo.sh` and the README equal it; every `python-version` input default is listed; no listed version is past its end date, judged against an injected clock |
| `tests/test_tool_locks.py` | No workflow runs an unhashed `pip install`; `security.yml`'s inline pip-audit and Semgrep locks equal `.github/requirements/*.txt`; the Snyk install refuses a lock without hashes |
| `tests/test_advanced_security.py` | `advanced-security`: the validation job rejects every invalid value (run under bash), always runs, and is a loud failure, not a gate (no job has `needs`); conditions skip only on `false`; uploads gated, scans not; the summary note |
| `tests/test_security_jobs.py` | Semgrep defaults and content-driven config; the gitleaks job as a pinned binary with its canary |
| `tests/test_gitleaks_scope.py` | The `gitleaks-scope` input (default `pr-commits`): a decision table over event and input value, fail closed on any other value, no expression in `run:`, and (network) the pinned binary on a pull request range; the `gitleaks-hash-manifest-paths` input: the generated overlay, every unusable path refused, and (network) the pinned binary allowing a SHA-256 only for the listed file and the one rule, never another rule or path, layered on the base commit's config |
| `tests/test_security_caller_gate.py` | The README security caller ends in a `gate` job over `ci-gate.yml` (`if: always()`, no token); a failed, cancelled or skipped scan is a red gate; the audit derives `gate / CI green` from a `ci-gate.yml` call and nothing from `security.yml` alone |
| `tests/test_image_hardening.py` | The container-release image checks (non-root, read-only probe) |
| `tests/test_container_release_digests.py` | container-release publishing: the plan job's publish decision run under bash over event and ref cases (only a `push` of a `refs/tags/v*` ref publishes by default; every other event, branch, malformed input refused; the old behavior only through explicit inputs), every pushing or signing step gated on that decision, per-run temporary tags, and the digest handoff: the record and index steps run against a stub registry, a missing, malformed, extra or wrong-platform digest refused before any merge |
| `tests/test_container_release_publish.py` | Publish order (release tags move last), the bounded tag step (first and later failure, wrong digest, failed rollback, against a fake registry), and Rekor 409 / retry handling (every 5xx) in container-release, run against stub cosign and docker |
| `tests/test_container_release_secret_skip.py` | container-release `skip-secret-scan-in-site-packages`: a boolean defaulting off; an allow path anchored at three image roots with a numeric version (negative cases for look-alike paths and malformed versions); the Trivy step's inputs unchanged in both jobs; the allow step runs under bash and writes one path-only `allow-rules` entry that skips only those roots; sixteen mutations of the workflow refused |
| `tests/test_verify_published.py` | `verify-published.yml`'s steps and gate, image and release halves; `source-repository` (default the calling repository, validated shape run under bash with injection-shaped values refused, passed to both cosign commands through env, fixture callers name their source); the rescan: off by default, Trivy pinned by hash with no action, the scan step run under bash against a fake `trivy` (flags per platform, a finding fails, `rescan-exit-code: "0"` only reports, an error before any report still fails, both halves scanned when the first fails, an ID that is not a CVE or GHSA is refused), and, in the `rescan-live` CI job only, the real Trivy over an SBOM naming a package with known critical advisories: it fails with SARIF and the advisory in the log, reports without failing at exit code 0, passes once every advisory is accepted, passes an empty SBOM |
| `tests/test_fixture_image.py` | The fixture image `fixture verify` and `fixture rescan` check: one Dockerfile on a digest-pinned base with no build-time network, `DIGEST` is `unpublished` or one valid sha256 and nothing else is accepted (the pin step is run under bash), the digest is written in no other tracked file, the fixture jobs name no image themselves, `fixture-image.yml` publishes through `container-release.yml` with the narrowest publish inputs while that workflow's defaults stay strict, and the signer identity regexp matches the signing workflow's subject and rejects others |
| `tests/test_base_image_digest.py` | `scripts/base_image_digest.py`: the FROM parser (stages, scratch, ARG defaults, continuations, hostile references refused with a positive twin each) and the report comparison (a fixable finding the current digest fixes fails; shared, unfixable and new findings do not; a report that is not a report fails); the workflow's inlined copy is byte for byte the script |
| `tests/test_base_image_workflow.py` | The compare step of `base-image-digest.yml` run under bash against a fake `docker` and a fake `trivy`: an unmoved tag passes without a scan, a fixable finding fails and writes the summary, `exit-code: "0"` only reports, an unresolvable digest or a failed scan fails instead of reading as clean |
| `tests/test_verify_main.py` | `scripts/verify_main.py` against a stubbed REST API and a fake clock (green head, no runs, red run, unreadable protection, wait exhausted, a moved head, hostile context names) and the shape of `main-verify.yml`: `actions: write` on the dispatch job only, default branch only, bounded, `ci.yml` still dispatchable |
| `tests/test_token_drift.py` | `scripts/check_token_drift.py` and `token-drift.yml`: a tampered file or lock, a missing file, traversal, a symlink, a FIFO, an oversize file and hostile refs fail; the live fetch is run against a fake API (one resolved commit for both requests, no redirect followed, the byte cap, the token only when set); the fixture jobs in `ci.yml` include planted ones a control job requires to drift; the workflow's inlined copy is byte for byte the script |
| `tests/test_vendored_drift.py` | `scripts/check_vendored_drift.py` and `vendored-drift.yml`: malformed, duplicate-key or escaping locks refused, a hash mismatch and a stale generator fail, no lock file fails, each negative case with a passing twin; the workflow's inlined copy is byte for byte the script |
| `tests/test_parallel_ci.py` | `parallel-ci.yml`: the planning script over ordinary and hostile inputs (path rules fail closed; every invalid input refused, each with a passing twin), the `changes` step in a real repository with a merge commit, the build and check steps under bash (an early-exiting setup cannot pass), and the YAML's properties (no `continue-on-error`, no expression in `run:`, no `$GITHUB_PATH` write, one-day artifact, caches off in audit) |
| `tests/test_ci_gate.py` | `scripts/parallel_ci_gate.py` and the gates of `parallel-ci.yml` and `ci-gate.yml`: only `success`, or a named skip, is green; the inlined copies are byte for byte the script |
| `tests/test_sbom.py` | The package release's SBOMs: the one syft pin, the SBOMs kept out of the PyPI upload and into the checksums and provenance; the CycloneDX file validated against its own schema version (the committed sample, or the fixture job's real output) |
| `tests/test_pypi_publish_egress.py` | The README's `publish-pypi` caller job allows every host the publish needs, the pypa Docker action's `ghcr.io` and `pkg-containers.githubusercontent.com` included; the reusable workflow carries none of them |
| `tests/test_pypi_publish_direct.py` | PyPI is published by direct steps in the caller's job: the README and wiki show download-artifact then the pinned pypa action with attestations, with the warning; no composite action in this repository wraps the pypa action; the reusable workflow no longer publishes to PyPI, `pypi: true` fails fast, the GitHub release does not depend on PyPI |
| `tests/test_release_publish_guards.py` | `artifact-release.yml` and `python-package-release.yml` publish only for an event in `allowed-publish-events` (default `push`) on a SemVer 2.0.0 `refs/tags/v<semver>` ref (valid and malformed tag matrices run under bash). One `context` step makes the decision and the job and step conditions are compared with the exact approved forms; each mutation (appended `|| true`, dropped or moved steps, `continue-on-error`, an unclassified write step) must each be caught. The upload step runs under bash against a stub `gh` that mimics `gh api --include`, pagination and GitHub's renaming of unsafe file names: a new release is created and re-read, an identical one uploads nothing, a partial one gets only its missing assets; a differing, digest-less, extra, duplicate, newline-named or not-`uploaded` (starter, missing, null, non-string, unknown state) remote asset fails and names it; assets past the first page and past 30 are all seen; the HTTP status line is parsed (odd casing and spacing accepted, `4040`, `404x`, a 500 whose text says 404 refused); lookup failures (401, 403, 429, 500, network, malformed JSON) stop the run; a draft release, a failing draft listing and a malformed draft listing fail closed; an asset changed, deleted, added or left in `starter` during the run is caught by the re-read; file names outside the repository naming policy fail before any `gh` call; malformed release and asset listings (`[{}]`, `[{"x":[]}]`, `{}`, `null`, mixed or scalar pages) never read as empty, an extra asset that is not `uploaded` or a duplicated extra is refused; a prerelease tag creates with `--prerelease` and a stable or build-metadata-only tag does not; a hidden file in the asset directory fails before any `gh` call; names differing only in case are refused before any `gh` call (the stub enforces case-insensitive uniqueness); an existing release with the wrong or a non-boolean `prerelease` value stops the run; `--clobber` appears nowhere; and every documented caller that publishes on the `release` event sets `allowed-publish-events` |
| `tests/test_docs_wiki.py` | `docs-pages.yml` and `wiki-publish.yml`: where the write grants sit, default-branch-only, and the publish script itself run against a local git repository |
| `tests/test_project_sync_wrapper.py` | `project-sync.yml` as a thin wrapper: the inputs callers pass, the pinned safo call, the Doppler key and the egress list |
| `tests/test_pre_commit_hook.py` | The gitleaks pre-commit hook: same pin as `security.yml`, refuses a planted key without printing it, allows offline with a warning, copied byte for byte by `new-repo.sh` |
| `tests/test_new_repo.py` | `scripts/new-repo.sh --dry-run` over synthetic trees |
| `tests/test_fixture.py` | Every fixture requirement carries a hash; direct dependencies are in the lock; the fixture image is non-root |
| `tests/test_wiki.py` | **This wiki**: every reusable workflow has a page whose generated table follows its YAML; regenerating is a no-op and a stale tree is caught; links resolve and cited tests exist; and every workflow, script, composite action, audit check, test file and baseline file is mentioned somewhere |
| `tests/test_wiki_release_facts.py` | **Version facts in the wiki are generated**: the release placeholders render from a temp repository's tags (newest by version, the peeled commit SHA, the date, the merges since), and no hand page types a 40-hex SHA or a `# vX.Y.Z` pin comment |
| `tests/test_pr_python_versions.py` | The `pr-python-versions` input of python-ci: empty by default so the matrix is unchanged, a reduced matrix on pull requests only, bad values refused, and `ci-green` still failing on a failed leg |

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
