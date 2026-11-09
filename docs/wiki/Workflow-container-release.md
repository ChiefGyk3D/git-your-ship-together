# container-release

**What it does.** Builds a container image, tests it, scans it with Trivy, and only then publishes it multi-arch to GHCR (and
Docker Hub, if asked), signs it with cosign, attaches a syft SPDX SBOM as an attestation, and records SLSA build provenance. It
builds whatever the Dockerfile builds; the name no longer says Python. On a pull request it builds, tests and scans and stops.

**Why it exists.** The same release was hand-written in nine repositories. The properties that came out of it: nothing is
published, signed or attested from a pull request; a publishing build never reads the Actions cache; and each platform is built and
tested natively, so the arm64 image the test runs against is the arm64 image that ships. See
[Releases and supply chain](Releases-and-supply-chain.md).

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `plan` | `contents: read` | Works out the per-platform build matrix and the lower-cased GHCR image name |
| `dockerfile-lint` | `contents: read` | hadolint, pinned version and per-architecture sha256, cached and hash-checked on disk |
| `build` (per platform, publishing runs only) | `contents: read`, `packages: write`, `security-events: write` | Builds once on a native runner (`ubuntu-24.04-arm` for arm64), pushes under a temporary `<sha>-<run id>-<attempt>-<arch>` tag, pulls it back by digest and runs the non-root check, the optional read-only probe and the Trivy scan (SARIF) on that image; records its digest |
| `build-local` (per platform, runs that do not publish) | `contents: read`, `security-events: write` | The same checks on one local build. No package write, no login, no push |
| `merge` | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` | Stages an index per registry from the recorded digests (GHCR, and Docker Hub when enabled) under a tag of this run, checks each one's digest and contents and that the digests agree, then signs, attaches the SBOM, records provenance and verifies, and only then writes the real tags (`sha-` tags first, `latest` last). Only after a push, never on a pull request |

The build job pushes only its own temporary platform tags; the signing identity exists only in `merge`.

**Publishing is an allow-list.** With `push: true` the run publishes only for a push of a `vMAJOR.MINOR.PATCH` tag (SemVer 2.0.0 pre-release and build parts allowed). Any other run builds and scans, and says so in a warning annotation and the step summary. `allowed-publish-events` (default `push`; `*` or comma-separated lowercase names, no spaces) and `require-tag-ref` (default `true`) widen it.

**BREAKING CHANGE.** Publishing is an allow-list: only a push of a `vMAJOR.MINOR.PATCH` tag publishes unless the caller sets `allowed-publish-events` and `require-tag-ref: false`. A refused `push: true` run builds and scans, and prints a `publish skipped` warning annotation and a job summary with the reason and the inputs to set. Also in this release: the build is split into `build` (publishing) and `build-local`; each registry gets its own index built from verified digests; `platforms` is validated as written and a repeated platform is refused; the tag check is SemVer 2.0.0; `allowed-publish-events` is validated. `penguin-overlord` and `solarstorm_scout` (main, schedule and manual publishers) add `allowed-publish-events: push,schedule,workflow_dispatch` and `require-tag-ref: false`; `hypeman` calls `python-package-release.yml` instead and follows that workflow's publish inputs.

**Docker Hub.** The per-registry index relies on buildx copying GHCR sources into Docker Hub. That is observed behavior of the previous version in production: `ChiefGyk3D/Stream-Daemon` run 41512180852 (2026-11-02, success) logged `copying ... from ghcr.io/... to docker.io/...`. Docker's documentation says sources must already exist in the destination registry; if buildx enforced that, the Docker Hub step would fail before signing.

**Migrating.** A caller that published from `main`, a schedule or a manual run (for example `penguin-overlord` and `solarstorm_scout`, which pass `push: ${{ github.event_name != 'pull_request' }}`) sets `allowed-publish-events: push,schedule,workflow_dispatch` and `require-tag-ref: false`; a caller that releases only from `v*.*.*` tags changes nothing.

**One build per platform.** A publishing leg builds once, pushes it, pulls it back by digest and runs the checks and the Trivy scan on that image; a non-publishing leg builds once, locally. `merge` stages the index under `stage-<sha>-<run id>-<attempt>` and verifies its digest and contents. No release tag is written there.

**Order of a publish (issue #286).** Stage the index in each registry, sign it, attest the SBOM, record provenance and verify the signature and the SBOM attestation of that digest with the pinned identity; only then does the tag step write the release tags. If any earlier step fails, no release tag moves.

**The tag step is bounded, not atomic.** A registry cannot write several tags in one step, so the step cannot promise that all tags move or none. Before writing anything it checks that the staged index reads back at its digest in each registry and records the digest every release tag holds now (a not-found reply means the tag is new; any other read failure stops the step with nothing moved). It writes one tag at a time, immutable `sha-` tags first and `latest` last, each from its own registry, reads each back, and reads every tag again after the last write. Every registry call is retried up to 4 attempts in all (5, 10 and 20 seconds), only for HTTP 408, 425, 429, any 5xx or a timeout or reset; a write that returns an error is judged by reading the tag back. Every digest a tag moves to is already signed, attested and verified.

On a failure the restore is best effort and never overwrites another writer. A tag is written back to its previous digest only while it still holds the digest this run wrote; a tag that holds any other digest was changed by someone else and is left alone, and the step fails with a "rollback failed" error naming the tag, the digest it holds, the digest this run promoted and the recorded previous digest. A tag already back on its previous digest needs no write. A restore needs the previous manifest to still exist, and the previous digest is whatever the tag held: this workflow does not verify it again. A tag that did not exist before cannot be deleted, so it may remain on the new digest; the step names it. If a restore is refused or fails, the step fails and names every tag and digest left behind. The step does not stop another writer with registry access. A registry has no compare-and-swap on a tag, so the read before a restore write cannot be made atomic with it; this window cannot be closed, only narrowed by the concurrency group and an immediate re-read.

**One publish per GHCR image, and release order.** Runs that publish the same GHCR image run one at a time whether or not Docker Hub is on, whatever their ref, and a running one is never cancelled. The key is the GHCR image, never the ref, the commit or other event data; Docker Hub is not in it, so callers with different GHCR images that share a Hub repository are not queued behind each other. The image name and `dockerhub-repository` take only letters, digits, `.`, `_`, `-` and `/` on one line. The ref is re-checked before each moving tag and once after the last; a run that is no longer the newest is rolled back and fails. GitHub keeps one pending run per group, so a pending run is replaced by a newer pending run for the same image; re-run the replaced one. The tag step also checks order. On a branch ref a run whose commit is no longer the head publishes only its `sha-` tags. On a `vMAJOR.MINOR.PATCH` tag ref it lists the repository's `v*` tags through the API (`contents: read`) and compares SemVer 2.0.0 precedence (a stable release against stable releases only): if a newer release exists it publishes only its version tag and the `sha-` tags and leaves `latest`, the major and minor tags alone, with a notice. A tag ref that is not a SemVer release has no order, so it publishes only its own name and the `sha-` tags. If the head or the tag list cannot be read, nothing moves.

**Rekor conflicts and retries.** A Rekor `409` (`an equivalent entry already exists`) is success only when `cosign verify` (`verify-attestation` for the SBOM) of that digest passes with `signer-identity-regexp`, the GitHub OIDC issuer, the calling repository and the commit of the run. A transient error (HTTP 408, 425, 429 and every 5xx, a timeout, a reset connection) is retried 4 times in all, waiting 5, 10 and 20 seconds. Any other error fails at once.

**Signing is required to publish.** A run that would publish with `sign`, `sbom` or `provenance` off fails in the plan job, and the tag step refuses too, unless `allow-unsigned-publish: true`. A run that does not publish is unaffected. `signer-identity-regexp` is validated in the plan job and again in `merge`.

## A minimal caller

```yaml
on:
  push:
    branches: [main]
    tags: ['v*.*.*']
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 5 * * 1'   # weekly rebuild of `latest`, so base-image fixes ship between commits

jobs:
  container:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/container-release.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
      security-events: write
    secrets:
      DOPPLER_TOKEN: ${{ secrets.DOPPLER_TOKEN }}
    with:
      push: ${{ github.event_name != 'pull_request' }}
      docker-test-command: docker run --rm "$IMAGE" python -c "import mypkg"
      egress-policy: block
      doppler-project: ci
      doppler-config: ci
      doppler-identity-id: ${{ vars.DOPPLER_IDENTITY_ID }}
```

## Behaviour from measured trouble

- **Hardening gates (2026-10-03).** hadolint on the Dockerfile; a non-root check in the workflow itself
  (`require-non-root`, default on; fix is a `USER` instruction); an opt-in read-only root filesystem probe; and
  `trivy-exit-code` now defaults to `"1"`, with `trivy-ignore-unfixed` so an advisory with no fix does not block. A caller with a
  fixable high or critical goes red until its base image or dependency moves; `trivyignores` takes a `.trivyignore` whose entries
  each carry a reason and a review date.
- **Secret findings inside installed packages (2026-11-07).** Trivy's `gcp-service-account` rule matched docstring text about an
  API enum value in the installed `anthropic` SDK (11 CRITICAL findings under `/opt/venv/lib/python3.14/site-packages/anthropic/`
  on Boon-Tube-Daemon's image); the newest SDK has it and no fixed version exists. `skip-secret-scan-in-site-packages: true`
  (default `false`) makes Trivy drop all secret findings (every secret rule; it still reads the files, so this is not a performance boundary) for files matched by one `allow-rules` path entry, anchored at the image root, under `usr/lib`, `usr/lib64`, `usr/local/lib`, `usr/local/lib64` and `opt/venv/lib`, each followed by `pythonX.Y/site-packages/` (numeric version), anchored at the image root. The path is
  `^(usr/(local/)?lib(64)?|opt/venv/lib)/python[0-9]+\.[0-9]+/site-packages/`; Trivy matches image paths without a leading slash
  (measured with Trivy 0.76.2 and 0.70.0, the version trivy-action v0.36.0 installs by default). The config is passed through `TRIVY_SECRET_CONFIG` (the
  `--secret-config` flag; trivy-action has no input for it). The vulnerability scan, severity, `ignore-unfixed` and exit code are untouched.
  **Tradeoff:** a genuine secret shipped by a dependency under those roots will NOT be detected; secrets at every other path
  are still found. The rule is path-wide because Trivy documents per-rule allow rules only inside custom rules, and a custom rule
  with a built-in's id runs beside the built-in instead of replacing it. Fork pull requests: a caller that passes this input on `pull_request` events lets an untrusted pull request's image weaken only its own secret detection; publishing is already gated off for pull requests. Source: Trivy secret scanning docs, "Allow Rules", read 2026-11-07.
- **A red Trivy scan names what tripped it.** When the scan step fails, a following `Summarize a failed Trivy scan` step (`inputs.trivy && failure()`, 2 minutes at most, no network) prints, from the SARIF the scan already wrote, the totals by severity and one row per rule id and file path with its count, secret rules first. It never prints the matched text, a message or a snippet, and it always exits 0, so it never changes pass or fail. When every secret hit is under `site-packages`, it adds one line pointing at `skip-secret-scan-in-site-packages: true` (opt-in, left off by default; CVE scanning stays on). Source and tests: `scripts/trivy_sarif_summary.py`, `tests/test_trivy_sarif_summary.py`.
- **Trivy's setuptools finding may be pip's.** pip vendors its own setuptools and msgpack under `pip/_vendor`, so upgrading
  setuptools in the image clears nothing; `pip uninstall -y pip` as the last build step does.
- **Temporary tags stay in GHCR** beside the index; delete them when you no longer need them.
- **The signing certificate names the innermost workflow.** Verify with `--certificate-identity-regexp`
  (`^https://github.com/ChiefGyk3D/git-your-ship-together/`), which matches this file and the old name alike.

<!-- inputs -->

## What it refuses to do

It never pushes, signs or attests from a pull request, never reads the Actions cache while building a release, and never ships an
image that runs as root unless the caller turns the check off.
