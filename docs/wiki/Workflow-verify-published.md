# verify-published

**What it does.** Verifies a published image from the outside, the way an operator would: `cosign verify` for the signature,
`cosign verify-attestation --type spdxjson` for the SBOM, `gh attestation verify` for provenance, then each platform pulled and
your `test-command` run against it. Set `release-tag` and it verifies a GitHub release the same way: every asset against
`SHA256SUMS`, build provenance for every file, and (unless `verify-release-sbom` is false) the two SBOMs a Python package release
carries. A final `Verified` job is the gate. It stops at the first failure. With `rescan: true` it also asks what
verification cannot: whether an advisory has been published since the release (see below).

**Why it exists.** The producer signs, attaches an SBOM and records provenance, and nothing proved those verify from outside. A
signature nobody checks is a claim. Run it nightly and a release that stops verifying is a red job, not a surprise.

## Jobs and trust boundaries

`verify` has `contents: read` and `packages: read`. **No secret, no Doppler, no `id-token`.** A verifier that needs a credential is
trusting something. A platform that differs from the runner's (arm64 on the x86 runner) runs under QEMU, set up only then.

## A minimal caller

```yaml
on:
  schedule:
    - cron: "17 5 * * *"
  workflow_dispatch:

jobs:
  verify:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/verify-published.yml@<sha> # vX.Y.Z
    permissions:
      contents: read
      packages: read
    with:
      image: ghcr.io/OWNER/IMAGE:latest
      test-command: docker run --rm "$IMAGE" --version
```

A digest is stronger than a tag. The default `identity-regexp` matches any workflow in the maintainer's repositories and so
matches an image from [container-release](Workflow-container-release.md); narrow it to one workflow with a pattern like
`^https://github.com/ChiefGyk3D/git-your-ship-together/\.github/workflows/container-release\.yml@refs/tags/v`. **A fork should
change the default**, which names the maintainer. The allow-list was measured in block mode: this repository's `fixture verify`
job refused GitHub's attestation store until its blob host was added.

## The post-release rescan

Verification proves an artefact is what the producer published. It says nothing about what has been
reported against it since. `rescan: true` adds a `rescan` job that runs only if verification did not fail:

- **What it reads.** Each platform in `platforms` of `image`, pulled by Trivy from the registry (no
  Docker, no QEMU), and `sbom.cdx.json` from the release `release-tag`, the SBOM
  [python-package-release](Workflow-python-package-release.md) attaches. A release with no `sbom.cdx.json`
  fails the rescan rather than passing it.
- **Bound to what was verified.** The `verify` job resolves the image to its digest first and runs the
  signature, SBOM and provenance checks against `repo@sha256:...`; the rescan scans that digest, never the
  tag, so a tag that moves between jobs is not scanned unverified. The release SBOM is the file
  `verify-release` checked, carried to the rescan as a one-day workflow artifact with its sha256; the
  rescan fails if the hash differs and never downloads the release a second time. An empty `platforms`
  list fails the rescan (no image scan ran) rather than passing.
- **What it fails on.** Findings at `rescan-severity` (`CRITICAL,HIGH`), with unfixed advisories skipped,
  using Trivy's exit code: `rescan-exit-code: "1"` fails, `"0"` reports only. Both halves are scanned
  before the step fails, and a Trivy error fails it too. The table is in the job log.
- **What it cannot find.** An advisory nobody has published, a package missing from the SBOM, or
  anything in code you wrote. A third-party SBOM matches less well than one Trivy generated, so the
  image scan is the stronger of the two.
- **The pin.** Trivy is a binary checked against `trivy-sha256`, not an action. It needs no new egress
  host: the database comes from `mirror.gcr.io` or `ghcr.io`, and the version check is switched off.
- **Accepted advisories.** `rescan-ignore-advisories` takes CVE and GHSA IDs and writes them to a
  `.trivyignore`; anything else is refused. Each ID needs an entry for your repository in
  `baseline/risk-register.yaml` with `trivy` in `where`. The weekly audit reads the input in your
  workflows and fails on an ID with no entry or a passed review date, as it does for pip-audit.

It is a rescan only if the caller schedules it. The caller above already has the nightly `schedule:`; add
`rescan: true` and, for a release, `release-tag`.

**Where the SARIF goes.** The reports (`*.sarif`, `*.txt`, one per platform and one for the release) are a
workflow artifact named `rescan-artifact-name`, kept 14 days. They are not uploaded to the Security tab by
the workflow: that needs `security-events: write`, and a called workflow that asks for a permission its
caller did not grant fails at startup for every caller, including the ones that never opted in. A caller
that wants the Security tab adds a job of its own, one upload per file with its own category:

```yaml
  upload:
    needs: verify
    if: always()
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/download-artifact@<sha> # vX.Y.Z
        with:
          name: verify-published-rescan
          path: rescan
      - uses: github/codeql-action/upload-sarif@<sha> # vX.Y.Z
        with:
          sarif_file: rescan/image-linux-amd64.sarif
          category: verify-published-rescan-image-amd64
```

**Proved to fail.** `tests/test_verify_published.py` runs the scan step against a fake `trivy` for the flags
and exit codes, and the `rescan-live` CI job runs the real pinned Trivy over an SBOM naming a package with
known critical advisories: the step goes red, naming them, and goes green again once they are all accepted.
The `fixture rescan` job calls the workflow itself, in block mode, over this repository's published image.

<!-- inputs -->

## What it refuses to do

It never holds a credential, never passes when verification failed (the `Verified` job fails unless the verification succeeded), and
never changes anything it verifies.
