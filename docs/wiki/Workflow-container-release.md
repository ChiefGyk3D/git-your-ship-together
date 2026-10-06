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
| `build` (per platform) | `contents: read`, `packages: write`, `security-events: write` | Builds and tests on a native runner (`ubuntu-24.04-arm` for arm64); non-root check; optional read-only probe; Trivy scan to SARIF. When publishing, pushes a temporary `<sha>-<arch>` tag |
| `merge` | `contents: read`, `packages: write`, `id-token: write`, `attestations: write` | Joins the platform images into the index under the real tags, then signs, attaches the SBOM and records provenance. Only after a push, never on a pull request |

The build job pushes only its own temporary platform tags; the signing identity exists only in `merge`.

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
- **Trivy's setuptools finding may be pip's.** pip vendors its own setuptools and msgpack under `pip/_vendor`, so upgrading
  setuptools in the image clears nothing; `pip uninstall -y pip` as the last build step does.
- **Temporary tags stay in GHCR** beside the index; delete them when you no longer need them.
- **The signing certificate names the innermost workflow.** Verify with `--certificate-identity-regexp`
  (`^https://github.com/ChiefGyk3D/git-your-ship-together/`), which matches this file and the old name alike.

<!-- inputs -->

## What it refuses to do

It never pushes, signs or attests from a pull request, never reads the Actions cache while building a release, and never ships an
image that runs as root unless the caller turns the check off.
