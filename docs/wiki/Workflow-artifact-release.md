# artifact-release

**What it does.** For anything that is a file rather than an image (a `.deb`, a firmware binary, an offline bundle): runs your build
command, then publishes the matching files to the GitHub release with a `SHA256SUMS`, a keyless cosign signature bundle per file and
build provenance. No secret anywhere.

**Why it exists.** Three repositories each built a file by hand and attached it to a release with nothing a downloader could verify.
This is the container release's supply-chain story for a file.

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `build` | `contents: read` | Runs everything you wrote: `build-command` with `$VERSION` set (the tag with its prefix removed, or `0.0.0+<sha>` off a tag), `verify-command`, collection of every file matching `artifacts`, `release-notes-command`. Keeps sudo only because `build-install-command` may legitimately be `sudo apt-get install ...` |
| `publish` | `contents: write`, `id-token: write`, `attestations: write` | Checks nothing out. Writes `SHA256SUMS`, records provenance, signs every file with cosign (a `<file>.sigstore.json` bundle beside it) and attaches all of it |

A pull request builds and checks and never publishes.

## A minimal caller

```yaml
on:
  push: { tags: ['v*'] }
  pull_request:          # builds and checks; never publishes
  workflow_dispatch:

jobs:
  artifacts:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/artifact-release.yml@<sha> # vX.Y.Z
    permissions:
      contents: write
      id-token: write
      attestations: write
    with:
      publish: ${{ startsWith(github.ref, 'refs/tags/v') }}
      build-install-command: sudo apt-get install -y dpkg-dev
      build-command: ./packaging/debian/build.sh dist
      artifacts: dist/*.deb
      verify-command: dpkg-deb --info dist/*.deb | grep -q "Version: $VERSION"
      egress-policy: block
      extra-allowed-endpoints: azure.archive.ubuntu.com:80
```

Verify a download with `cosign verify-blob --bundle <file>.sigstore.json <file>` against this repository's identity, or
`gh attestation verify <file> --owner OWNER`. The build's hosts depend on your build command and go in `extra-allowed-endpoints`.
Outputs: `version`. SBOMs are not attached yet (issue #99).

<!-- inputs -->

## What it refuses to do

It never publishes from a pull request, never signs with a stored key, and fails if `build-command` is empty rather than publishing
nothing.
