# artifact-release

**What it does.** For anything that is a file rather than an image (a `.deb`, a firmware binary, an offline bundle): runs your build
command, then publishes the matching files to the GitHub release with a `SHA256SUMS`, a keyless cosign signature bundle per file and
build provenance. No secret anywhere.

**Why it exists.** Three repositories each built a file by hand and attached it to a release with nothing a downloader could verify.
This is the container release's supply-chain story for a file.

**Publishing is an allow-list.** The publish job, and each step in it that signs, attests or uploads, runs only for an event named in `allowed-publish-events` (default `push`; a caller triggered by `release: published` sets `push,release`) on a `refs/tags/v<semver>` (SemVer 2.0.0: no leading zeroes, no empty identifiers) ref. An existing release is only completed: every asset must be absent or already there with the identical sha256 digest. Nothing is replaced; a differing asset fails the run and names it, and that version is burned. The asset set is read again after the upload and must hold exactly this build's files with identical digests, or the run fails. Concurrent writers to the same release are unsupported. The release must hold exactly the files this build produced: an asset that is not part of the build (an extra asset) is treated like a differing one and fails the run, before and after the upload. All assets are read through the paginated asset listing, so a release with more than one page of assets is checked in full. The release is looked up by its HTTP status (a 404 means no release; any other failure stops the run). Every local file name must follow the asset naming policy, checked before any release call: ASCII letters, digits, `.`, `_` and `-`, starting and ending with a letter or digit (an uploaded name that GitHub changed would break the exact comparison). This is a conservative repository naming policy, stricter than what GitHub documents: GitHub documents renaming for special characters and leading or trailing periods, and the policy also refuses names that start or end with `_` or `-`. Existing callers whose build produces such a name (spaces, `+`, non-ASCII, a leading or trailing `_` or `-`) must rename the file in their `build-command` before re-pinning; the run fails before any release call, so nothing is half-published. Every remote asset, extras included, must be in state `uploaded`, and no name may occur twice. Listing pages are validated as an array of arrays of objects before they are read, so a malformed listing stops the run. A draft release for the tag is not completed automatically: the run fails and asks you to publish or delete the draft, or burn the version.

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
