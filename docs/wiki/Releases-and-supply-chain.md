# Releases and supply chain

**What this is.** How a tag becomes a published, signed, verifiable artifact, and how
anyone can check that from the outside. It covers the four release workflows
([container-release](Workflow-container-release.md),
[python-package-release](Workflow-python-package-release.md),
[artifact-release](Workflow-artifact-release.md) and the old name
[python-docker-release](Workflow-python-docker-release.md)) and the checker,
[verify-published](Workflow-verify-published.md).

## Why it exists

A signature proves only that someone with the key signed the file. Holding a signing key
is its own risk: it can be stolen, lost or left in a CI secret. And a release pipeline is
where a compromise is most valuable, because whatever goes in is then trusted by everyone
downstream. Four repositories had written the same Python package release by hand before it
existed here, with four slightly different checks.

## The pieces

**Pins by commit SHA.** Every action in these workflows, and every call of these workflows
from a caller, names a commit and carries the version in a comment. A tag can be moved; a
commit cannot. Callers' pins move through Dependabot after a seven-day cooldown. A
version tag in this repository is immutable by ruleset: a version cut by mistake is
superseded by the next number, never deleted and reused. Before cutting one, fetch the tags;
another session once cut v1.3.0 while a first believed the latest was v1.2.0, and the v1.2.1
that followed would have moved every caller's pin backwards.

**Keyless signing (Sigstore).** cosign signs using the job's own OIDC identity and records it
in the public Rekor log. The certificate names the workflow that ran, so there is no signing
key to hold or rotate. The identity is the *reusable* workflow, not the caller, which is how
Sigstore attributes a job inside a reusable workflow, and it is the point: one identity to
trust across every repository that calls it.

**Build provenance (SLSA).** GitHub's artifact attestation records which workflow, at which
commit, produced the artifact. Every release workflow records it for every file.

**SBOM.** The container release attaches an SPDX SBOM from syft as a cosign attestation, bound
to the same identity as the signature. The package and artifact releases do not attach one
yet; issue #99 proposes a CycloneDX and an SPDX file from syft over the built wheel and
sdist, listed in `SHA256SUMS` and attested with the rest. Not built.

**Checksums.** Package and artifact releases attach a `SHA256SUMS` file.

**PyPI Trusted Publishing.** PyPI accepts the job's OIDC identity for a named repository,
workflow file and environment. No API token exists. It also publishes PEP 740 attestations for
every file.

## Why a publishing build never reads the cache

Anyone who can open a pull request can write to the Actions cache. A poisoned layer inside a
release that is then signed is the one outcome a signature cannot undo, because the signature
is valid. So a publishing build never restores from the cache, and a test holds that. The CI
workflows do cache downloaded tools, and still check the hash of what is on disk on every run,
so a cache saves a download and never lowers the bar.

## Order and trust boundaries

- **Nothing is pushed, signed or attested from a pull request.** A pull request builds, tests
  and scans, then stops. A test holds that order.
- **The job that runs the caller's code is read-only.** In the package and artifact releases,
  `build` has `contents: read` and runs `build-command`, `verify-command` and the smoke test.
  The publishing jobs check nothing out and run only pinned actions and `gh` against files the
  build handed over.
- **Each platform is built and tested natively.** The container release builds `linux/arm64`
  on an arm64 runner and `linux/amd64` on an x86 one, so `docker-test-command` and the Trivy
  scan run against the real arm64 image. A `merge` job joins them into the index under the
  real tags.
- **A tag must agree with the version.** The package release reads the version off the sdist's
  own name and refuses a tag that disagrees.

## Verifying a release from the outside

```sh
cosign verify ghcr.io/OWNER/IMAGE:latest \
  --certificate-identity-regexp '^https://github.com/ChiefGyk3D/git-your-ship-together/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/OWNER/IMAGE:latest --owner OWNER
```

For a file: `cosign verify-blob --bundle <file>.sigstore.json <file>` against the same identity,
or `gh attestation verify <file> --owner OWNER`.

[verify-published](Workflow-verify-published.md) does this on a schedule: signature, SBOM
attestation and build provenance verified from outside, then each platform pulled and the
caller's test command run. It holds no token and no secret, because a verifier that needs a
credential is trusting something. Its allow-list was measured in block mode, and the first
run refused GitHub's attestation store until its blob host was added.

## What this refuses to do

It never publishes from a pull request, never reads the cache in a publishing build, never
signs with a stored key, and never lets a tag disagree with the packaged version.
