# Release Workflows

Four ways to ship, one promise: **build once, check it, and only then publish,
and make the result verifiable by someone who does not trust you.** In every one,
the job that runs your build command is separate from the job that holds the
write token, and a pull request never publishes, signs or attests.

Full input tables:
[Container release](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#container-release),
[Verify published](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#verify-published),
[Python package release](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#python-package-release),
[Artifact release](https://github.com/ChiefGyk3D/git-your-ship-together/blob/main/README.md#artifact-release).

## container-release

`.github/workflows/container-release.yml`. Builds whatever your Dockerfile builds.

**Jobs:** `plan` (decide platforms), `dockerfile-lint` (hadolint), `build` (per
platform), `merge` (publish and sign).

**What a push produces**, for every platform in `platforms`:

1. The image at `ghcr.io/<owner>/<repo>`, and at Docker Hub too when `dockerhub: true`
   and the Doppler config holds the credentials.
2. A **cosign keyless signature** on the image index. The certificate names *this
   workflow's* identity, so there is no signing key to hold or rotate.
3. An **SPDX SBOM** from syft, attached as a cosign attestation and kept as an artifact.
4. **SLSA build provenance** through GitHub's attestation API.
5. A **Trivy scan** uploaded to the Security tab (on pull requests too).

**How it builds:**

- Each platform is **built and tested natively** on its own runner (`linux/arm64` on
  `ubuntu-24.04-arm`, `linux/amd64` on `ubuntu-24.04`), so your `docker-test-command`
  and the Trivy scan run against the *real* arm64 image, not an emulated one. QEMU is
  only used for a platform with no native runner.
- Per-platform images are pushed under temporary tags (`<sha>-<arch>`) and a `merge`
  job joins them into the index under the real tags.
- Checks before publish: hadolint on the Dockerfile; the image must run as non-root
  (`require-non-root`); optionally a read-only-filesystem probe.
- **On a pull request it builds, tests and scans and stops.**

**Verify it yourself** (what a consumer does):

```sh
cosign verify ghcr.io/chiefgyk3d/typo-sniper:latest \
  --certificate-identity-regexp '^https://github.com/ChiefGyk3D/git-your-ship-together/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/chiefgyk3d/typo-sniper:latest --owner ChiefGyk3D
```

The certificate identity is the **reusable workflow**, not the calling project.
That is how Sigstore attributes a job inside a reusable workflow, and it is the
point: **one identity to trust across every repository that calls it.**

## verify-published

`.github/workflows/verify-published.yml`: consumer-side verification.

The producer signs; this proves the signature, SBOM attestation and provenance
verify *from outside*, the way an operator would. Then it pulls each platform and
runs your `test-command`. Set `release-tag` and it verifies a GitHub release the same
way: every asset against `SHA256SUMS`, build provenance for every file, and (unless
`verify-release-sbom` is false) the two SBOMs a Python package release carries. It
stops at the first failure and ends in a `Verified` gate. It reads only: no secret, no Doppler, no `id-token`. Run it on a schedule so
you notice if a published image stops verifying.

## python-package-release

`.github/workflows/python-package-release.yml`: for PyPI and/or a GitHub release.

**Build job** (`contents: read`, runs your code): build the sdist and wheel,
`twine check --strict`, read the version off the sdist's own name, **refuse a tag
that disagrees with the packaged version**, run your `verify-command` (a CHANGELOG
section? a `__version__`?), install the wheel into a fresh venv and run your
`smoke-command`.

**Publish jobs** (check nothing out): `publish-pypi` uses **Trusted Publishing**,
meaning PyPI trusts the job's OIDC identity, so **no API token exists**; and
`github-release` attaches the files, a `SHA256SUMS` and build provenance to the release.

**SBOMs.** The build job also runs [syft](https://github.com/anchore/syft) (pinned by
version and sha256, the `syft-version` and `syft-sha256` inputs) over the unpacked wheel
and sdist and writes `sbom.cdx.json` (CycloneDX) and `sbom.spdx.json` (SPDX). They are
their own artifact, so PyPI never receives them; `github-release` adds them to the
release, to `SHA256SUMS` and to the same provenance step. `sbom: true` is the default,
and a pull request writes them too, so a broken SBOM is a red check, not a surprise at
tag time. They list the package and its metadata, not a resolved dependency tree.
`artifact-release.yml` does not write them: its files are arbitrary (a `.deb`, a
firmware blob) and syft would report nothing, which reads as assurance and is not.

One-time setup per project: on PyPI's *Publishing* page add a Trusted Publisher
naming the owner, the repository, the **caller's** workflow filename and the
environment `pypi`. That is the whole credential.

## artifact-release

`.github/workflows/artifact-release.yml`: for anything that is a file, not an image
(a `.deb`, firmware, an offline bundle).

Same story as the container release, for a file: your command builds it in a
read-only job (with `$VERSION` set from the tag, or `0.0.0+<sha>` off a tag); a second job that
checks nothing out writes `SHA256SUMS`, records provenance, **signs every file with
cosign** (a `<file>.sigstore.json` bundle beside it) and attaches everything to the
release. Verify a download with `cosign verify-blob --bundle <file>.sigstore.json <file>`
or `gh attestation verify <file> --owner ChiefGyk3D`.

## Choosing

| You ship... | Use |
|---|---|
| A container image | `container-release.yml` (+ `verify-published.yml` on a schedule) |
| A Python wheel | `python-package-release.yml` |
| A `.deb`, firmware binary, tarball | `artifact-release.yml` (firmware is compiled by `arduino-ci.yml` first) |
| More than one | Call more than one, from separate caller jobs |
