# python-package-release

**What it does.** Builds the sdist and wheel, runs `twine check --strict`, reads the version off the sdist's own name and refuses a
tag that disagrees, runs your `verify-command`, installs the wheel into a fresh virtual environment and runs your
`smoke-command`, writes the release notes; then publishes to the GitHub release with a `SHA256SUMS` and build provenance. PyPI
(Trusted Publishing, PEP 740 attestations) is published from a job in *your* workflow (download the `dist` artifact, run the pypa action),
because PyPI cannot trust a reusable workflow as the publisher. No secret anywhere.

**Why it exists.** Four repositories had written build, check, tag-against-version and PyPI publish by hand, four slightly different
ways. The checks that matter are the ones that catch a release that does not match its tag, or a wheel that does not install.

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `build` | `contents: read` | Everything that runs your code: the build, `twine check`, `verify-command`, the wheel smoke test, the release notes command |
| `pypi-unsupported` | `contents: read` | Runs only when a caller still passes `pypi: true`: fails at once with the fix, instead of at PyPI with `invalid-publisher` |
| `github-release` | `contents: write`, `id-token: write`, `attestations: write` | Checks nothing out. Records provenance for every file and attaches them with a `SHA256SUMS`; creates the release from the notes or uploads to one that exists |

**SBOMs.** The build job also runs [syft](https://github.com/anchore/syft) (pinned by version and sha256, the `syft-version`
and `syft-sha256` inputs) over the unpacked wheel and sdist and writes `sbom.cdx.json` (CycloneDX) and `sbom.spdx.json` (SPDX). They
are their own artifact, so PyPI never receives them; `github-release` adds them to the release, to `SHA256SUMS` and to the same
provenance step. `sbom: true` is the default, and a pull request writes them too, so a broken SBOM is a red check, not a surprise at
tag time. They list the package and its metadata, not a resolved dependency tree. `artifact-release.yml` does not write them: its
files are arbitrary (a `.deb`, a firmware blob) and syft would report nothing, which reads as assurance and is not.

A pull request builds and checks and never publishes, whatever `publish` says. The version is read off the sdist's own name, so a
static `version =`, a dynamic attribute and a VCS plugin all answer alike.

## A minimal caller

```yaml
on:
  release: { types: [published] }
  pull_request:          # builds and checks; never publishes
  workflow_dispatch:

jobs:
  package:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-package-release.yml@<sha> # vX.Y.Z
    permissions:
      contents: write      # the GitHub release and its assets
      id-token: write      # build provenance
      attestations: write  # the provenance record
    with:
      publish: ${{ github.event_name == 'release' }}   # the GitHub release step; pypi stays false
      verify-command: grep -q "^## \[$VERSION\]" CHANGELOG.md
      smoke-command: my-cli --version
      egress-policy: block

  publish-pypi:
    needs: package
    if: github.event_name == 'release'
    runs-on: ubuntu-latest
    environment:
      name: pypi            # the name the Trusted Publisher on PyPI holds
      url: https://pypi.org/p/<project>
    permissions:
      contents: read
      id-token: write       # PyPI Trusted Publishing; the OIDC token names THIS workflow
    steps:
      - uses: step-security/harden-runner@<sha> # vX.Y.Z
        with:
          egress-policy: block
          allowed-endpoints: api.github.com:443 files.pythonhosted.org:443 fulcio.sigstore.dev:443 ghcr.io:443 github.com:443 pkg-containers.githubusercontent.com:443 productionresultssa12.blob.core.windows.net:443 pypi.org:443 rekor.sigstore.dev:443 release-assets.githubusercontent.com:443 timestamp.sigstore.dev:443 tuf-repo-cdn.sigstore.dev:443 upload.pypi.org:443 uploads.github.com:443
          disable-sudo: true
          disable-telemetry: true
      - uses: actions/download-artifact@<sha> # vX.Y.Z
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@<sha> # vX.Y.Z
        with:
          attestations: true
```

**Why PyPI is published from your workflow.** PyPI matches the OIDC token's `job_workflow_ref`. Inside a reusable workflow that is
the reusable file, so a Trusted Publisher registered for your workflow is answered `invalid-publisher` even when owner, repository,
workflow file and environment all match (warehouse#11096; hypeman v0.3.1 and v0.3.2). The `publish-pypi` job above lives in your file, `needs` the `package` job, downloads the `dist` artifact and runs
`pypa/gh-action-pypi-publish` with attestations, so the token names your workflow. The
`package` job keeps `publish:` on so the GitHub release step still runs, with `pypi` left `false`. The pypa action is a Docker
action, so the job's `harden-runner` list needs `ghcr.io:443` and `pkg-containers.githubusercontent.com:443` under `block`.

**Warning: the pypa action must be a direct step of your job.** `pypa/gh-action-pypi-publish` is a Docker action that derives its image from the repository of the action that *contains* it. Wrapped in a composite action or a reusable workflow it resolves to that repository's image: GYST v1.19.0 wrapped it in a composite, and hypeman's v0.3.3 release ran `docker run ghcr.io/ChiefGyk3D/git-your-ship-together:<sha>`, which does not exist, and failed with "Run 'docker run --help'" (run 37976560401). Keep both steps in your own job, as above.

**PyPI setup, once per project.** On the project's *Publishing* page add a Trusted Publisher naming this owner, the calling
repository, the file name of the workflow that holds the `publish-pypi` job and the environment `pypi`. That is the whole credential.

The workflow outputs `version`. SBOMs are not attached yet; see issue #99 on [Releases and supply chain](Releases-and-supply-chain.md).

<!-- inputs -->

## What it refuses to do

It never publishes from a pull request, never publishes a tag that disagrees with the packaged version, and never needs a stored
credential.
