# python-package-release

**What it does.** Builds the sdist and wheel, runs `twine check --strict`, reads the version off the sdist's own name and refuses a
tag that disagrees, runs your `verify-command`, installs the wheel into a fresh virtual environment and runs your
`smoke-command`, writes the release notes; then publishes to PyPI (Trusted Publishing, PEP 740 attestations) and to the GitHub
release with a `SHA256SUMS` and build provenance. No secret anywhere.

**Why it exists.** Four repositories had written build, check, tag-against-version and PyPI publish by hand, four slightly different
ways. The checks that matter are the ones that catch a release that does not match its tag, or a wheel that does not install.

## Jobs and trust boundaries

| Job | Holds | Notes |
|---|---|---|
| `build` | `contents: read` | Everything that runs your code: the build, `twine check`, `verify-command`, the wheel smoke test, the release notes command |
| `publish-pypi` | `id-token: write` | Checks nothing out. Hands `dist/` to PyPI over the job's OIDC identity from the `pypi` environment |
| `github-release` | `contents: write`, `id-token: write`, `attestations: write` | Checks nothing out. Records provenance for every file and attaches them with a `SHA256SUMS`; creates the release from the notes or uploads to one that exists |

A pull request builds and checks and never publishes, whatever `publish` says. The version is read off the sdist's own name, so a
static `version =`, a dynamic attribute and a VCS plugin all answer alike.

## A minimal caller

```yaml
on:
  push: { tags: ['v*'] }
  pull_request:          # builds and checks; never publishes
  workflow_dispatch:

jobs:
  package:
    uses: ChiefGyk3D/git-your-ship-together/.github/workflows/python-package-release.yml@<sha> # vX.Y.Z
    permissions:
      contents: write      # the GitHub release and its assets
      id-token: write      # PyPI Trusted Publishing, and build provenance
      attestations: write  # the provenance record
    with:
      publish: ${{ startsWith(github.ref, 'refs/tags/v') }}
      verify-command: grep -q "^## \[$VERSION\]" CHANGELOG.md
      smoke-command: my-cli --version
      egress-policy: block
```

**PyPI setup, once per project.** On the project's *Publishing* page add a Trusted Publisher naming this owner, the calling
repository, the **caller's** workflow file name (not this one's) and the environment `pypi`. That is the whole credential.

The workflow outputs `version`. SBOMs are not attached yet; see issue #99 on [Releases and supply chain](Releases-and-supply-chain.md).

<!-- inputs -->

## What it refuses to do

It never publishes from a pull request, never publishes a tag that disagrees with the packaged version, and never needs a stored
credential.
