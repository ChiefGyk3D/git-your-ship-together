# gyst-fixture

The image `fixture verify` and `fixture rescan` in `.github/workflows/ci.yml` check, in place of a third-party
image on a moving tag (issues #285, #315, #381). It prints its version and nothing else.

- `Dockerfile`, `VERSION`: the whole image. Alpine pinned by digest, one file, no network at build, no secret.
- `.github/workflows/fixture-image.yml` builds and publishes it to `ghcr.io/chiefgyk3d/gyst-fixture` through this
  repository's own `container-release.yml` (SBOM and provenance attestations, keyless cosign signature) on a manual run
  or a push to `main` that changes this directory. Bump `VERSION` and the `value=` of the version tag in that
  workflow together (`tests/test_fixture_image.py` holds them equal).
- `DIGEST` is the only place the published digest is written. It holds `unpublished` (the CI jobs keep checking the
  star-daemon image) or `sha256:<64 hex>` (they check `gyst-fixture@sha256:<that>`). Changing it does not republish.

After a publish, put the digest the workflow reports in `DIGEST`. The owner step after the first publish (making the package public) is in the CHANGELOG entry that added this image.
