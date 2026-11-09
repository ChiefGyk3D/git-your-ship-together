# The image fixture verify and fixture rescan in ci.yml check: signed, SBOM-attested and provenance-attested through
# container-release.yml by .github/workflows/fixture-image.yml, and pinned by digest in the DIGEST file next to this one.
# It does one thing, prints its version, so no network is touched at build and no secret is needed. The base is pinned
# by digest; Dependabot moves it (.github/dependabot.yml).
FROM alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2

LABEL org.opencontainers.image.title="gyst-fixture"
LABEL org.opencontainers.image.source="https://github.com/ChiefGyk3D/git-your-ship-together"

COPY VERSION /VERSION
USER 10001
ENTRYPOINT ["cat", "/VERSION"]
