# The fixture image: the same shape as the calling repositories' images, so the
# release workflow's build, check and scan steps run against something real.
# The base is pinned by digest; Dependabot moves it.
FROM python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0

LABEL org.opencontainers.image.title="fixture-app"
LABEL org.opencontainers.image.source="https://github.com/ChiefGyk3D/git-your-ship-together"

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
# No third-party dependencies: --no-deps proves that, and there is nothing to hash.
RUN pip install --no-cache-dir --no-deps . \
    && useradd --create-home --uid 1000 app
USER app
ENTRYPOINT ["fixture-app"]
