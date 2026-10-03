# The fixture image: the same shape as the calling repositories' images, so the
# release workflow's build, check and scan steps run against something real.
# The base is pinned by digest; Dependabot moves it.
FROM python:3.13-slim@sha256:bb2988715db2cf7ace7b53f38f3cffbef7c7046a656bee66245eb0ed386e2e81

LABEL org.opencontainers.image.title="fixture-app"
LABEL org.opencontainers.image.source="https://github.com/ChiefGyk3D/git-your-ship-together"

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
# No third-party dependencies: --no-deps proves that, and there is nothing to hash.
# pip is removed after the install: the image never installs anything again,
# and pip's vendored setuptools and msgpack are what Trivy otherwise reports
# against an image that ships neither.
RUN pip install --no-cache-dir --no-deps . \
    && pip uninstall -y pip \
    && useradd --create-home --uid 1000 app
USER app
ENTRYPOINT ["fixture-app"]
