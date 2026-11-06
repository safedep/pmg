FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
# Original: golang:1.27.3-bookworm

WORKDIR /build

COPY go.mod go.sum ./

# PMG in CI decrypts proxy.golang.org, so ci.yml passes the PMG CA bundle as
# the secret pmg-ca. The bundle also holds the public roots. A build without
# the secret, such as the release build, uses the roots of the image. The make
# step also gets the secret, because go.work can make it fetch modules.
RUN --mount=type=secret,id=pmg-ca,target=/run/secrets/pmg-ca.pem,mode=0444 \
    if [ -f /run/secrets/pmg-ca.pem ]; then export SSL_CERT_FILE=/run/secrets/pmg-ca.pem; fi; \
    go mod download

COPY . .

ARG TARGETOS TARGETARCH

RUN --mount=type=secret,id=pmg-ca,target=/run/secrets/pmg-ca.pem,mode=0444 \
    if [ -f /run/secrets/pmg-ca.pem ]; then export SSL_CERT_FILE=/run/secrets/pmg-ca.pem; fi; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make

FROM debian:13-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
# Original: debian:13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETPLATFORM

LABEL org.opencontainers.image.source=https://github.com/safedep/pmg
LABEL org.opencontainers.image.description="Package Manager Guard to protect against malicious open source packages"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=build /build/bin/pmg /usr/local/bin/pmg

ENTRYPOINT ["pmg"]
