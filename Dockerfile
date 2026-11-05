FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS build
# Original: golang:1.27.3-bookworm

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} make

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
