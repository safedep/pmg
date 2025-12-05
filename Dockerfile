FROM --platform=$BUILDPLATFORM golang:1.25-bookworm@sha256:5117d68695f57faa6c2b3a49a6f3187ec1f66c75d5b080e4360bfe4c1ada398c AS build
# Original: golang:1.25-bookworm

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN make

FROM debian:11-slim@sha256:e4b93db6aad977a95aa103917f3de8a2b16ead91cf255c3ccdb300c5d20f3015
# Original: debian:11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETPLATFORM

LABEL org.opencontainers.image.source=https://github.com/safedep/pmg
LABEL org.opencontainers.image.description="Package Manager Guard to protect against malicious open source packages"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=build /build/bin/pmg /usr/local/bin/pmg

ENTRYPOINT ["pmg"]
