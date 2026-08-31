# syntax=docker/dockerfile:1
# Multi-stage reproducible build for walden with pinned git binary.
# Builder stage: Go 1.25.3 toolchain on Alpine pinned by multi-arch digest.
FROM golang:1.25.3-alpine@sha256:aee43c3ccbf24fdffb7295693b6e33b21e01baec1b2a55acc351fde345e9ec34 AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/

# Build static binary and pre-receive hook personality, normalizing file timestamps for reproducible layers
RUN mkdir -p /out/usr/local/bin && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o /out/usr/local/bin/walden ./cmd/walden && \
    ln -s walden /out/usr/local/bin/pre-receive && \
    touch -h -d @0 /out/usr/local/bin/walden /out/usr/local/bin/pre-receive /out/usr/local/bin /out/usr/local /out/usr /out

# Runtime stage: minimal Alpine container with git 2.47.2 pinned by multi-arch digest.
FROM alpine/git:2.47.2@sha256:062a01ad7a0eb17cff382bc5e26086b4d710e56dfdfdf001109a49b6d9bd378c

COPY --link --from=builder /out/ /

# walden default configuration
EXPOSE 8470
VOLUME ["/data"]

# walden serve is PID 1
ENTRYPOINT ["walden", "serve"]
