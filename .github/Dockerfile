# =============================================================================
#  Test Container for Vaious Go Versions (Last Updated: 2026-03-23)
# =============================================================================
# Default version: minimum supported go version
ARG VARIANT="1.25-alpine"

# -----------------------------------------------------------------------------
#  Main Stage
# -----------------------------------------------------------------------------
FROM golang:${VARIANT}

RUN apk add --no-cache \
    git \
    alpine-sdk \
    build-base

WORKDIR /workspaces

ENTRYPOINT go mod download && go test -race ./...
