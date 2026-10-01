#!/usr/bin/env bash
# What CI gates on (ci.yml), so a local pass and a green pull request mean
# the same thing. gofmt -l lists unformatted files but exits zero, hence the
# test -z.
set -euo pipefail
cd "$(dirname "$0")/.."

go build ./...
go vet ./...
test -z "$(gofmt -l .)"
go test -race ./...
