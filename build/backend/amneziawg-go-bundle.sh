#!/bin/sh
# Builds a static amneziawg-go binary inside golang:alpine into /out/amneziawg-go.
# Runs with ARCH=amd64|arm64 (or GO_ARCH) and optional AWG_GO_VERSION (pinned tag/branch).
set -eu

GOARCH_TARGET="${GO_ARCH:-${ARCH:-amd64}}"
case "$GOARCH_TARGET" in
    x86_64) GOARCH_TARGET=amd64 ;;
    aarch64) GOARCH_TARGET=arm64 ;;
esac

AWG_GO_VERSION="${AWG_GO_VERSION:-v3.1.20261116}"
AWG_GO_REPO="${AWG_GO_REPO:-https://github.com/amnezia-vpn/amneziawg-go.git}"

apk add --no-cache git >/dev/null 2>&1 || true

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if git clone --depth 1 --branch "$AWG_GO_VERSION" "$AWG_GO_REPO" "$WORK/src"; then
    :
else
    git clone --depth 1 "$AWG_GO_REPO" "$WORK/src"
fi

cd "$WORK/src"
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH_TARGET" \
    go build -trimpath -ldflags="-X main.Version=${AWG_GO_VERSION#v} -s -w" -o /out/amneziawg-go .
chmod 0755 /out/amneziawg-go
