#!/bin/sh
# Builds a static sing-box binary inside golang:alpine into /out/sing-box.
# Runs with ARCH=amd64|arm64 (or GO_ARCH) and optional SING_BOX_VERSION (pinned tag).
set -eu

GOARCH_TARGET="${GO_ARCH:-${ARCH:-amd64}}"
case "$GOARCH_TARGET" in
    x86_64) GOARCH_TARGET=amd64 ;;
    aarch64) GOARCH_TARGET=arm64 ;;
esac

SING_BOX_VERSION="${SING_BOX_VERSION:-v1.14.4}"
SING_BOX_REPO="${SING_BOX_REPO:-https://github.com/SagerNet/sing-box.git}"
SING_BOX_TAGS="${SING_BOX_TAGS:-with_quic,with_utls,with_gvisor,with_clash_api,with_v2ray_api}"

apk add --no-cache git >/dev/null 2>&1 || true

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone --depth 1 --branch "$SING_BOX_VERSION" "$SING_BOX_REPO" "$WORK/src"

cd "$WORK/src"
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH_TARGET" \
    go build -v -trimpath -tags "$SING_BOX_TAGS" \
    -ldflags="-X github.com/sagernet/sing-box/constant.Version=${SING_BOX_VERSION#v} -s -w -buildid=" \
    -o /out/sing-box ./cmd/sing-box
chmod 0755 /out/sing-box
