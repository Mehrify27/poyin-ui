#!/usr/bin/env bash
#
# build.sh — build the complete, self-contained vpn-ui binary. Run it, that's it.
#
#   ./build.sh            the full build, exactly as before
#   ./build.sh --help     every switch, with what it skips and what that costs
#
# The Xray core is pinned as a git submodule (third_party/Xray-core, at a fixed
# commit). On every run it syncs that submodule, builds the Xray core from it, and
# fetches the latest geo files — then compiles build/out/vpn-ui-<arch> with everything
# baked in via go:embed. warpcli.sh is committed project source
# (web/service/warpcli.sh) and embedded directly. The static VPN daemon bundle is
# pinned + slow to build, so it is reused when already present.
#
# Every switch has a matching environment variable (SKIP_CORE=1 and friends) and both
# still work: the switches are the documented surface, the env vars are what the older
# plan files and docs use. A switch wins over its env var, and a skip wins over a force.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

usage() {
    cat <<'EOF'
vpn-ui build: compiles build/out/vpn-ui-<arch> with the Xray core, the geo data
files and the static VPN daemon bundle baked in.

Usage: ./build.sh [options]          # no options = the full build

Skip work (iterating on Go code):
  -q, --quick             --skip-submodules + --skip-core: recompile the panel from
                          everything already cached. The usual dev loop.
      --skip-submodules   don't touch third_party/*, build whatever is checked out
      --skip-core         reuse the cached Xray core AND geo files
      --skip-bundle       reuse the VPN daemon bundle even when it looks stale

Force work (picking up new upstream):
      --latest            move the submodules to their tracked branch TIPS and rebuild
                          the core from that. The new pin is left uncommitted; run
                          'git add third_party/<name>' to persist it for everyone else
      --update-submodules hard-sync the submodules back to the RECORDED pins,
                          discarding any local work in them
      --force-core        rebuild the Xray core even when the pin is unchanged
      --force-geo         re-download the geo files, skipping the not-modified check
      --force-bundle      rebuild the static daemon bundle (needs docker, slow)
  -f, --force             all three --force-* above

What lands in the binary:
      --geo-lean          embed ONLY geoip.dat + geosite.dat, dropping the ~118MB of
                          country files; the panel then downloads one the first time
                          a routing rule names it
      --geo-only          refresh the geo files but don't rebuild the core
  -a, --arch GOARCH       target architecture (default: this host's 'go env GOARCH').
                          Static builds cross-compile via Docker; --dynamic cross-
                          builds need a cgo cross compiler in CC
      --static            build a statically linked musl ELF via Docker (default)
      --dynamic           compile with the host toolchain/glibc instead of static musl
      --repo OWNER/NAME   override default GitHub release repo embedded in binary
      --mirror URL        GitHub mirror/proxy prefix for core/geo downloads and builds
      --skip-deps         skip automatic host build-dependency preflight

Other:
  -n, --dry-run           print what each step would do, then stop
      --no-color          plain output (same as NO_COLOR=1)
  -h, --help              this message

Environment (all still honored; the matching switch wins):
  SKIP_SUBMODULES  SKIP_CORE  SUBMODULES_LATEST  SUBMODULES_UPDATE
  CORE_FORCE  GEO_FORCE  GEO_LEAN  GEO_ONLY  REPO  GH_PROXY
  STATIC           1 = static musl ELF via Docker (default), 0 = host dynamic build
  GO_ALPINE_IMAGE  override golang:*-alpine base image used by static builds
  DOCKER_NET       extra 'docker run' flags for the daemon/static Docker builds
                   (e.g. --network=host when the default bridge is firewalled)
  XRAY_SRC         build the core from another local checkout
  XRAY_REPO/REF    fork URL / git ref for the fallback clone
  CC               cgo cross compiler, required by --dynamic -a/--arch off host arch

Examples:
  ./build.sh                       full build (what a release ships)
  ./build.sh --quick               Go-only change: reuse the core and the bundle
  ./build.sh --latest              after pushing new Xray-core commits
  ./build.sh --dry-run             what this run would rebuild, without building it
  ./build.sh --geo-lean            ~118MB smaller binary, geo fetched on demand
EOF
}

# Parsing runs before the logging lib is sourced (--no-color has to land first), so
# errors here are plain. Exit 2 = bad usage, distinct from a failed build.
die() { printf 'build.sh: %s\n' "$*" >&2; exit 2; }

# Seed every knob from the environment, then let the switches overwrite it. This is
# what keeps 'SKIP_SUBMODULES=1 SKIP_CORE=1 ./build.sh' (all over the plan files)
# working unchanged alongside './build.sh --quick'.
SKIP_SUBMODULES="${SKIP_SUBMODULES:-0}"
SKIP_CORE="${SKIP_CORE:-0}"
SUBMODULES_LATEST="${SUBMODULES_LATEST:-0}"
SUBMODULES_UPDATE="${SUBMODULES_UPDATE:-0}"
SKIP_BUNDLE=0
FORCE_BUNDLE=0
DRY_RUN=0
SKIP_DEPS="${SKIP_DEPS:-0}"
STATIC="${STATIC:-1}"
GO_ALPINE_IMAGE="${GO_ALPINE_IMAGE:-}"
ARCH_FLAG=""
REPO_SLUG="${VPNUI_REPO:-${REPO:-Mehrify27/poyin-ui}}"
MIRROR_URL="${VPNUI_GH_PROXY:-${GH_PROXY:-}}"

while (( $# )); do
    case "$1" in
        -h|--help)           usage; exit 0 ;;
        -q|--quick)          SKIP_SUBMODULES=1; SKIP_CORE=1 ;;
        --skip-submodules)   SKIP_SUBMODULES=1 ;;
        --skip-core)         SKIP_CORE=1 ;;
        --skip-bundle)       SKIP_BUNDLE=1 ;;
        --skip-deps)         SKIP_DEPS=1 ;;
        --static)            STATIC=1 ;;
        --dynamic)           STATIC=0 ;;
        --latest)            SUBMODULES_LATEST=1 ;;
        --update-submodules) SUBMODULES_UPDATE=1 ;;
        # The force knobs are read by build/core/build.sh, a separate process, so they
        # have to be exported. A plain shell var would silently not reach it.
        --force-core)        export CORE_FORCE=1 ;;
        --force-geo)         export GEO_FORCE=1 ;;
        --force-bundle)      FORCE_BUNDLE=1 ;;
        -f|--force)          export CORE_FORCE=1 GEO_FORCE=1; FORCE_BUNDLE=1 ;;
        --geo-lean)          export GEO_LEAN=1 ;;
        --geo-only)          export GEO_ONLY=1 ;;
        # Both spellings, matching test_unit/run.sh's flags.
        -a|--arch)           [[ $# -ge 2 ]] || die "-a/--arch needs a GOARCH (amd64, arm64, ...)"; ARCH_FLAG="$2"; shift ;;
        --arch=*)            ARCH_FLAG="${1#*=}"; [[ -n "$ARCH_FLAG" ]] || die "--arch= needs a GOARCH (amd64, arm64, ...)" ;;
        --repo)              [[ $# -ge 2 ]] || die "--repo needs owner/name"; REPO_SLUG="$2"; shift ;;
        --repo=*)            REPO_SLUG="${1#*=}"; [[ -n "$REPO_SLUG" ]] || die "--repo= needs owner/name" ;;
        --mirror)            [[ $# -ge 2 ]] || die "--mirror needs a URL prefix"; MIRROR_URL="$2"; shift ;;
        --mirror=*)          MIRROR_URL="${1#*=}"; [[ -n "$MIRROR_URL" ]] || die "--mirror= needs a URL prefix" ;;
        -n|--dry-run)        DRY_RUN=1 ;;
        --no-color)          export NO_COLOR=1 ;;
        -*)                  die "unknown option '$1'. Run './build.sh --help' for the list." ;;
        *)                   die "unexpected argument '$1', this script takes options only. Run './build.sh --help'." ;;
    esac
    shift
done

if [[ -n "$MIRROR_URL" ]]; then
    export GH_PROXY="$MIRROR_URL"
    export VPNUI_GH_PROXY="$MIRROR_URL"
fi
export REPO="$REPO_SLUG"

read_build_version() {
    local raw=""
    if [[ -s "$REPO_ROOT/VERSION" ]]; then
        raw="$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")"
    elif [[ -s "$REPO_ROOT/config/version" ]]; then
        raw="$(tr -d '[:space:]' < "$REPO_ROOT/config/version")"
    fi
    raw="${raw#v}"
    raw="${raw#V}"
    [[ -n "$raw" ]] || raw="2.0.1"
    printf '%s' "$raw"
}

BUILD_VERSION="$(read_build_version)"
if [[ "${DRY_RUN}" != "1" ]] && [[ -f "$REPO_ROOT/config/version" ]]; then
    if [[ "$(tr -d '[:space:]' < "$REPO_ROOT/config/version")" != "$BUILD_VERSION" ]]; then
        printf '%s\n' "$BUILD_VERSION" > "$REPO_ROOT/config/version"
    fi
fi

ensure_host_deps() {
    [[ "$SKIP_DEPS" == "1" ]] && return 0
    local missing=()
    local cc_bin="${CC:-gcc}"
    command -v git  >/dev/null 2>&1 || missing+=(git)
    command -v curl >/dev/null 2>&1 || missing+=(curl)
    command -v tar  >/dev/null 2>&1 || missing+=(tar)
    if [[ "$ARCH" == "$HOST_ARCH" ]] && ! command -v "$cc_bin" >/dev/null 2>&1; then
        missing+=(gcc)
    fi
    (( ${#missing[@]} == 0 )) && return 0
    if (( DRY_RUN )); then
        info "would install missing host build tool(s): ${missing[*]}"
        return 0
    fi
    if [[ $EUID -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
        warn "missing host build tools (${missing[*]}) and cannot elevate to install them cleanly"
        return 0
    fi
    local sudo_cmd=()
    [[ $EUID -eq 0 ]] || sudo_cmd=(sudo)
    local id="" like=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        id="${ID,,}"
        like="${ID_LIKE,,}"
    fi
    if command -v apt-get >/dev/null 2>&1; then
        info "installing build prerequisites on ${PRETTY_NAME:-Debian/Ubuntu}: build-essential curl git tar ca-certificates"
        DEBIAN_FRONTEND=noninteractive "${sudo_cmd[@]}" apt-get update -qq || true
        DEBIAN_FRONTEND=noninteractive "${sudo_cmd[@]}" apt-get install -y -qq build-essential curl git tar ca-certificates || true
    elif command -v dnf5 >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
        local dnf_bin="dnf"
        command -v dnf >/dev/null 2>&1 || dnf_bin="dnf5"
        info "installing build prerequisites on ${PRETTY_NAME:-Fedora/EL}: gcc make curl git tar ca-certificates"
        "${sudo_cmd[@]}" "$dnf_bin" install -y gcc make curl git tar ca-certificates || true
    elif command -v yum >/dev/null 2>&1; then
        "${sudo_cmd[@]}" yum install -y gcc make curl git tar ca-certificates || true
    elif command -v pacman >/dev/null 2>&1; then
        "${sudo_cmd[@]}" pacman -Sy --needed --noconfirm base-devel curl git tar ca-certificates || true
    elif command -v zypper >/dev/null 2>&1; then
        "${sudo_cmd[@]}" zypper --non-interactive install gcc make curl git tar ca-certificates || true
    elif command -v apk >/dev/null 2>&1; then
        "${sudo_cmd[@]}" apk add --no-cache build-base curl git tar ca-certificates || true
    fi
}

command -v go >/dev/null 2>&1 || die "no 'go' in PATH. The panel, the Xray core and the arch default all need the Go toolchain."
HOST_ARCH="$(go env GOARCH)"
ARCH="${ARCH_FLAG:-$HOST_ARCH}"

docker_platform_for_arch() {
    case "$1" in
        amd64)     printf 'linux/amd64' ;;
        arm64)     printf 'linux/arm64' ;;
        386)       printf 'linux/386' ;;
        arm|armv7) printf 'linux/arm/v7' ;;
        *)         return 1 ;;
    esac
}

DOCKER_PLATFORM=""
if (( STATIC )); then
    DOCKER_PLATFORM="$(docker_platform_for_arch "$ARCH")" || die "static Docker build does not support --arch '$ARCH' (pass --dynamic with CC=... instead)"
    if ! (( DRY_RUN )); then
        command -v docker >/dev/null 2>&1 || die "static build requires 'docker' in PATH (or pass --dynamic for a host glibc build)."
        docker info >/dev/null 2>&1 || die "static build requires a running Docker daemon (or pass --dynamic for a host glibc build)."
    fi
else
    # sqlite needs cgo, so a dynamic build for another GOARCH invokes a C compiler
    # for THAT arch. Without CC set, go reaches for the host gcc and fails deep in
    # linker errors that say nothing about the real cause. Say it here instead.
    if [[ "$ARCH" != "$HOST_ARCH" && -z "${CC:-}" ]]; then
        die "cross-building for '$ARCH' on '$HOST_ARCH' needs a cgo cross compiler, e.g.: CC=aarch64-linux-gnu-gcc ./build.sh --dynamic --arch $ARCH"
    fi
fi

# Colored logging (step/ok/info/warn/err). Falls back to plain echo if the shared
# lib is ever missing, so the build never breaks on it.
# shellcheck source=build/lib/log.sh
source "$REPO_ROOT/build/lib/log.sh" 2>/dev/null || { step(){ echo "==> $*"; }; ok(){ echo "  - $*"; }; info(){ echo "  $*"; }; warn(){ echo "  ! $*" >&2; }; err(){ echo "  x $*" >&2; }; hr(){ :; }; }

# A skip beats a force, because the forced step is the one that doesn't run at all.
# Combining them is never what someone meant, and the loser would otherwise be a
# silent no-op, the exact failure mode that makes a flag-heavy script untrustworthy.
if (( SKIP_SUBMODULES )) && (( SUBMODULES_LATEST || SUBMODULES_UPDATE )); then
    warn "--skip-submodules wins: the submodule step doesn't run, so --latest/--update-submodules do nothing"
fi
if (( SKIP_CORE )) && [[ "${CORE_FORCE:-0}" == "1" || "${GEO_FORCE:-0}" == "1" || "${GEO_ONLY:-0}" == "1" ]]; then
    warn "--skip-core wins: the core step doesn't run, so --force-core/--force-geo/--geo-only do nothing"
fi
if (( SKIP_BUNDLE && FORCE_BUNDLE )); then
    warn "--skip-bundle wins over --force-bundle: the daemon bundle is left as it is"
    # Drop it rather than just ignore it: --force-bundle marks the bundle stale, and
    # the skip path would then report a perfectly good bundle as stale.
    FORCE_BUNDLE=0
fi

# --dry-run executes nothing: each step reports the decision it WOULD take and the
# run stops before the compile. Every staleness check below is read-only, so the plan
# printed here is the plan a real run follows.
do_run() {
    if (( DRY_RUN )); then info "would run: $*"; return 0; fi
    "$@"
}

hr
step "vpn-ui build ${_CD:-}(v${BUILD_VERSION}, ${ARCH}, repo=${REPO_SLUG})${_CR:-}"
hr
if (( DRY_RUN )); then info "dry run: nothing is fetched, built or written"; fi
ensure_host_deps

# 0. Pinned upstream (third_party/Xray-core). Clone it
#    ONCE, then reuse. `git submodule status` prefixes a line with '-' when a
#    submodule is uninitialised and '+' when checked out at a different commit
#    than recorded; a leading space means it already matches the pin and there's
#    nothing to fetch. So we only sync when something actually needs it — repeat
#    builds don't re-clone/re-fetch. Use --update-submodules to force a sync
#    (e.g. after bumping a pin), or --skip-submodules to skip entirely.
if [[ "$SKIP_SUBMODULES" != "1" && -f .gitmodules ]]; then
    if [[ "$SUBMODULES_LATEST" == "1" ]]; then
        # --remote fetches each submodule's tracked branch (branch= in .gitmodules)
        # and moves the working tree to its tip — this is how new upstream commits
        # (e.g. a freshly-pushed Xray-core) actually get pulled in. The core rebuild
        # in step 1 then triggers automatically because the .xray.commit marker no
        # longer matches the new HEAD. The parent's recorded pin is left dirty on
        # purpose; commit third_party/* yourself to persist the bump.
        step "pulling LATEST upstream submodule commits (--latest)"
        do_run git submodule update --init --remote --recursive
        info "submodules moved to branch tips — 'git add third_party/*' + commit to persist the new pin"
    elif [[ "$SUBMODULES_UPDATE" == "1" ]]; then
        step "syncing pinned submodules (--update-submodules)"
        do_run git submodule update --init --recursive
    # Capture ONCE into a variable and match with a here-string. Piping into `grep -q`
    # is broken under this script's `set -o pipefail`: grep exits at the first match,
    # git gets SIGPIPE, and the pipeline reports 141 even though the pattern matched,
    # so the check silently evaluated FALSE and this whole block never ran.
    elif sub_status="$(git submodule status --recursive 2>/dev/null || true)"; grep -q '^-' <<<"$sub_status"; then
        # '-' means NOT INITIALISED (fresh clone): there is nothing local to lose, so
        # checking it out at the recorded pin is always safe.
        step "initialising submodules"
        do_run git submodule update --init --recursive
    elif grep -q '^+' <<<"$sub_status"; then
        # '+' means the submodule sits at a DIFFERENT commit than the parent's recorded
        # pin — i.e. someone has local work there (a patch to the Xray-core or telemt
        # fork). `git submodule update` would hard-reset it back to the pin and the build
        # would silently produce a binary WITHOUT that patch, which is exactly how the
        # telemt patches were lost once before. Never rewind implicitly: build what is
        # checked out and say so. Use --update-submodules to force the reset on purpose.
        warn "submodule(s) AHEAD of the recorded pin — building what is checked out, NOT rewinding:"
        grep '^+' <<<"$sub_status" | sed 's/^/    /' || true
        warn "commit the gitlink (git add third_party/<name>) to persist this, or --update-submodules to discard it"
    else
        ok "submodules already at pinned commits — skipping clone/sync"
    fi
else
    ok "submodules: skipped, building whatever is checked out"
fi

# 1. Xray core (built from the pinned third_party/Xray-core submodule) + latest geo.
if [[ "$SKIP_CORE" != "1" ]]; then
    step "Xray core (third_party/Xray-core) + geo files"
    do_run bash build/core/build.sh "$ARCH"
else
    ok "Xray core + geo files: reusing the cached copies"
fi

# 2. Static VPN daemon bundle (built in Docker/Alpine — pinned + slow, so cached).
#    The cache is keyed on the artifacts themselves: every bundle added since the
#    original build is named here, so a checkout that predates one still picks it
#    up instead of quietly shipping a binary that is missing a whole protocol.
#    Each entry is either a .tgz relocatable tree or a flat binary, by its own name.
BUNDLE_ARTIFACTS=(
    libreswan-bundle.tgz     # IPsec, ALL_ALGS / MODP1024
    accel-ppp-bundle.tgz     # SSTP server
    strongswan-bundle.tgz    # IKEv2
    telemt                   # MTProto Proxy
    sing-box                 # Hysteria 2 server/client
    pptp                     # PPTP client
    openconnect              # OpenConnect client
    vpnc-script              # its routing/DNS hook
    sstpc-bundle.tgz         # SSTP client (a tree: sstpc needs a dlopen'd OpenSSL provider)
    sstp-pppd-plugin.so      # and the pppd plugin it cannot handshake without
)
bundle_stale=0
if (( FORCE_BUNDLE )); then
    bundle_stale=1
elif ! compgen -G "backend/bin/$ARCH/*" > /dev/null 2>&1; then
    bundle_stale=1
else
    for a in "${BUNDLE_ARTIFACTS[@]}"; do
        [[ -f "backend/bin/$ARCH/$a" ]] || { bundle_stale=1; info "bundle artifact missing: $a"; }
    done
    # Presence is not enough for openvpn: a bundle built before compression was
    # turned on has the file but cannot dial a server that insists on comp-lzo,
    # and an existence-only check would keep that binary forever. --version exits
    # non-zero by design, hence the `|| true`.
    if [[ -x "backend/bin/$ARCH/openvpn" && "$ARCH" == "$HOST_ARCH" ]]; then
        ovpn_ver="$("backend/bin/$ARCH/openvpn" --version 2>&1 || true)"
        for feat in "[LZO]" "[LZ4]"; do
            if [[ "$ovpn_ver" != *"$feat"* ]]; then
                bundle_stale=1
                info "bundled openvpn was built without $feat"
            fi
        done
    fi
fi
if (( SKIP_BUNDLE )); then
    # Worth a warning, not a quiet skip: the bundle is what carries whole protocols,
    # and a binary built past a stale one is missing a daemon with nothing at runtime
    # to say so.
    if (( bundle_stale )); then
        warn "--skip-bundle: the daemon bundle is stale or incomplete, so this binary may be MISSING a protocol"
    else
        ok "VPN daemon bundle already present, skipping"
    fi
elif (( bundle_stale )); then
    step "VPN daemon bundle"
    if (( FORCE_BUNDLE )); then info "--force-bundle: rebuilding regardless of the cache"; fi
    do_run bash build/backend/build.sh "$ARCH"
else
    ok "VPN daemon bundle already present, skipping"
fi

# 3. Panel binary (cgo required for sqlite). Output goes to build/out/.
OUT_DIR="$REPO_ROOT/build/out"
OUT_BIN="$OUT_DIR/vpn-ui-$ARCH"
OUT_TGZ="$OUT_DIR/vpn-ui-${BUILD_VERSION}-linux-${ARCH}.tar.gz"
OUT_TGZ_LATEST="$OUT_DIR/vpn-ui-linux-${ARCH}.tar.gz"
LDFLAGS="-s -w -X github.com/mhsanaei/3x-ui/v2/config.ldVersion=${BUILD_VERSION} -X github.com/mhsanaei/3x-ui/v2/config.ldRepo=${REPO_SLUG}"
if [[ -n "$MIRROR_URL" ]]; then
    LDFLAGS+=" -X github.com/mhsanaei/3x-ui/v2/config.ldGHProxy=${MIRROR_URL}"
fi

STATIC_BUILD_TAGS="osusergo,netgo,sqlite_omit_load_extension"
STATIC_LDFLAGS="${LDFLAGS} -linkmode external -extldflags '-static'"
STATIC_BUILDER_IMG=""

prepare_static_builder() {
    local arch="$1" platform="$2"
    local host_ver mod_ver mm base_img safe_tag builder_img build_ctx
    local -a candidates=()

    host_ver="$(go env GOVERSION 2>/dev/null || go version | awk '{print $3}')"
    host_ver="${host_ver#go}"
    mod_ver="$(awk '/^go[ \t]+/{print $2; exit}' "$REPO_ROOT/go.mod" 2>/dev/null || true)"
    mm="$(printf '%s' "${host_ver:-$mod_ver}" | grep -oE '^[0-9]+\.[0-9]+' || echo "1.27")"

    if [[ -n "$GO_ALPINE_IMAGE" ]]; then
        candidates=("$GO_ALPINE_IMAGE")
    else
        [[ "$host_ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && candidates+=("golang:${host_ver}-alpine")
        candidates+=("golang:${mm}-alpine")
    fi

    build_ctx="$(mktemp -d)"
    for base_img in "${candidates[@]}"; do
        safe_tag="${base_img//[:\/]/_}"
        builder_img="vpn-ui-go-builder:${safe_tag}-${arch}"
        if docker image inspect "$builder_img" >/dev/null 2>&1; then
            rm -rf "$build_ctx"
            STATIC_BUILDER_IMG="$builder_img"
            return 0
        fi
        info "preparing static Go builder: $builder_img (base: $base_img, $platform)"
        if docker build ${DOCKER_NET:-} --platform "$platform" -t "$builder_img" -f - "$build_ctx" <<EOF
FROM ${base_img}
RUN apk add --no-cache gcc musl-dev file
EOF
        then
            rm -rf "$build_ctx"
            STATIC_BUILDER_IMG="$builder_img"
            return 0
        fi
        warn "failed to prepare builder from $base_img, trying next fallback if any"
    done
    rm -rf "$build_ctx"
    err "could not prepare Alpine Go builder image for $platform"
    exit 1
}

build_panel_static() {
    local host_modcache goproxy gosumdb goprivate gonosumdb
    local -a docker_user_args=()
    prepare_static_builder "$ARCH" "$DOCKER_PLATFORM"

    host_modcache="$(go env GOMODCACHE)"
    mkdir -p "$host_modcache"
    info "ensuring Go module cache on host: $host_modcache"
    go mod download

    # Map UID/GID for standard rootful Docker so output files stay owned by the
    # calling user; under rootless Docker UID 0 in-container already maps to host UID.
    if ! docker info -f '{{json .SecurityOptions}}' 2>/dev/null | grep -q 'name=rootless'; then
        docker_user_args=(--user "$(id -u):$(id -g)")
    fi

    goproxy="$(go env GOPROXY 2>/dev/null || true)"
    gosumdb="$(go env GOSUMDB 2>/dev/null || true)"
    goprivate="$(go env GOPRIVATE 2>/dev/null || true)"
    gonosumdb="$(go env GONOSUMDB 2>/dev/null || true)"

    local -a docker_env_args=(
        -e HOME=/tmp
        -e GOCACHE=/tmp/gocache
        -e GOMODCACHE=/go/pkg/mod
        -e GOPATH=/tmp/gopath
        -e CGO_ENABLED=1
        -e "CGO_CFLAGS=${CGO_CFLAGS:--g -O2 -Wno-discarded-qualifiers}"
        -e GOOS=linux
        -e "GOARCH=${ARCH}"
    )
    [[ -n "$goproxy" ]]   && docker_env_args+=(-e "GOPROXY=${goproxy}")
    [[ -n "$gosumdb" ]]   && docker_env_args+=(-e "GOSUMDB=${gosumdb}")
    [[ -n "$goprivate" ]] && docker_env_args+=(-e "GOPRIVATE=${goprivate}")
    [[ -n "$gonosumdb" ]] && docker_env_args+=(-e "GONOSUMDB=${gonosumdb}")

    docker run --rm ${DOCKER_NET:-} \
        --platform "$DOCKER_PLATFORM" \
        ${docker_user_args[@]+"${docker_user_args[@]}"} \
        "${docker_env_args[@]}" \
        -v "$host_modcache:/go/pkg/mod" \
        -v "$REPO_ROOT:/src" \
        -w /src \
        "$STATIC_BUILDER_IMG" \
        go build -trimpath -buildvcs=false -tags "$STATIC_BUILD_TAGS" -ldflags "$STATIC_LDFLAGS" -o "build/out/vpn-ui-${ARCH}" main.go

    local file_desc=""
    if command -v file >/dev/null 2>&1; then
        file_desc="$(file -b "$OUT_BIN" 2>/dev/null || true)"
    fi
    if [[ -z "$file_desc" ]]; then
        file_desc="$(docker run --rm --platform "$DOCKER_PLATFORM" ${docker_user_args[@]+"${docker_user_args[@]}"} -v "$OUT_DIR:/out:ro" "$STATIC_BUILDER_IMG" file -b "/out/vpn-ui-${ARCH}" 2>/dev/null || true)"
    fi
    if ! printf '%s' "$file_desc" | grep -qiE 'statically linked|static-pie linked'; then
        err "expected a statically linked ELF binary for $OUT_BIN, got: ${file_desc:-unknown}"
        exit 1
    fi
    ok "verified static ELF: ${file_desc}"
}

step "compiling vpn-ui v${BUILD_VERSION}$( (( STATIC )) && printf ' [static/musl]' || printf ' [dynamic/host]' )"
if (( DRY_RUN )); then
    if (( STATIC )); then
        info "would run (Docker $DOCKER_PLATFORM musl): go build -trimpath -buildvcs=false -tags \"$STATIC_BUILD_TAGS\" -ldflags \"$STATIC_LDFLAGS\" -o build/out/vpn-ui-$ARCH main.go"
    else
        info "would run: CGO_ENABLED=1 GOARCH=$ARCH go build -ldflags \"$LDFLAGS\" -o build/out/vpn-ui-$ARCH main.go"
    fi
    info "would package offline bundle: $OUT_TGZ (+ SHA256SUMS + deploy.sh + vpn-ui.sh + VERSION)"
    hr
    ok "dry run: nothing was built"
    hr
    exit 0
fi
mkdir -p "$OUT_DIR"
if (( STATIC )); then
    build_panel_static
else
    CGO_ENABLED=1 GOARCH="$ARCH" go build -ldflags "$LDFLAGS" -o "$OUT_BIN" main.go
fi

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        openssl dgst -sha256 -r "$1" | awk '{print $1}'
    fi
}

step "packaging offline release bundle & checksums"
bin_sum="$(sha256_of "$OUT_BIN")"
printf '%s  %s\n' "$bin_sum" "vpn-ui-${ARCH}" > "$OUT_BIN.sha256"

bundle_stage="$(mktemp -d)"
trap 'rm -rf "$bundle_stage"' EXIT
cp "$OUT_BIN" "$bundle_stage/vpn-ui-${ARCH}"
chmod 0755 "$bundle_stage/vpn-ui-${ARCH}"
cp "$REPO_ROOT/deploy.sh" "$bundle_stage/deploy.sh"
chmod 0755 "$bundle_stage/deploy.sh"
cp "$REPO_ROOT/vpn-ui.sh" "$bundle_stage/vpn-ui.sh"
chmod 0755 "$bundle_stage/vpn-ui.sh"
printf '%s\n' "$BUILD_VERSION" > "$bundle_stage/VERSION"
(
    cd "$bundle_stage"
    for f in "vpn-ui-${ARCH}" "deploy.sh" "vpn-ui.sh" "VERSION"; do
        printf '%s  %s\n' "$(sha256_of "$f")" "$f"
    done > SHA256SUMS
    tar -czf "$OUT_TGZ" "vpn-ui-${ARCH}" "deploy.sh" "vpn-ui.sh" "VERSION" "SHA256SUMS"
)
rm -rf "$bundle_stage"
trap - EXIT

cp -f "$OUT_TGZ" "$OUT_TGZ_LATEST"
printf '%s  %s\n' "$(sha256_of "$OUT_TGZ")" "$(basename "$OUT_TGZ")" > "${OUT_TGZ}.sha256"
printf '%s  %s\n' "$(sha256_of "$OUT_TGZ_LATEST")" "$(basename "$OUT_TGZ_LATEST")" > "${OUT_TGZ_LATEST}.sha256"

hr
ok "done: ${_CB:-}$(ls -lh "$OUT_BIN" | awk '{print $5}')${_CR:-} -> ${_CB:-}build/out/vpn-ui-${ARCH}${_CR:-}"
ok "bundle: ${_CB:-}build/out/$(basename "$OUT_TGZ")${_CR:-} (offline/air-gapped ready)"
info "run it:  ./build/out/vpn-ui-${ARCH}"
hr
