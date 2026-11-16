#!/usr/bin/env bash
# MmD / poyin-ui
set -euo pipefail

REPO="${VPNUI_REPO:-${REPO:-Mehrify27/poyin-ui}}"
GH_PROXY_PREFIX="${VPNUI_GH_PROXY:-${GH_PROXY:-}}"
LOCAL_ASSET="${LOCAL_ASSET:-}"
OFFLINE="${OFFLINE:-0}"
FORCE_UPDATE="${FORCE_UPDATE:-0}"
SKIP_DEPS="${SKIP_DEPS:-0}"
ARCH_OVERRIDE="${ARCH:-}"

DEST_DIR="/opt/vpn-ui"
# The DEFAULT systemd unit name, and ONLY a fallback. The operator can rename the
# service from the panel (settings key systemdServiceName), and `$DEST --systemd`
# below installs the unit under THAT name — so a literal pinned here would have this
# script configure one unit and then restart another. Every systemctl call goes
# through unit_name() instead; this is what it answers with when there is no binary
# to ask yet.
UNIT_FALLBACK="vpn-ui"
# The management menu (`vpn-ui`). Installed from INSIDE the binary we just placed
# ($DEST install-menu), never curled from the repo's default branch: that would pin
# a menu from a different release than the binary it drives.
MENU="/usr/bin/vpn-ui"
DB="$DEST_DIR/vpn-ui.db"
BACKUP_DIR="$DEST_DIR/backups"
# Real-SSL (Let's Encrypt via acme.sh: Cloudflare DNS-01 or standalone HTTP-01).
CERT_DIR="$DEST_DIR/cert"
DOMAIN="${DEPLOY_DOMAIN:-}"
EMAIL="${DEPLOY_EMAIL:-}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
    BLUE=$'\e[38;5;39m'; GREEN=$'\e[38;5;114m'; RED=$'\e[38;5;203m'
    YELLOW=$'\e[38;5;221m'; TEAL=$'\e[38;5;44m'; WHITE=$'\e[1;38;5;255m'
else
    B= D= R= BLUE= GREEN= RED= YELLOW= TEAL= WHITE=
fi

# ":: text"  bold-blue header + bold-white message (pacman's step style)
msg()  { printf '%s::%s %s%s%s\n' "$B$BLUE" "$R" "$WHITE" "$*" "$R"; }
# "  -> text"  blue action arrow
act()  { printf '  %s->%s %s\n' "$BLUE" "$R" "$*"; }
ok()   { printf '  %s->%s %s%s%s\n' "$GREEN" "$R" "$GREEN" "$*" "$R"; }
warn() { printf '%swarning:%s %s\n' "$B$YELLOW" "$R" "$*" >&2; }
die()  { printf '%serror:%s %s\n'   "$B$RED" "$R" "$*" >&2; exit 1; }
hr()   { printf '%s%s%s\n' "$D" "$(printf '%.0s-' {1..60})" "$R"; }

usage() {
    cat <<'EOF'
vpn-ui installer / in-place upgrader

Usage:
  ./deploy.sh [options]

Options:
  --local <path>       Install or upgrade from a local vpn-ui binary or
                       .tar.gz release bundle (air-gapped / restricted networks)
  --offline            Never contact GitHub or distro repos; auto-detect a
                       compatible binary or .tar.gz bundle next to deploy.sh
  --mirror <url>       GitHub mirror/proxy prefix (e.g. https://ghproxy.example.com/)
  --repo <owner/name>  Override GitHub release repository (default: Mehrify27/poyin-ui)
  --arch <amd64|arm64> Override host architecture detection
  --force, --reinstall Allow reinstalling same version or forced downgrade
  --skip-deps          Skip automatic host runtime package checks/installs
  -h, --help           Show this help message

Environment variables:
  LOCAL_ASSET, OFFLINE=1, GH_PROXY, VPNUI_GH_PROXY, REPO, VPNUI_REPO,
  FORCE_UPDATE=1, SKIP_DEPS=1, IMPORT_DB=<path>, PANEL_TLS=http|selfsign|letsencrypt,
  DEPLOY_DOMAIN, DEPLOY_EMAIL, DEPLOY_CF_TOKEN, DEPLOY_WILDCARD=1

Examples (including offline / Iran servers):
  ./deploy.sh --local ./vpn-ui-2.0.0-linux-amd64.tar.gz
  ./deploy.sh --mirror https://mirror.example.com/
  ./deploy.sh --offline
EOF
}

ORIG_ARGS=("$@")
while (( $# )); do
    case "$1" in
        -h|--help)         usage; exit 0 ;;
        --local)           [[ $# -ge 2 ]] || die "--local requires a path"; LOCAL_ASSET="$2"; shift ;;
        --local=*)         LOCAL_ASSET="${1#*=}"; [[ -n "$LOCAL_ASSET" ]] || die "--local= requires a path" ;;
        --offline)         OFFLINE=1 ;;
        --mirror)          [[ $# -ge 2 ]] || die "--mirror requires a URL"; GH_PROXY_PREFIX="$2"; shift ;;
        --mirror=*)        GH_PROXY_PREFIX="${1#*=}"; [[ -n "$GH_PROXY_PREFIX" ]] || die "--mirror= requires a URL" ;;
        --repo)            [[ $# -ge 2 ]] || die "--repo requires owner/name"; REPO="$2"; shift ;;
        --repo=*)          REPO="${1#*=}"; [[ -n "$REPO" ]] || die "--repo= requires owner/name" ;;
        --arch)            [[ $# -ge 2 ]] || die "--arch requires amd64 or arm64"; ARCH_OVERRIDE="$2"; shift ;;
        --arch=*)          ARCH_OVERRIDE="${1#*=}"; [[ -n "$ARCH_OVERRIDE" ]] || die "--arch= requires amd64 or arm64" ;;
        --force|--reinstall) FORCE_UPDATE=1 ;;
        --skip-deps)       SKIP_DEPS=1 ;;
        --)                shift; break ;;
        *)                 die "unknown option '$1'. Run './deploy.sh --help' for usage." ;;
    esac
    shift
done

export REPO
export VPNUI_REPO="$REPO"
if [[ -n "$GH_PROXY_PREFIX" ]]; then
    export GH_PROXY="$GH_PROXY_PREFIX"
    export VPNUI_GH_PROXY="$GH_PROXY_PREFIX"
fi

# Capture script directory safely (also works when deploy.sh is piped from curl).
SCRIPT_SELF="${BASH_SOURCE[0]:-}"
if [[ -n "$SCRIPT_SELF" && -f "$SCRIPT_SELF" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_SELF")" && pwd)"
else
    SCRIPT_DIR="$PWD"
fi

apply_gh_proxy() {
    local url="$1"
    [[ -n "$GH_PROXY_PREFIX" ]] || { printf '%s' "$url"; return 0; }
    local p="$GH_PROXY_PREFIX"
    [[ "$p" == */ ]] || p="${p}/"
    if [[ "$url" == "$p"* ]]; then
        printf '%s' "$url"
    elif [[ "$url" == https://github.com/* || "$url" == https://api.github.com/* || "$url" == https://raw.githubusercontent.com/* ]]; then
        printf '%s%s' "$p" "$url"
    else
        printf '%s' "$url"
    fi
}

# Pure-bash SemVer 2.0.0 comparator: prints 1 (a > b), 0 (a == b), -1 (a < b).
semver_cmp() {
    local a="$1" b="$2"
    a="${a#v}"; a="${a#V}"; a="${a%%+*}"
    b="${b#v}"; b="${b#V}"; b="${b%%+*}"
    local acore="$a" apre="" bcore="$b" bpre=""
    if [[ "$a" == *-* ]]; then acore="${a%%-*}"; apre="${a#*-}"; fi
    if [[ "$b" == *-* ]]; then bcore="${b%%-*}"; bpre="${b#*-}"; fi

    local amaj=0 amin=0 apatch=0 bmaj=0 bmin=0 bpatch=0
    local IFS='.'
    read -r amaj amin apatch _ <<< "$acore"
    read -r bmaj bmin bpatch _ <<< "$bcore"
    unset IFS
    [[ "$amaj" =~ ^[0-9]+$ ]] || amaj=0
    [[ "$amin" =~ ^[0-9]+$ ]] || amin=0
    [[ "$apatch" =~ ^[0-9]+$ ]] || apatch=0
    [[ "$bmaj" =~ ^[0-9]+$ ]] || bmaj=0
    [[ "$bmin" =~ ^[0-9]+$ ]] || bmin=0
    [[ "$bpatch" =~ ^[0-9]+$ ]] || bpatch=0

    if (( 10#$amaj != 10#$bmaj )); then
        (( 10#$amaj > 10#$bmaj )) && echo 1 || echo -1; return 0
    fi
    if (( 10#$amin != 10#$bmin )); then
        (( 10#$amin > 10#$bmin )) && echo 1 || echo -1; return 0
    fi
    if (( 10#$apatch != 10#$bpatch )); then
        (( 10#$apatch > 10#$bpatch )) && echo 1 || echo -1; return 0
    fi

    if [[ -z "$apre" && -z "$bpre" ]]; then echo 0; return 0; fi
    if [[ -z "$apre" ]]; then echo 1; return 0; fi
    if [[ -z "$bpre" ]]; then echo -1; return 0; fi

    local -a ap bp
    IFS='.' read -ra ap <<< "$apre"
    IFS='.' read -ra bp <<< "$bpre"
    local i max=${#ap[@]}
    (( ${#bp[@]} > max )) && max=${#bp[@]}
    for (( i=0; i<max; i++ )); do
        if (( i >= ${#ap[@]} )); then echo -1; return 0; fi
        if (( i >= ${#bp[@]} )); then echo 1; return 0; fi
        local x="${ap[$i]}" y="${bp[$i]}"
        if [[ "$x" == "$y" ]]; then continue; fi
        if [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]]; then
            (( 10#$x > 10#$y )) && echo 1 || echo -1; return 0
        elif [[ "$x" =~ ^[0-9]+$ ]]; then
            echo -1; return 0
        elif [[ "$y" =~ ^[0-9]+$ ]]; then
            echo 1; return 0
        elif [[ "$x" < "$y" ]]; then
            echo -1; return 0
        else
            echo 1; return 0
        fi
    done
    echo 0
}

# Byte counts the way a human reads them (one decimal from KB up).
fmt_bytes() {
    local b="$1" div unit
    if   (( b >= 1073741824 )); then div=1073741824; unit=GB
    elif (( b >= 1048576    )); then div=1048576;    unit=MB
    elif (( b >= 1024       )); then div=1024;       unit=KB
    else printf '%d B' "$b"; return 0
    fi
    printf '%d.%d %s' "$(( b / div ))" "$(( b * 10 / div % 10 ))" "$unit"
}

# Compact durations for the ETA and the elapsed time: "45s", "2m07s".
fmt_time() {
    local s="$1"
    if (( s >= 60 )); then printf '%dm%02ds' "$(( s / 60 ))" "$(( s % 60 ))"
    else printf '%ds' "$s"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -r "$1" | awk '{print $1}'
    else
        printf ''
    fi
}

verify_sha256_against_manifest() {
    local file="$1" manifest="$2" target_name="${3:-$(basename "$1")}"
    [[ -f "$manifest" ]] || return 0
    local want got
    want="$(awk -v tgt="$target_name" '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        {
            f=$2; sub(/^\*/, "", f); n=split(f, a, "/"); base=a[n];
            if (base == tgt || NF == 1) { print tolower($1); exit }
        }' "$manifest")"
    [[ -n "$want" ]] || return 0
    got="$(sha256_of "$file" | tr '[:upper:]' '[:lower:]')"
    if [[ -z "$got" ]]; then
        warn "no sha256sum/shasum/openssl found to verify checksum against $manifest"
        return 0
    fi
    if [[ "$got" != "$want" ]]; then
        die "SHA-256 verification failed for ${target_name}: got ${got}, want ${want}"
    fi
    ok "verified SHA-256 (${want:0:12}...)"
}

# Acquire root: re-exec through sudo when not already root, preserving flags.
if [[ $EUID -ne 0 ]]; then
    if [[ -f "$0" ]] && command -v sudo >/dev/null 2>&1; then
        exec sudo -- bash "$0" "${ORIG_ARGS[@]}"
    fi
    die "must run as root — use: sudo $0 ${ORIG_ARGS[*]:-}"
fi

# Resolve target architecture cleanly.
host_raw_arch="$(uname -m)"
if [[ -n "$ARCH_OVERRIDE" ]]; then
    case "$ARCH_OVERRIDE" in
        amd64|x86_64)  ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *) die "unsupported --arch '$ARCH_OVERRIDE' (use amd64 or arm64)" ;;
    esac
else
    case "$host_raw_arch" in
        x86_64|amd64)  ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            warn "host architecture is '$host_raw_arch' — defaulting to amd64 binary"
            ARCH="amd64"
            ;;
    esac
fi

ASSET="vpn-ui-${ARCH}"
DEST="$DEST_DIR/$ASSET"
DL_URL="$(apply_gh_proxy "https://github.com/$REPO/releases/latest/download/$ASSET")"

# Preflight
hr
printf '%s[%sVPN-UI%s]%s deploy (%s, %s)\n' "$B$TEAL" "$GREEN" "$TEAL" "$R" "$ARCH" "$REPO"
hr

command -v systemctl >/dev/null 2>&1 || die "systemctl not found — this host isn't running systemd."

ensure_runtime_deps() {
    [[ "$OFFLINE" == "1" || "$SKIP_DEPS" == "1" ]] && return 0

    local os_id="" os_ver="" os_pretty=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        os_id="${ID:-}"
        os_ver="${VERSION_ID:-}"
        os_pretty="${PRETTY_NAME:-$os_id $os_ver}"
    fi

    local need_cmds=()
    command -v tar >/dev/null 2>&1 || need_cmds+=(tar)
    command -v ip >/dev/null 2>&1 || need_cmds+=(ip)
    command -v sqlite3 >/dev/null 2>&1 || need_cmds+=(sqlite3)
    if [[ -z "$LOCAL_ASSET" ]] && ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        need_cmds+=(curl)
    fi

    (( ${#need_cmds[@]} == 0 )) && return 0

    msg "Ensuring runtime tools (${need_cmds[*]}) on ${os_pretty:-Linux}"
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq || warn "apt-get update failed (continuing best-effort)"
        local pkgs=(ca-certificates tar iproute2 sqlite3 nftables)
        command -v curl >/dev/null 2>&1 || pkgs+=(curl)
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" || warn "some apt packages failed to install"
    elif command -v dnf5 >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
        local dnf_bin="dnf"
        command -v dnf >/dev/null 2>&1 || dnf_bin="dnf5"
        local pkgs=(ca-certificates tar iproute sqlite nftables)
        # EL9/EL10 & Fedora 43/44 often preinstall curl-minimal; only ask for curl if missing.
        command -v curl >/dev/null 2>&1 || pkgs+=(curl)
        "$dnf_bin" install -y -q "${pkgs[@]}" || warn "some ${dnf_bin} packages failed to install"
    elif command -v yum >/dev/null 2>&1; then
        local pkgs=(ca-certificates tar iproute sqlite nftables)
        command -v curl >/dev/null 2>&1 || pkgs+=(curl)
        yum install -y -q "${pkgs[@]}" || warn "some yum packages failed to install"
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --needed --noconfirm ca-certificates curl tar iproute2 sqlite nftables || warn "pacman install warning"
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install ca-certificates curl tar iproute2 sqlite3 nftables || warn "zypper install warning"
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache ca-certificates curl tar iproute2 sqlite nftables || warn "apk add warning"
    fi
}

check_host_environment() {
    local os_pretty="Linux"
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        os_pretty="${PRETTY_NAME:-${ID:-Linux} ${VERSION_ID:-}}"
    fi
    act "host:   ${TEAL}${os_pretty}${R} (kernel $(uname -r), arch ${ARCH})"

    if command -v getenforce >/dev/null 2>&1; then
        local se; se="$(getenforce 2>/dev/null || true)"
        if [[ "$se" == "Enforcing" ]]; then
            warn "SELinux is Enforcing. If systemd denies executing ${DEST}, run: restorecon -v ${DEST}"
        fi
    fi

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        act "firewall: firewalld active — remember to open your panel port & VPN inbound ports"
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        act "firewall: ufw active — remember to allow your panel port & VPN inbound ports"
    fi
}

ensure_runtime_deps
check_host_environment

# Fresh install vs in-place update: an already-installed binary means UPDATE.
MODE="install"; OLD_VER=""
if [[ -e "$DEST" ]]; then
    MODE="update"
    OLD_VER="$("$DEST" -v 2>/dev/null | tr -d '[:space:]' || true)"
    OLD_VER="${OLD_VER#v}"
fi

if [[ -z "$LOCAL_ASSET" && "$OFFLINE" != "1" ]]; then
    if   command -v curl >/dev/null 2>&1; then DL="curl"
    elif command -v wget >/dev/null 2>&1; then DL="wget"
    else DL=""; fi
else
    DL=""
fi

# Auto-detect local bundle/binary adjacent to deploy.sh or in PWD.
find_local_candidate() {
    local dir base match
    for dir in "$SCRIPT_DIR" "$PWD"; do
        [[ -d "$dir" ]] || continue
        # 1) versioned bundle e.g. vpn-ui-2.0.0-linux-amd64.tar.gz
        match="$(find "$dir" -maxdepth 1 -type f -name "vpn-ui-*-linux-${ARCH}.tar.gz" 2>/dev/null | sort -V | tail -n1 || true)"
        [[ -n "$match" ]] && { printf '%s' "$match"; return 0; }
        # 2) unversioned bundle
        if [[ -f "$dir/vpn-ui-linux-${ARCH}.tar.gz" ]]; then
            printf '%s' "$dir/vpn-ui-linux-${ARCH}.tar.gz"; return 0
        fi
        # 3) raw binary
        if [[ -f "$dir/$ASSET" ]]; then
            printf '%s' "$dir/$ASSET"; return 0
        fi
    done
    return 1
}

# Millisecond clock for the transfer rates below.
now_ms() {
    local t
    t="$(date +%s%3N 2>/dev/null || true)"
    [[ "$t" =~ ^[0-9]{13,}$ ]] || t="$(date +%s)000"
    printf '%s' "$t"
}

remote_size() {
    local url="$1" len=""
    if [[ "$DL" == "curl" ]]; then
        len="$(curl -fsIL --connect-timeout 15 --max-time 20 "$url" 2>/dev/null \
               | grep -iE '^[[:space:]]*content-length:' | tail -n1 | tr -cd '0-9')" || len=""
    elif [[ "$DL" == "wget" ]]; then
        len="$(wget --spider -S --tries=1 --timeout=20 "$url" 2>&1 \
               | grep -iE '^[[:space:]]*content-length:' | tail -n1 | tr -cd '0-9')" || len=""
    fi
    [[ "$len" =~ ^[0-9]+$ ]] && printf '%s' "$len"
    return 0
}

DL_BAR_FULL='####################'
DL_BAR_EMPTY='--------------------'
DL_LINE_LEN=0
DL_COLS=80
progress_line() {
    local bytes="$1" total="$2" speed="$3"
    local pct=0 pct_txt="" size_txt rate_txt eta_txt="" bar="" barlen=0 pad="" len
    size_txt="$(fmt_bytes "$bytes")"
    rate_txt="$(fmt_bytes "$speed")/s"
    if (( total > 0 )); then
        pct=$(( bytes * 100 / total ))
        (( pct > 100 )) && pct=100
        pct_txt="$(printf '%3d%%  ' "$pct")"
        size_txt="$size_txt / $(fmt_bytes "$total")"
        if (( speed > 0 && bytes < total )); then
            eta_txt="   eta $(fmt_time "$(( (total - bytes) / speed ))")"
        fi
    fi
    size_txt="$size_txt   "

    len=$(( 5 + ${#pct_txt} + ${#size_txt} + ${#rate_txt} + ${#eta_txt} ))
    if (( total > 0 && DL_COLS - len >= 23 )); then
        bar="[${TEAL}${DL_BAR_FULL:0:$(( pct * 20 / 100 ))}${R}${D}${DL_BAR_EMPTY:0:$(( 20 - pct * 20 / 100 ))}${R}] "
        barlen=23
    fi
    len=$(( len + barlen ))
    (( DL_LINE_LEN > len )) && pad="$(printf '%*s' "$(( DL_LINE_LEN - len ))" '')"
    DL_LINE_LEN=$len
    printf '\r  %s->%s %s%s%s%s%s%s%s%s' \
        "$BLUE" "$R" "$bar" "$pct_txt" "$size_txt" "$GREEN" "$rate_txt" "$R" "$eta_txt" "$pad"
}

fetch_asset() {
    local url="$1" out="$2"
    local total tick=0.2 rc=0 rated=0 live=0
    local start now bytes=0 last_ms last_b=0 speed=0 elapsed
    [[ -t 1 ]] && live=1

    if (( live )); then DL_COLS="$(tput cols 2>/dev/null || echo 80)"; fi
    [[ "$DL_COLS" =~ ^[0-9]+$ ]] || DL_COLS=80
    sleep 0.01 2>/dev/null || tick=1

    total="$(remote_size "$url")"
    [[ "$total" =~ ^[0-9]+$ ]] || total=0
    if (( ! live && total > 0 )); then act "size:   $(fmt_bytes "$total")"; fi

    DL_ERR="$(mktemp)"
    if [[ "$DL" == "curl" ]]; then
        curl -fL --connect-timeout 15 --max-time 300 --retry 3 -sS -o "$out" "$url" 2>"$DL_ERR" &
    else
        wget --connect-timeout=15 --timeout=300 --tries=3 -nv -O "$out" "$url" 2>"$DL_ERR" &
    fi
    DL_PID=$!

    start="$(now_ms)"; last_ms="$start"
    while kill -0 "$DL_PID" 2>/dev/null; do
        sleep "$tick"
        bytes="$(stat -c %s "$out" 2>/dev/null || echo 0)"
        now="$(now_ms)"
        if (( bytes < last_b )); then
            last_b="$bytes"; last_ms="$now"; speed=0
        elif (( now - last_ms >= 800 )); then
            speed=$(( (bytes - last_b) * 1000 / (now - last_ms) ))
            last_b="$bytes"; last_ms="$now"; rated=1
        elif (( ! rated && now > start )); then
            speed=$(( bytes * 1000 / (now - start) ))
        fi
        if (( live )); then progress_line "$bytes" "$total" "$speed"; fi
    done
    wait "$DL_PID" || rc=$?
    DL_PID=""

    bytes="$(stat -c %s "$out" 2>/dev/null || echo 0)"
    elapsed=$(( $(now_ms) - start ))
    (( elapsed < 1 )) && elapsed=1
    DL_BYTES="$bytes"
    DL_SECS=$(( (elapsed + 500) / 1000 ))
    DL_RATE=$(( bytes * 1000 / elapsed ))

    if (( live )); then
        if (( rc == 0 )); then
            progress_line "$bytes" "$total" "$DL_RATE"
            printf '\n'
        elif (( DL_LINE_LEN > 0 )); then
            printf '\r%*s\r' "$DL_LINE_LEN" ''
        fi
    fi
    if (( rc != 0 )) && [[ -s "$DL_ERR" ]]; then warn "$(tail -n1 "$DL_ERR")"; fi
    rm -f "$DL_ERR"; DL_ERR=""
    return "$rc"
}

install -d -m 0755 "$DEST_DIR"
tmp="$(mktemp "${DEST}.XXXXXX")"
TAR_TMP=""
BUNDLED_MENU=""
BUNDLE_VER=""
DL_PID=""; DL_ERR=""

dl_cleanup() {
    if [[ -n "$DL_PID" ]] && kill -0 "$DL_PID" 2>/dev/null; then
        kill "$DL_PID" 2>/dev/null || true
        wait "$DL_PID" 2>/dev/null || true
    fi
    [[ -n "$DL_ERR" ]] && rm -f "$DL_ERR"
    [[ -n "$TAR_TMP" ]] && rm -rf "$TAR_TMP"
    rm -f "$tmp"
    return 0
}
trap 'dl_cleanup' EXIT
trap 'dl_cleanup; exit 130' INT
trap 'dl_cleanup; exit 143' TERM

stage_from_local() {
    local src="$1"
    [[ -r "$src" && ! -d "$src" ]] || die "cannot read local asset: $src"
    act "staging local asset: ${TEAL}${src}${R}"

    # Verify outer archive/binary checksum if sidecar exists.
    if [[ -f "${src}.sha256" ]]; then
        verify_sha256_against_manifest "$src" "${src}.sha256" "$(basename "$src")"
    elif [[ -f "$(dirname "$src")/SHA256SUMS" ]]; then
        verify_sha256_against_manifest "$src" "$(dirname "$src")/SHA256SUMS" "$(basename "$src")"
    fi

    case "$src" in
        *.tar.gz|*.tgz)
            command -v tar >/dev/null 2>&1 || die "'tar' is required to extract $src"
            TAR_TMP="$(mktemp -d)"
            tar -xzf "$src" -C "$TAR_TMP" || die "failed to extract $src"
            local extracted_bin
            extracted_bin="$(find "$TAR_TMP" -maxdepth 2 -type f -name "$ASSET" | head -n1 || true)"
            [[ -n "$extracted_bin" ]] || die "archive $src does not contain '$ASSET'"
            local sums_file
            sums_file="$(find "$TAR_TMP" -maxdepth 2 -type f -name "SHA256SUMS" | head -n1 || true)"
            if [[ -n "$sums_file" ]]; then
                verify_sha256_against_manifest "$extracted_bin" "$sums_file" "$ASSET"
            fi
            local ver_file
            ver_file="$(find "$TAR_TMP" -maxdepth 2 -type f -name "VERSION" | head -n1 || true)"
            if [[ -n "$ver_file" ]]; then
                BUNDLE_VER="$(tr -d '[:space:]' < "$ver_file")"
                BUNDLE_VER="${BUNDLE_VER#v}"
            fi
            local menu_file
            menu_file="$(find "$TAR_TMP" -maxdepth 2 -type f -name "vpn-ui.sh" | head -n1 || true)"
            if [[ -n "$menu_file" ]]; then
                BUNDLED_MENU="$menu_file"
            fi
            cp -f "$extracted_bin" "$tmp"
            ;;
        *)
            cp -f "$src" "$tmp"
            ;;
    esac
}

ver=""
if [[ -n "$LOCAL_ASSET" ]]; then
    msg "Using local installation package"
    stage_from_local "$LOCAL_ASSET"
    ver="$BUNDLE_VER"
elif [[ "$OFFLINE" == "1" ]]; then
    msg "Offline mode (--offline): locating local bundle or binary"
    local_found="$(find_local_candidate || true)"
    [[ -n "$local_found" ]] || die "no local ${ASSET} or vpn-ui-*-linux-${ARCH}.tar.gz found in ${SCRIPT_DIR}. Pass --local <path>."
    stage_from_local "$local_found"
    ver="$BUNDLE_VER"
else
    [[ -n "$DL" ]] || die "need 'curl' or 'wget' (or pass --local <path> / --offline)"
    msg "Fetching latest release of $REPO${GH_PROXY_PREFIX:+ (via mirror)}"
    if [[ "$DL" == "curl" ]]; then
        latest_url="$(apply_gh_proxy "https://github.com/$REPO/releases/latest")"
        ver="$(curl -sILo /dev/null --connect-timeout 10 --max-time 20 -w '%{url_effective}' "$latest_url" 2>/dev/null \
               | grep -oE 'tag/[^/[:space:]]+$' | sed 's#tag/##' || true)"
    fi
    [[ -n "$ver" ]] && act "latest release: ${GREEN}${ver}${R}" || act "asset: ${GREEN}${ASSET}${R}"
    if [[ "$MODE" == "update" ]]; then
        act "mode:   ${YELLOW}update${R} (${OLD_VER:-unknown} -> ${ver:-latest})"
    else
        act "mode:   ${GREEN}fresh install${R}"
    fi

    msg "Downloading ${ASSET}"
    if fetch_asset "$DL_URL" "$tmp"; then
        ok "downloaded $(fmt_bytes "$DL_BYTES") in $(fmt_time "$DL_SECS")  (avg $(fmt_bytes "$DL_RATE")/s)"
    else
        local_fallback="$(find_local_candidate || true)"
        if [[ -n "$local_fallback" ]]; then
            warn "GitHub download failed; falling back to local asset: $local_fallback"
            stage_from_local "$local_fallback"
            ver="$BUNDLE_VER"
        else
            die "download failed from $DL_URL — for restricted/Iran servers retry with '--mirror <proxy-url>' or '--local <path/to/${ASSET}-or-.tar.gz>'"
        fi
    fi
fi

trap - INT TERM

# Sanity: non-empty and a real Linux ELF binary (not an HTML 404 page).
[[ -s "$tmp" ]] || die "staged binary is empty."
if command -v file >/dev/null 2>&1; then
    file -b "$tmp" | grep -qi 'ELF' || die "staged file is not an ELF binary (got: $(file -b "$tmp"))."
else
    [[ "$(head -c4 "$tmp")" == $'\x7fELF' ]] || die "staged file is not an ELF binary."
fi

chmod +x "$tmp"
probed_ver="$("$tmp" -v 2>/dev/null | tr -d '[:space:]' || true)"
probed_ver="${probed_ver#v}"
NEW_VER="${probed_ver:-${ver#v}}"

if [[ "$MODE" == "update" ]]; then
    act "mode:   ${YELLOW}in-place upgrade${R} (v${OLD_VER:-unknown} -> v${NEW_VER:-unknown})"
    if [[ -n "$OLD_VER" && -n "$NEW_VER" && "$OLD_VER" =~ ^[0-9]+ && "$NEW_VER" =~ ^[0-9]+ ]]; then
        cmp="$(semver_cmp "$NEW_VER" "$OLD_VER")"
        if [[ "$cmp" == "-1" && "$FORCE_UPDATE" != "1" ]]; then
            die "refusing downgrade from v${OLD_VER} to v${NEW_VER} (pass --force to override)."
        elif [[ "$cmp" == "0" ]]; then
            act "target v${NEW_VER} matches installed v${OLD_VER}; performing verified reinstall"
        fi
    fi
else
    act "mode:   ${GREEN}fresh install${R}${NEW_VER:+ (v${NEW_VER})}"
fi

unit_name() {
    local u=""
    if [[ -x "$DEST" ]]; then
        u="$("$DEST" info --get systemdUnit 2>/dev/null | tr -d '[:space:]')" || u=""
    fi
    if [[ -n "$u" ]]; then printf '%s' "$u"; else printf '%s' "$UNIT_FALLBACK"; fi
}

stop_unit_if_active() {
    systemctl is-active --quiet "$1" 2>/dev/null || return 0
    act "stopping running ${1} for replacement"
    systemctl stop "$1" || true
}

old_unit="$(unit_name)"
stop_unit_if_active "$old_unit"
if [[ "$old_unit" != "$UNIT_FALLBACK" ]]; then
    stop_unit_if_active "$UNIT_FALLBACK"
fi
if command -v pkill >/dev/null 2>&1; then
    pkill -x vpn-ui 2>/dev/null || true
    pkill -x "$ASSET" 2>/dev/null || true
    pkill -x "vpn-ui-amd64" 2>/dev/null || true
    pkill -x "vpn-ui-arm64" 2>/dev/null || true
fi

# Checkpoint WAL & back up active DB (including legacy x-ui.db if present).
ACTIVE_DB=""
if [[ -f "$DB" ]]; then
    ACTIVE_DB="$DB"
elif [[ -f "$DEST_DIR/x-ui.db" ]]; then
    ACTIVE_DB="$DEST_DIR/x-ui.db"
fi

backup=""
if [[ "$MODE" == "update" && -n "$ACTIVE_DB" ]]; then
    install -d -m 0755 "$BACKUP_DIR"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$ACTIVE_DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 \
            || warn "sqlite3 wal_checkpoint returned non-zero (proceeding with sidecar copy)"
    fi
    ts="$(date +%Y%m%d-%H%M%S)"
    db_base="$(basename "$ACTIVE_DB" .db)"
    backup="$BACKUP_DIR/${db_base}_${OLD_VER:-unknown}_${ts}.db"
    cp -p "$ACTIVE_DB" "$backup" || die "DB backup failed ($ACTIVE_DB -> $backup) — aborting before replacing the binary."
    for side in wal shm; do
        [[ -f "${ACTIVE_DB}-${side}" ]] && cp -p "${ACTIVE_DB}-${side}" "${backup}-${side}" || true
    done
    if command -v sqlite3 >/dev/null 2>&1; then
        ic="$(sqlite3 "$backup" "PRAGMA integrity_check;" 2>/dev/null || true)"
        if [[ "$ic" != "ok" ]]; then
            rm -f "$backup" "${backup}-wal" "${backup}-shm"
            die "DB backup integrity check failed (${ic:-empty}) — aborting upgrade safely."
        fi
        ok "backed up & verified DB -> $backup"
    else
        ok "backed up DB -> $backup"
    fi
fi

# Preserve outgoing binary for automatic rollback if health verification fails.
if [[ -e "$DEST" ]]; then
    cp -p "$DEST" "${DEST}.bak" && chmod 0755 "${DEST}.bak" \
        || die "could not create rollback copy ${DEST}.bak — aborting upgrade"
fi

mv -f "$tmp" "$DEST"
chmod 0755 "$DEST"
if [[ -n "$TAR_TMP" ]]; then rm -rf "$TAR_TMP"; TAR_TMP=""; fi
trap - EXIT
ok "installed -> $DEST"

# Helper for automatic rollback on upgrade failure.
rollback_upgrade() {
    local reason="$1"
    warn "upgrade failed: ${reason}"
    if [[ "$MODE" == "update" && -e "${DEST}.bak" ]]; then
        msg "Rolling back binary and database to pre-upgrade state"
        systemctl stop "${unit:-$old_unit}" 2>/dev/null || true
        mv -f "${DEST}.bak" "$DEST"
        chmod 0755 "$DEST"
        if [[ -n "${backup:-}" && -f "${backup}" && -n "${ACTIVE_DB:-}" ]]; then
            rm -f "${ACTIVE_DB}-wal" "${ACTIVE_DB}-shm"
            cp -p "${backup}" "${ACTIVE_DB}" || warn "DB restore copy failed"
            for side in wal shm; do
                [[ -f "${backup}-${side}" ]] && cp -p "${backup}-${side}" "${ACTIVE_DB}-${side}" || true
            done
        fi
        "$DEST" install-menu >/dev/null 2>&1 || true
        "$DEST" --systemd >/dev/null 2>&1 || true
        systemctl restart "${unit:-$old_unit}" >/dev/null 2>&1 || true
        die "rolled back to v${OLD_VER:-previous} after failure: ${reason}"
    fi
    die "${reason}"
}

# Install/refresh the management menu on BOTH paths.
msg "Installing the ${MENU} management menu"
export VPNUI_BIN="$DEST"
if "$DEST" install-menu >/dev/null 2>&1 && [[ -r "$MENU" ]]; then
    ok "management menu -> ${MENU}  (run: ${TEAL}vpn-ui${R})"
    # shellcheck source=vpn-ui.sh
    source "$MENU"
elif [[ -n "$BUNDLED_MENU" && -r "$BUNDLED_MENU" ]]; then
    install -m 0755 "$BUNDLED_MENU" "$MENU"
    ok "management menu -> ${MENU} (from local bundle)"
    # shellcheck source=vpn-ui.sh
    source "$MENU"
else
    warn "could not install ${MENU}, so the 'vpn-ui' menu is unavailable on this host."
    obtain_letsencrypt_cert() { warn "real SSL needs ${MENU}, which failed to install. Skipping."; return 1; }
fi

# Configure + install/refresh systemd unit.
if [[ "$MODE" == "install" ]]; then
    imported=""
    import_path="${IMPORT_DB:-}"
    if [[ -n "$import_path" ]]; then
        if [[ -r "$import_path" ]]; then
            msg "Importing database from $import_path"
            if "$DEST" import --from "$import_path"; then
                imported="1"
                ok "Imported existing data. You will log in with that panel's credentials."
            else
                warn "Import failed, continuing with a fresh database."
            fi
        else
            warn "Cannot read '$import_path', continuing with a fresh database."
        fi
    fi

    tls_choice="http"
    case "${PANEL_TLS:-}" in
        letsencrypt|le|acme|real)        tls_choice="letsencrypt" ;;
        selfsign|https|self-signed|yes)  tls_choice="selfsign" ;;
        http|plain|0|no)                 tls_choice="http" ;;
        "")
            if [[ -n "$DOMAIN" || -n "${DEPLOY_CF_TOKEN:-}" ]]; then
                tls_choice="letsencrypt"
            elif [[ -r /dev/tty ]]; then
                {
                    printf '%s::%s %sPanel access mode%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
                    printf "    %s1)%s HTTPS  (real cert via Let's Encrypt: Cloudflare token, manual, or this server's IP)\n" "$GREEN" "$R"
                    printf '    %s2)%s HTTPS  (self-signed certificate)\n'                "$GREEN" "$R"
                    printf '    %s3)%s HTTP   (no TLS) %s[default]%s\n'                    "$GREEN" "$R" "$D" "$R"
                    printf '  choose [1/2/3]: '
                } > /dev/tty
                read -r _ans < /dev/tty || _ans=""
                case "$_ans" in
                    1) tls_choice="letsencrypt" ;;
                    2) tls_choice="selfsign" ;;
                esac
            fi
            ;;
        *) warn "unrecognized PANEL_TLS='${PANEL_TLS}' — defaulting to HTTP." ;;
    esac

    if [[ "$tls_choice" == "selfsign" ]]; then
        msg "Generating self-signed TLS certificate (HTTPS)"
        "$DEST" cert -selfsign
    elif [[ "$tls_choice" == "letsencrypt" ]]; then
        obtain_letsencrypt_cert || tls_choice="http"
    fi

    cred_mode="random"
    if [[ "$imported" == "1" ]]; then
        cred_mode="keep"
    elif [[ -r /dev/tty ]]; then
        {
            printf '%s::%s %sPanel login / access%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
            printf '    %s1)%s Randomize  (port, username, password, web path) %s[default]%s\n' "$GREEN" "$R" "$D" "$R"
            printf '    %s2)%s Custom     (enter each value yourself)\n' "$GREEN" "$R"
            printf '  choose [1/2]: '
        } > /dev/tty
        read -r _cans < /dev/tty || _cans=""
        [[ "$_cans" == "2" ]] && cred_mode="custom"
    fi

    if [[ "$cred_mode" == "keep" ]]; then
        msg "Installing systemd unit (keeping the imported panel's login)"
        "$DEST" --systemd
    elif [[ "$cred_mode" == "custom" ]]; then
        msg "Enter panel login / access details (leave a field blank to keep the default)"
        printf '  %susername%s: ' "$BLUE" "$R" > /dev/tty; read -r  C_USER < /dev/tty || C_USER=""
        printf '  %spassword%s: ' "$BLUE" "$R" > /dev/tty; read -rs C_PASS < /dev/tty || C_PASS=""; printf '\n' > /dev/tty
        printf '  %sport%s: '     "$BLUE" "$R" > /dev/tty; read -r  C_PORT < /dev/tty || C_PORT=""
        printf '  %sweb path%s: ' "$BLUE" "$R" > /dev/tty; read -r  C_PATH < /dev/tty || C_PATH=""
        msg "Applying custom login / access + installing systemd unit"
        "$DEST" --user "$C_USER" --pass "$C_PASS" --port "$C_PORT" --path "$C_PATH" --systemd
    else
        msg "Configuring credentials + installing systemd unit"
        warn "--random sets a fresh port, username, password and web path — note them below."
        "$DEST" --random --systemd
    fi
else
    msg "Running non-destructive schema migration"
    if ! "$DEST" migrate >/dev/null 2>&1; then
        rollback_upgrade "database schema migration failed"
    fi
    if [[ "${PANEL_TLS:-}" =~ ^(letsencrypt|le|acme|real)$ || -n "$DOMAIN" || -n "${DEPLOY_CF_TOKEN:-}" ]]; then
        obtain_letsencrypt_cert || true
    fi
    msg "Refreshing systemd unit (existing credentials, DB, TLS certs & daemon configs preserved)"
    if ! "$DEST" --systemd; then
        rollback_upgrade "updating systemd unit failed"
    fi
fi

unit="$(unit_name)"
msg "Starting ${unit} & verifying health"
if ! systemctl restart "$unit"; then
    journalctl -u "$unit" -n 25 --no-pager >&2 || true
    rollback_upgrade "systemctl restart ${unit} failed"
fi

healthy=0
for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$unit" && [[ "$("$DEST" info --get panelRunning 2>/dev/null || true)" == "true" ]]; then
        healthy=1
        break
    fi
    sleep 0.5
done

if (( ! healthy )); then
    journalctl -u "$unit" -n 25 --no-pager >&2 || true
    rollback_upgrade "${unit} did not pass health check within 15s"
fi
ok "${unit} is running and passed health check"

# Done
hr
msg "Deploy complete"
if [[ "$MODE" == "install" ]]; then
    if [[ "${cred_mode:-random}" == "keep" ]]; then
        act "sign in with the username / password from the panel you imported"
    elif [[ "${cred_mode:-random}" == "custom" ]]; then
        act "your custom login (port / user / password / web path) was applied — see above"
    else
        act "the randomized login (port / user / password / web path) is printed above"
    fi
    if [[ "${tls_choice:-http}" == "letsencrypt" ]]; then
        act "panel serves ${GREEN}HTTPS${R} with a real cert for ${TEAL}${DOMAIN}${WILDCARD_SAN:+ + ${WILDCARD_SAN}}${R}, no browser warning"
        act "auto-renew runs via acme.sh (cron); SSTP can reuse ${TEAL}$CERT_DIR/fullchain.pem${R} + ${TEAL}$CERT_DIR/privkey.pem${R}"
    elif [[ "${tls_choice:-http}" == "selfsign" ]]; then
        act "panel serves ${GREEN}HTTPS${R} with a self-signed cert — the browser warns once; accept it to continue"
    fi
else
    act "upgraded ${TEAL}v${OLD_VER:-unknown}${R} -> ${GREEN}v${NEW_VER:-latest}${R} (credentials, DB, certs & configs preserved)"
    if [[ -n "${backup:-}" ]]; then
        act "DB backup: ${TEAL}${backup}${R}"
    fi
fi
if [[ -x "$MENU" ]]; then
    act "manage:  ${TEAL}vpn-ui${R}  (update, login, start/stop, Xray, SSL)"
fi
act "status:  ${TEAL}systemctl status ${unit}${R}"
act "logs:    ${TEAL}journalctl -u ${unit} -f${R}"
hr
