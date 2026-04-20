package api

import (
	"crypto/rand"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// ── UUID & ID ─────────────────────────────────────────────────────────────────

func isValidUUID(id string) bool {
	if id == "" {
		return false
	}
	r := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	return r.MatchString(strings.ToLower(id))
}

func generateSecureUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return uuid.New().String()
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ── Command validation ────────────────────────────────────────────────────────

func validateCommand(cmd *types.Command) error {
	if cmd == nil {
		return fmt.Errorf("command cannot be nil")
	}
	if cmd.Command == "" {
		return fmt.Errorf("command text cannot be empty")
	}
	if len(cmd.Command) > 10000 {
		return fmt.Errorf("command too long (max 10000 characters)")
	}
	if cmd.Timeout < 0 || cmd.Timeout > 3600 {
		return fmt.Errorf("invalid timeout (must be 0-3600 seconds)")
	}

	validOps := map[string]bool{
		"execute": true, "upload": true, "download": true,
		"process_list": true, "process_kill": true, "process_start": true,
		"persist_setup": true, "persist_remove": true,
	}
	if cmd.OperationType != "" && !validOps[cmd.OperationType] {
		return fmt.Errorf("invalid operation type: %s", cmd.OperationType)
	}
	return nil
}

func containsDangerousPatterns(command string) bool {
	cmdLower := strings.ToLower(strings.TrimSpace(command))

	dangerous := []string{
		"rm -rf /", "rm -rf /*", "del /s /q", "format c:", "shutdown", "reboot",
		"dd if=/dev/zero", ":(){ :|:& };:", "mkfs", "fdisk", "parted",
		"sudo rm", "sudo dd", "sudo mkfs", "chmod 777 /", "chown root /",
	}
	for _, p := range dangerous {
		if strings.Contains(cmdLower, p) {
			return true
		}
	}

	suspiciousPS := []string{
		"invoke-expression", "iex", "downloadstring", "system.net.webclient",
		"reflection.assembly", "bypass", "encodedcommand", "-enc",
	}
	for _, p := range suspiciousPS {
		if strings.Contains(cmdLower, p) {
			return true
		}
	}
	return false
}

// ── Sanitization ─────────────────────────────────────────────────────────────

func sanitizeCommand(command string) string {
	command = strings.ReplaceAll(command, "\x00", "")
	command = strings.ReplaceAll(command, "\r", "")
	return strings.TrimSpace(command)
}

func sanitizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if cleaned := sanitizeCommand(a); cleaned != "" && len(cleaned) <= 1000 {
			out = append(out, cleaned)
		}
	}
	return out
}

func sanitizeWorkingDir(dir string) string {
	if dir == "" {
		return ""
	}
	dir = filepath.Clean(dir)
	if strings.Contains(dir, "..") {
		return ""
	}
	return strings.ReplaceAll(dir, "\x00", "")
}

func sanitizeMetadata(m map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range m {
		if len(k) <= 100 && len(v) <= 1000 {
			ck := sanitizeCommand(k)
			if ck != "" {
				out[ck] = sanitizeCommand(v)
			}
		}
	}
	return out
}

// ── Path & file validation ────────────────────────────────────────────────────

func validateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}
	if len(path) > 1000 {
		return fmt.Errorf("file path too long (max 1000 characters)")
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("path traversal not allowed")
	}
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("null bytes not allowed in path")
	}
	if runtime.GOOS == "windows" {
		for _, ch := range []string{"<", ">", ":", "\"", "|", "?", "*"} {
			if strings.Contains(path, ch) {
				return fmt.Errorf("invalid character '%s' in Windows path", ch)
			}
		}
	}
	return nil
}

func validateFileName(name string) error {
	if name == "" {
		return fmt.Errorf("filename cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("filename too long (max 255 characters)")
	}
	for _, ch := range []string{"\x00", "\n", "\r", "\t"} {
		if strings.Contains(name, ch) {
			return fmt.Errorf("filename contains invalid character")
		}
	}
	if runtime.GOOS == "windows" {
		reserved := []string{
			"CON", "PRN", "AUX", "NUL",
			"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
			"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
		}
		base := strings.ToUpper(strings.TrimSuffix(name, filepath.Ext(name)))
		for _, r := range reserved {
			if base == r {
				return fmt.Errorf("filename '%s' is reserved on Windows", name)
			}
		}
	}
	return nil
}

func isAllowedFileExtension(filename string) bool {
	allowed := map[string]bool{
		// Text / config
		".txt": true, ".log": true, ".json": true, ".xml": true, ".csv": true,
		".yaml": true, ".yml": true, ".conf": true, ".cfg": true, ".ini": true,
		".md": true, ".html": true, ".htm": true,
		// Scripts
		".bat": true, ".cmd": true, ".sh": true, ".ps1": true, ".py": true,
		".js": true, ".php": true, ".pl": true, ".rb": true,
		// Executables
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".msi": true, ".deb": true, ".rpm": true, ".pkg": true,
		// Archives
		".zip": true, ".rar": true, ".7z": true, ".tar": true, ".gz": true,
		".bz2": true, ".xz": true,
		// Images
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".ico": true, ".svg": true,
		// Documents
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".ppt": true, ".pptx": true, ".rtf": true,
		// Data
		".db": true, ".sqlite": true, ".sql": true, ".bak": true,
		".reg": true, ".key": true, ".crt": true, ".pem": true,
		// No extension (Unix executables)
		"": true,
	}
	return allowed[strings.ToLower(filepath.Ext(filename))]
}

func validateFileContent(content []byte, filename string) error {
	if len(content) == 0 {
		return fmt.Errorf("file is empty")
	}
	if isTextFile(filename) {
		for i, b := range content {
			if b == 0 {
				return fmt.Errorf("null byte at position %d in text file", i)
			}
		}
		if len(content) > 10*1024*1024 {
			return fmt.Errorf("text file too large (max 10MB)")
		}
	}
	return nil
}

func isTextFile(filename string) bool {
	text := map[string]bool{
		".txt": true, ".log": true, ".json": true, ".xml": true,
		".csv": true, ".yaml": true, ".yml": true, ".conf": true,
		".cfg": true, ".ini": true, ".md": true, ".html": true,
		".htm": true, ".js": true, ".py": true, ".sh": true,
		".bat": true, ".cmd": true, ".ps1": true, ".php": true,
		".pl": true, ".rb": true, ".sql": true,
	}
	return text[strings.ToLower(filepath.Ext(filename))]
}
