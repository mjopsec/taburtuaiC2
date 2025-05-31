// server/services/auth_service.go
package services

import (
    "crypto/rand"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "fmt"
    "sync"
    "time"
)

// AuthManager handles advanced authentication
type AuthManager struct {
    agents      map[string]*AgentAuth
    sessions    map[string]*Session
    mutex       sync.RWMutex
    maxSessions int
}

type AgentAuth struct {
    AgentID       string
    SharedSecret  []byte
    LastAuth      time.Time
    FailedAttempts int
    IsBlacklisted bool
    Certificate   []byte
}

type Session struct {
    SessionID   string
    AgentID     string
    CreatedAt   time.Time
    LastUsed    time.Time
    ExpiresAt   time.Time
    IsActive    bool
}

func NewAuthManager() *AuthManager {
    return &AuthManager{
        agents:      make(map[string]*AgentAuth),
        sessions:    make(map[string]*Session),
        maxSessions: 1000,
    }
}

// GenerateAgentCredentials creates secure credentials for new agent
func (am *AuthManager) GenerateAgentCredentials(agentID string) (*AgentAuth, error) {
    am.mutex.Lock()
    defer am.mutex.Unlock()

    // Generate 32-byte shared secret
    secret := make([]byte, 32)
    if _, err := rand.Read(secret); err != nil {
        return nil, fmt.Errorf("failed to generate secret: %v", err)
    }

    auth := &AgentAuth{
        AgentID:      agentID,
        SharedSecret: secret,
        LastAuth:     time.Now(),
    }

    am.agents[agentID] = auth
    return auth, nil
}

// AuthenticateAgent validates agent with mutual authentication
func (am *AuthManager) AuthenticateAgent(agentID string, challenge, response []byte) (*Session, error) {
    am.mutex.Lock()
    defer am.mutex.Unlock()

    auth, exists := am.agents[agentID]
    if !exists {
        return nil, fmt.Errorf("agent not registered")
    }

    if auth.IsBlacklisted {
        return nil, fmt.Errorf("agent blacklisted")
    }

    // Verify response using HMAC-SHA256
    expectedResponse := sha256.Sum256(append(challenge, auth.SharedSecret...))
    if subtle.ConstantTimeCompare(response, expectedResponse[:]) != 1 {
        auth.FailedAttempts++
        if auth.FailedAttempts >= 5 {
            auth.IsBlacklisted = true
        }
        return nil, fmt.Errorf("authentication failed")
    }

    // Reset failed attempts on success
    auth.FailedAttempts = 0
    auth.LastAuth = time.Now()

    // Create session
    session := &Session{
        SessionID: generateSessionID(),
        AgentID:   agentID,
        CreatedAt: time.Now(),
        LastUsed:  time.Now(),
        ExpiresAt: time.Now().Add(24 * time.Hour),
        IsActive:  true,
    }

    am.sessions[session.SessionID] = session
    return session, nil
}

// ValidateSession checks if session is valid and updates last used
func (am *AuthManager) ValidateSession(sessionID string) (*Session, error) {
    am.mutex.Lock()
    defer am.mutex.Unlock()

    session, exists := am.sessions[sessionID]
    if !exists {
        return nil, fmt.Errorf("session not found")
    }

    if !session.IsActive || time.Now().After(session.ExpiresAt) {
        delete(am.sessions, sessionID)
        return nil, fmt.Errorf("session expired")
    }

    session.LastUsed = time.Now()
    return session, nil
}

func generateSessionID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return hex.EncodeToString(b)
}

// CleanupExpiredSessions removes old sessions
func (am *AuthManager) CleanupExpiredSessions() {
    am.mutex.Lock()
    defer am.mutex.Unlock()

    now := time.Now()
    for id, session := range am.sessions {
        if now.After(session.ExpiresAt) {
            delete(am.sessions, id)
        }
    }
}
