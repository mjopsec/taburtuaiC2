package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// ECDHSession holds an ephemeral P-256 key pair for one-time key exchange
type ECDHSession struct {
	privKey   *ecdh.PrivateKey
	PubKeyB64 string // base64-encoded uncompressed public key — send this to the peer
}

// NewECDHSession generates a fresh ephemeral P-256 key pair
func NewECDHSession() (*ECDHSession, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDH key: %w", err)
	}
	return &ECDHSession{
		privKey:   priv,
		PubKeyB64: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// DeriveSessionKey computes a 32-byte AES key from the shared ECDH secret.
// peerPubB64 is the peer's base64-encoded P-256 public key.
func (s *ECDHSession) DeriveSessionKey(peerPubB64 string) ([]byte, error) {
	peerBytes, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil {
		return nil, fmt.Errorf("decode peer public key: %w", err)
	}
	peerPub, err := ecdh.P256().NewPublicKey(peerBytes)
	if err != nil {
		return nil, fmt.Errorf("parse peer public key: %w", err)
	}
	shared, err := s.privKey.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH exchange: %w", err)
	}
	// Domain-separated SHA-256 as KDF
	h := sha256.New()
	h.Write(shared)
	h.Write([]byte("taburtuai-c2-session-v1"))
	return h.Sum(nil), nil
}

// NewManagerFromRawKey creates a Manager from a 32-byte raw AES-256 key.
// Used after ECDH key derivation to create a per-session crypto manager.
func NewManagerFromRawKey(key []byte) (*Manager, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, key)
	return &Manager{
		primaryKey:   keyCopy,
		secondaryKey: keyCopy,
		gcm:          gcm,
	}, nil
}
