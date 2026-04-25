package crypto

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// Manager handles all encryption and decryption operations
type Manager struct {
	primaryKey   []byte
	secondaryKey []byte
	gcm          cipher.AEAD
}

// NewManager creates a new crypto manager with given keys
func NewManager(primaryKey, secondaryKey string) (*Manager, error) {
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

	return &Manager{
		primaryKey:   pKey[:],
		secondaryKey: sKey[:],
		gcm:          gcm,
	}, nil
}

// EncryptData encrypts data with multiple layers
func (m *Manager) EncryptData(data []byte) (string, error) {
	// Layer 1: Compress
	compressed, err := m.compressData(data)
	if err != nil {
		return "", fmt.Errorf("compression failed: %v", err)
	}

	// Layer 2: Add padding
	padded := m.addPadding(compressed)

	// Layer 3: AES-GCM encryption
	nonce := make([]byte, m.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %v", err)
	}

	encrypted := m.gcm.Seal(nil, nonce, padded, nil)

	// Layer 4: Combine nonce + encrypted data
	combined := append(nonce, encrypted...)

	// Layer 5: Base64 encoding
	encoded := base64.StdEncoding.EncodeToString(combined)

	// Layer 6: Add obfuscation markers
	obfuscated := m.addObfuscationMarkers(encoded)

	return obfuscated, nil
}

// DecryptData decrypts data reversing all layers
func (m *Manager) DecryptData(obfuscatedData string) ([]byte, error) {
	// Remove obfuscation markers
	encoded := m.removeObfuscationMarkers(obfuscatedData)

	// Base64 decode
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %v", err)
	}

	// Extract nonce and encrypted data
	if len(combined) < m.gcm.NonceSize() {
		return nil, fmt.Errorf("invalid data size")
	}

	nonce := combined[:m.gcm.NonceSize()]
	encrypted := combined[m.gcm.NonceSize():]

	// AES-GCM decryption
	padded, err := m.gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Remove padding
	compressed := m.removePadding(padded)

	// Decompress
	data, err := m.decompressData(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %v", err)
	}

	return data, nil
}

// PrimaryKeyBytes returns a copy of the primary AES key bytes.
// Used by the agent to pass sensitive key material to sleep masking.
func (m *Manager) PrimaryKeyBytes() []byte {
	out := make([]byte, len(m.primaryKey))
	copy(out, m.primaryKey)
	return out
}

// Helper methods
func (m *Manager) compressData(data []byte) ([]byte, error) {
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

func (m *Manager) decompressData(data []byte) ([]byte, error) {
	// C implant sends uncompressed plaintext — detect by absence of gzip magic.
	if len(data) < 2 || data[0] != 0x1F || data[1] != 0x8B {
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func (m *Manager) addPadding(data []byte) []byte {
	paddingSize := 1 + (len(data) % 16)
	padding := make([]byte, paddingSize)
	if _, err := io.ReadFull(rand.Reader, padding); err != nil {
		// extremely unlikely; zero-fill rather than panic
		for i := range padding {
			padding[i] = 0
		}
	}

	result := make([]byte, 1+paddingSize+len(data))
	result[0] = byte(paddingSize)
	copy(result[1:1+paddingSize], padding)
	copy(result[1+paddingSize:], data)
	return result
}

func (m *Manager) removePadding(data []byte) []byte {
	if len(data) < 2 {
		return data
	}
	paddingSize := int(data[0])
	if paddingSize >= len(data) {
		return data
	}
	return data[1+paddingSize:]
}

// obfuscationMarkers is a large pool of plausible HTTP/web field prefixes.
// Using a wide, varied pool makes static NIDS regex matching impractical.
var obfuscationMarkers = []string{
	"session_id=", "token=", "data=", "payload=", "content=", "response=",
	"auth=", "sig=", "nonce=", "hash=", "checksum=", "digest=",
	"state=", "code=", "ticket=", "ref=", "key=", "id=",
	"value=", "body=", "msg=", "blob=", "raw=", "enc=",
	"t=", "v=", "q=", "r=", "s=", "x=",
	"client_id=", "request_id=", "trace_id=", "span_id=", "correlation_id=",
	"access_token=", "refresh_token=", "bearer=", "api_key=", "csrf=",
	"challenge=", "proof=", "assertion=", "grant=", "scope=",
}

func (m *Manager) addObfuscationMarkers(data string) string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(obfuscationMarkers))))
	return obfuscationMarkers[n.Int64()] + data
}

func (m *Manager) removeObfuscationMarkers(data string) string {
	for _, marker := range obfuscationMarkers {
		if strings.HasPrefix(data, marker) {
			return data[len(marker):]
		}
	}
	return data
}
