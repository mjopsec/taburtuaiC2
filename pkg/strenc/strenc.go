package strenc

import (
	"encoding/hex"
)

// Enc XOR-encrypts s with key and returns the result as a lowercase hex string.
func Enc(s string, key byte) string {
	b := []byte(s)
	for i := range b {
		b[i] ^= key
	}
	return hex.EncodeToString(b)
}

// Dec hex-decodes h then XOR-decrypts with key, returning the plaintext string.
// Returns "" on any decode error.
func Dec(h string, key byte) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return ""
	}
	for i := range b {
		b[i] ^= key
	}
	return string(b)
}
