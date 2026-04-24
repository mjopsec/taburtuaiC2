package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// newPinnedClient returns an *http.Client whose TLS stack verifies the server's
// leaf certificate against the expected SHA-256 fingerprint.
//
// fingerprint may be colon-separated ("aa:bb:cc:…") or plain hex ("aabbcc…").
// An empty fingerprint means no pinning — returns the default client.
func newPinnedClient(fingerprint string) (*http.Client, error) {
	if fingerprint == "" {
		return &http.Client{Timeout: 60 * time.Second}, nil
	}

	pin, err := parsePin(fingerprint)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// VerifyPeerCertificate is called after normal TLS handshake
			// (chain verification).  We add our own leaf-cert check on top.
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("cert pin: server sent no certificate")
				}
				got := sha256.Sum256(rawCerts[0]) // leaf cert (index 0)
				if got != pin {
					return fmt.Errorf("cert pin: fingerprint mismatch — server cert not trusted")
				}
				return nil
			},
		},
	}

	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}, nil
}

// parsePin normalises a hex fingerprint into a fixed [32]byte array.
func parsePin(fp string) ([32]byte, error) {
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, " ", "")
	fp = strings.ToLower(fp)

	b, err := hex.DecodeString(fp)
	if err != nil {
		return [32]byte{}, fmt.Errorf("cert pin: invalid hex %q: %v", fp, err)
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("cert pin: expected 64-hex SHA-256, got %d chars", len(fp))
	}
	var arr [32]byte
	copy(arr[:], b)
	return arr, nil
}
