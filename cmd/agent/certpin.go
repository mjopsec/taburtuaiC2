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

// newPinnedClient returns an *http.Client configured for the given TLS policy.
//
// fingerprint: SHA-256 hex of the expected leaf cert ("aa:bb:cc:…" or "aabbcc…").
//   Empty = no pinning.
// insecure: skip OS certificate chain verification (required for self-signed certs).
//   When combined with a fingerprint, the pin is still enforced even though the
//   chain check is skipped — this is the correct way to pin a self-signed cert.
func newPinnedClient(fingerprint string, insecure bool) (*http.Client, error) {
	if fingerprint == "" && !insecure {
		return &http.Client{Timeout: 60 * time.Second}, nil
	}

	tlsCfg := &tls.Config{} //nolint:gosec
	if insecure {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}

	if fingerprint != "" {
		pin, err := parsePin(fingerprint)
		if err != nil {
			return nil, err
		}
		// VerifyPeerCertificate runs after the TLS handshake regardless of
		// InsecureSkipVerify, so the pin is always checked.
		tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("cert pin: server sent no certificate")
			}
			got := sha256.Sum256(rawCerts[0])
			if got != pin {
				return fmt.Errorf("cert pin: fingerprint mismatch — server cert not trusted")
			}
			return nil
		}
	}

	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
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
