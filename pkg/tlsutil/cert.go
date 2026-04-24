package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// GenerateSelfSigned creates a self-signed ECDSA P-256 certificate valid for
// one year. hosts may contain DNS names or IP address strings.
func GenerateSelfSigned(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"taburtuaiC2"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// SaveCerts writes certPEM and keyPEM to disk.
func SaveCerts(certPEM, keyPEM []byte, certFile, keyFile string) error {
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, keyPEM, 0600)
}

// LoadOrGenerate loads a TLS certificate from disk if certFile/keyFile exist,
// otherwise generates a new self-signed cert for the given hosts.
// Returns the loaded/generated tls.Certificate and the PEM bytes.
func LoadOrGenerate(certFile, keyFile string, hosts []string) (tls.Certificate, []byte, []byte, error) {
	// Try loading existing files first.
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				return tls.Certificate{}, nil, nil, err
			}
			certPEM, _ := os.ReadFile(certFile)
			keyPEM, _ := os.ReadFile(keyFile)
			return cert, certPEM, keyPEM, nil
		}
	}

	// Generate a new self-signed certificate.
	certPEM, keyPEM, err := GenerateSelfSigned(hosts)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}

	// Persist to disk if paths were requested.
	if certFile != "" && keyFile != "" {
		_ = SaveCerts(certPEM, keyPEM, certFile, keyFile)
	}

	return cert, certPEM, keyPEM, nil
}

// ServerTLSConfig returns a hardened *tls.Config with the supplied certificate.
func ServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		PreferServerCipherSuites: true,
	}
}
