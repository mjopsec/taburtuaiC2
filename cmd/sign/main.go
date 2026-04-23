// sign — Authenticode self-signed binary signer for Windows PE files.
//
// Generates a self-signed RSA certificate and uses osslsigncode (Linux/macOS)
// or signtool (Windows) to apply an Authenticode signature to a PE binary.
//
// Usage:
//
//	sign --binary agent.exe
//	sign --binary agent.exe --publisher "Microsoft Corporation" --subject "Windows Update Agent"
//	sign --binary agent.exe --cert sign.pfx --password pfxpassword
//	sign --gen-cert --publisher "Microsoft Corp" --out sign.pfx
//
// The certificate is NOT trusted by Windows (no CA vouches for it), but it
// passes simple "is this file signed?" checks and makes static analysis harder.
// For a trusted cert, use a code signing certificate from a CA.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

func main() {
	var (
		binaryPath  = flag.String("binary", "", "PE binary to sign (.exe)")
		certPath    = flag.String("cert", "", "Existing PFX/P12 cert to use (skips cert generation)")
		certPass    = flag.String("password", "taburtuai", "PFX password")
		publisher   = flag.String("publisher", "Microsoft Corporation", "Certificate CN / publisher name")
		subject     = flag.String("subject", "Authenticode", "Certificate O field")
		outCert     = flag.String("out", "sign.pfx", "Output PFX path when using --gen-cert")
		genCertOnly = flag.Bool("gen-cert", false, "Only generate a PFX cert, do not sign a binary")
		validDays   = flag.Int("days", 730, "Certificate validity in days")
		timestampURL = flag.String("ts", "http://timestamp.sectigo.com", "RFC3161 timestamp server URL")
	)
	flag.Parse()

	if *genCertOnly {
		if err := generatePFX(*publisher, *subject, *certPass, *outCert, *validDays); err != nil {
			fmt.Fprintf(os.Stderr, "[-] cert generation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Self-signed cert written to %s\n", *outCert)
		return
	}

	if *binaryPath == "" {
		fmt.Fprintf(os.Stderr, "[-] --binary is required\n")
		flag.Usage()
		os.Exit(1)
	}

	useCert := *certPath
	tmpCert := ""

	// Generate a temporary cert if none provided
	if useCert == "" {
		tmpCert = filepath.Join(os.TempDir(), "taburtuai_sign_tmp.pfx")
		if err := generatePFX(*publisher, *subject, *certPass, tmpCert, *validDays); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to generate temp cert: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tmpCert)
		useCert = tmpCert
	}

	if err := signBinary(*binaryPath, useCert, *certPass, *publisher, *timestampURL); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Signing failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Signed: %s\n", *binaryPath)
}

// generatePFX creates a self-signed RSA-2048 certificate and writes it as a
// PKCS#12 PFX file.  We output separate PEM files and then combine with
// openssl because Go's standard library does not include a PKCS12 encoder.
// The openssl call is optional — if unavailable we write PEM files instead
// and print instructions.
func generatePFX(publisher, subject, password, outPath string, validDays int) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("RSA keygen: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   publisher,
			Organization: []string{subject},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("x509 create: %w", err)
	}

	// Write temp PEM files
	tmpKey := outPath + ".key.pem"
	tmpCert := outPath + ".cert.pem"
	defer os.Remove(tmpKey)
	defer os.Remove(tmpCert)

	kf, err := os.Create(tmpKey)
	if err != nil {
		return err
	}
	pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	kf.Close()

	cf, err := os.Create(tmpCert)
	if err != nil {
		return err
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	// Try openssl pkcs12 export
	cmd := exec.Command("openssl", "pkcs12", "-export",
		"-inkey", tmpKey,
		"-in", tmpCert,
		"-out", outPath,
		"-passout", "pass:"+password,
		"-name", publisher,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		// openssl not available — write PEM files and guide the user
		pemOut := outPath + ".pem"
		pf, _ := os.Create(pemOut)
		pem.Encode(pf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		pem.Encode(pf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		pf.Close()
		fmt.Fprintf(os.Stderr, "[!] openssl not found (%v: %s)\n", err, string(out))
		fmt.Fprintf(os.Stderr, "    PEM written to %s — convert manually:\n", pemOut)
		fmt.Fprintf(os.Stderr, "    openssl pkcs12 -export -inkey %s -in %s -out %s -passout pass:%s\n",
			pemOut, pemOut, outPath, password)
		return nil
	}
	return nil
}

// signBinary invokes the appropriate signing tool for the current platform.
func signBinary(binary, cert, password, publisher, tsURL string) error {
	if runtime.GOOS == "windows" {
		return signWithSigntool(binary, cert, password, publisher, tsURL)
	}
	return signWithOsslsigncode(binary, cert, password, publisher, tsURL)
}

func signWithOsslsigncode(binary, cert, password, publisher, tsURL string) error {
	if _, err := exec.LookPath("osslsigncode"); err != nil {
		return fmt.Errorf("osslsigncode not found — install with: apt install osslsigncode")
	}
	signed := binary + ".signed.exe"
	args := []string{
		"sign",
		"-pkcs12", cert,
		"-pass", password,
		"-n", publisher,
		"-t", tsURL,
		"-in", binary,
		"-out", signed,
	}
	cmd := exec.Command("osslsigncode", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("osslsigncode: %v\n%s", err, string(out))
	}
	return os.Rename(signed, binary)
}

func signWithSigntool(binary, cert, password, publisher, tsURL string) error {
	signtool, err := exec.LookPath("signtool")
	if err != nil {
		// Try well-known Windows SDK path
		candidates := []string{
			`C:\Program Files (x86)\Windows Kits\10\bin\x64\signtool.exe`,
			`C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe`,
		}
		for _, c := range candidates {
			if _, err2 := os.Stat(c); err2 == nil {
				signtool = c
				break
			}
		}
		if signtool == "" {
			return fmt.Errorf("signtool.exe not found — install Windows SDK")
		}
	}
	args := []string{
		"sign",
		"/f", cert,
		"/p", password,
		"/d", publisher,
		"/t", tsURL,
		"/fd", "sha256",
		binary,
	}
	cmd := exec.Command(signtool, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("signtool: %v\n%s", err, string(out))
	}
	return nil
}
