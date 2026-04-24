package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// socks5Server is a minimal in-process SOCKS5 proxy listener.
// It binds on 127.0.0.1:<port> (default 1080) so the operator can
// tunnel through the agent via `ssh -D` or proxychains.
type socks5Server struct {
	listener net.Listener
	running  int32 // atomic bool
	wg       sync.WaitGroup
}

var globalSOCKS5 *socks5Server
var socks5mu sync.Mutex

// StartSOCKS5 starts a SOCKS5 listener on the given address (e.g. "127.0.0.1:1080").
// If a server is already running it is stopped first.
func StartSOCKS5(addr string) (string, error) {
	socks5mu.Lock()
	defer socks5mu.Unlock()

	if globalSOCKS5 != nil {
		globalSOCKS5.stop()
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("socks5 listen %s: %w", addr, err)
	}

	srv := &socks5Server{listener: ln}
	atomic.StoreInt32(&srv.running, 1)
	globalSOCKS5 = srv

	srv.wg.Add(1)
	go srv.serve()

	return ln.Addr().String(), nil
}

// StopSOCKS5 tears down the running SOCKS5 proxy.
func StopSOCKS5() string {
	socks5mu.Lock()
	defer socks5mu.Unlock()
	if globalSOCKS5 == nil {
		return "no socks5 proxy running"
	}
	addr := globalSOCKS5.listener.Addr().String()
	globalSOCKS5.stop()
	globalSOCKS5 = nil
	return fmt.Sprintf("socks5 stopped (%s)", addr)
}

// SOCKS5Status returns a human-readable status string.
func SOCKS5Status() string {
	socks5mu.Lock()
	defer socks5mu.Unlock()
	if globalSOCKS5 == nil || atomic.LoadInt32(&globalSOCKS5.running) == 0 {
		return "not running"
	}
	return "running on " + globalSOCKS5.listener.Addr().String()
}

func (s *socks5Server) stop() {
	atomic.StoreInt32(&s.running, 0)
	s.listener.Close()
	s.wg.Wait()
}

func (s *socks5Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if atomic.LoadInt32(&s.running) == 0 {
				return
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			handleSOCKS5Conn(conn)
		}()
	}
}

// handleSOCKS5Conn implements the SOCKS5 handshake (RFC 1928) then pipes traffic.
func handleSOCKS5Conn(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(10 * time.Second))

	// Version/methods negotiation
	buf := make([]byte, 2)
	if _, err := io.ReadFull(client, buf); err != nil {
		return
	}
	if buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	// Select NO_AUTH (0x00)
	client.Write([]byte{0x05, 0x00})

	// Request
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 || hdr[1] != 0x01 { // only CONNECT supported
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // cmd not supported
		return
	}

	var target string
	switch hdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		io.ReadFull(client, addr)
		target = net.IP(addr).String()
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		io.ReadFull(client, lenBuf)
		domain := make([]byte, lenBuf[0])
		io.ReadFull(client, domain)
		target = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		io.ReadFull(client, addr)
		target = net.IP(addr).String()
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // addr type unsupported
		return
	}

	portBuf := make([]byte, 2)
	io.ReadFull(client, portBuf)
	port := binary.BigEndian.Uint16(portBuf)
	dialAddr := net.JoinHostPort(target, fmt.Sprintf("%d", port))

	client.SetDeadline(time.Time{}) // clear deadline before dialing

	remote, err := net.DialTimeout("tcp", dialAddr, 10*time.Second)
	if err != nil {
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	defer remote.Close()

	// Success reply
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// Bidirectional pipe
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go pipe(remote, client)
	go pipe(client, remote)
	<-done
}
