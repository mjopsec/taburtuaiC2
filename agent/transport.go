package main

// BeaconTransport is the interface all C2 transports implement.
// The HTTP transport (built into agent.go) is used by default.
// Alternative transports (DoH, ICMP, SMB) implement this interface and are
// selected at build time via the TRANSPORT Makefile variable.
type BeaconTransport interface {
	// SendData transmits an encrypted payload to the C2 (checkin, result).
	SendData(payload []byte) error
	// PollCommand requests the next pending command. Returns nil, nil when
	// there is no command pending.
	PollCommand() ([]byte, error)
}
