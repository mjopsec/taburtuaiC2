//go:build !windows

package transport

import "fmt"

// SMBClient stub for non-Windows platforms.
type SMBClient struct {
	PipePath  string
	SessionID string
}

func NewSMBClient(serverHost, pipeName, agentID string) (*SMBClient, error) {
	return nil, fmt.Errorf("SMB named pipe transport not supported on this platform")
}

func (c *SMBClient) SendData(_ []byte) error {
	return fmt.Errorf("SMB named pipe transport not supported on this platform")
}

func (c *SMBClient) PollCommand() ([]byte, error) {
	return nil, fmt.Errorf("SMB named pipe transport not supported on this platform")
}

func (c *SMBClient) Close() {}
