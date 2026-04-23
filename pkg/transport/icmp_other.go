//go:build !windows

package transport

import "fmt"

// ICMPClient stub for non-Windows platforms.
// Full raw-socket ICMP is implemented in icmp_windows.go.
type ICMPClient struct {
	ServerIP  string
	SessionID string
}

func NewICMPClient(serverIP, agentID string) (*ICMPClient, error) {
	return nil, fmt.Errorf("ICMP transport not supported on this platform")
}

func (c *ICMPClient) SendData(_ []byte) error {
	return fmt.Errorf("ICMP transport not supported on this platform")
}

func (c *ICMPClient) PollCommand() ([]byte, error) {
	return nil, fmt.Errorf("ICMP transport not supported on this platform")
}
