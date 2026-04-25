//go:build !windows

package exec

import "fmt"

// TokenInfo holds information about a process's token.
type TokenInfo struct {
	PID          uint32
	ProcessName  string
	Username     string
	Integrity    string
	Impersonating bool
}

func ListTokens() ([]TokenInfo, error)              { return nil, fmt.Errorf("token ops are Windows-only") }
func ImpersonateToken(_ uint32) (string, error)     { return "", fmt.Errorf("token ops are Windows-only") }
func RevertToSelf() error                           { return fmt.Errorf("token ops are Windows-only") }
func MakeToken(_, _, _ string) error                { return fmt.Errorf("token ops are Windows-only") }
func TokenListText(_ []TokenInfo) string            { return "Windows-only" }
