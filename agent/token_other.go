//go:build !windows

package main

import "fmt"

type TokenInfo struct {
	PID         uint32
	ProcessName string
	Username    string
	Integrity   string
}

func listTokens() ([]TokenInfo, error)              { return nil, fmt.Errorf("token ops are Windows-only") }
func impersonateToken(_ uint32) (string, error)     { return "", fmt.Errorf("token ops are Windows-only") }
func revertToSelf() error                           { return fmt.Errorf("token ops are Windows-only") }
func makeToken(_, _, _ string) (interface{}, error) { return nil, fmt.Errorf("token ops are Windows-only") }
func tokenListText(_ []TokenInfo) string            { return "Windows-only" }
