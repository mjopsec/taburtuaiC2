//go:build !windows

package recon

import "fmt"

func StartKeylogger() error { return fmt.Errorf("keylogger is Windows-only") }
func DumpKeylog() string    { return "" }
func ClearKeylog()          {}
func StopKeylogger()        {}
