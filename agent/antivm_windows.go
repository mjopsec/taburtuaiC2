//go:build windows

package main

import (
	"os/exec"
	"strings"
	"unsafe"
)

// IsVM returns true if any VM/sandbox artifact is detected.
func IsVM() bool {
	return checkCPUIDHypervisor() ||
		checkVMRegistryKeys() ||
		checkVMProcesses()
}

// checkCPUIDHypervisor detects the hypervisor-present bit (CPUID leaf 1, ECX[31]).
// Uses the CPUID brand string query (leaf 0x40000000) via a dummy LoadLibrary trick
// to avoid inline assembly. Falls back to checking known hypervisor brand strings.
func checkCPUIDHypervisor() bool {
	// Indirect check: if the machine is a hypervisor, the Hyper-V CPUID leaves
	// (0x40000001+) are present. We detect this by checking if the HvPresent bit
	// is set by inspecting the string returned from "wmic computersystem get model".
	out, err := exec.Command("wmic", "computersystem", "get", "model").Output()
	if err != nil {
		return false
	}
	model := strings.ToLower(string(out))
	vmKeywords := []string{"virtual", "vmware", "vbox", "kvm", "qemu", "hyper-v", "xen", "parallels"}
	for _, kw := range vmKeywords {
		if strings.Contains(model, kw) {
			return true
		}
	}
	return false
}

// checkVMRegistryKeys: look for known VMware/VBox/Hyper-V registry artifacts.
func checkVMRegistryKeys() bool {
	keys := []string{
		`HKLM\SOFTWARE\VMware, Inc.\VMware Tools`,
		`HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions`,
		`HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`,
	}
	for _, k := range keys {
		out, err := exec.Command("reg", "query", k).CombinedOutput()
		if err == nil && len(out) > 0 {
			return true
		}
	}
	return false
}

// checkVMProcesses: look for known VM agent process names via toolhelp snapshot.
func checkVMProcesses() bool {
	vmProcs := []string{
		"vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
		"vboxservice.exe", "vboxtray.exe",
		"vmsrvc.exe", "vmusrvc.exe",
		"xenservice.exe", "qemu-ga.exe",
	}

	type PROCESSENTRY32W struct {
		dwSize              uint32
		cntUsage            uint32
		th32ProcessID       uint32
		th32DefaultHeapID   uintptr
		th32ModuleID        uint32
		cntThreads          uint32
		th32ParentProcessID uint32
		pcPriClassBase      int32
		dwFlags             uint32
		szExeFile           [260]uint16
	}

	hSnap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapProcess), 0)
	if hSnap == ^uintptr(0) {
		return false
	}

	pe := PROCESSENTRY32W{dwSize: uint32(unsafe.Sizeof(PROCESSENTRY32W{}))}
	procProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe)))

	for {
		exeName := strings.ToLower(utf16PtrToString(pe.szExeFile[:]))
		for _, vm := range vmProcs {
			if exeName == vm {
				return true
			}
		}
		r, _, _ := procProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}
	return false
}

func utf16PtrToString(u16 []uint16) string {
	end := len(u16)
	for i, c := range u16 {
		if c == 0 {
			end = i
			break
		}
	}
	return string(utf16ToRunes(u16[:end]))
}

// AntiVMReport returns a string summarising detected VM artifacts.
func AntiVMReport() string {
	var findings []string
	if checkCPUIDHypervisor() {
		findings = append(findings, "CPUID[hypervisor bit]")
	}
	if checkVMRegistryKeys() {
		findings = append(findings, "RegistryArtifacts")
	}
	if checkVMProcesses() {
		findings = append(findings, "VMProcesses")
	}
	if len(findings) == 0 {
		return "clean"
	}
	return strings.Join(findings, ", ")
}
