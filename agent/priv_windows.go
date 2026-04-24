//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// enablePrivilege enables a named privilege on the current process token.
// Required before RegSaveKeyW (SeBackupPrivilege), LSASS ops (SeDebugPrivilege), etc.
func enablePrivilege(name string) error {
	var luid windows.LUID
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, err)
	}

	hToken, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("OpenCurrentProcessToken: %w", err)
	}
	defer hToken.Close()

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(hToken, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
}
