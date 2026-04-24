//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// .NET CLR hosting via ICLRRuntimeHost (mscoree.dll).
//
// Loads the CLR in-process and executes a .NET assembly without spawning
// powershell.exe or csc.exe.  Uses the COM-based CLR hosting API:
//
//   CLRCreateInstance → ICLRMetaHost → EnumerateInstalledRuntimes →
//   ICLRRuntimeInfo → GetInterface(ICLRRuntimeHost) → Start →
//   ExecuteInDefaultAppDomain
//
// The assembly must expose a static method with signature:
//   public static int MethodName(string arg)
//
// Requires mscoree.dll (present on any system with .NET Framework installed).

// ─── COM GUID helpers ─────────────────────────────────────────────────────────

type clrGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	// CLSID_CLRMetaHost  {9280188D-0E8E-4867-B30C-7FA83884E8DE}
	clsidCLRMetaHost = clrGUID{0x9280188D, 0x0E8E, 0x4867,
		[8]byte{0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE}}

	// IID_ICLRMetaHost  {D332DB9E-B9B3-4125-8207-A14884F53216}
	iidICLRMetaHost = clrGUID{0xD332DB9E, 0xB9B3, 0x4125,
		[8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}}

	// IID_ICLRRuntimeInfo  {BD39D1D2-BA2F-486A-89B0-B4B0CB466891}
	iidICLRRuntimeInfo = clrGUID{0xBD39D1D2, 0xBA2F, 0x486A,
		[8]byte{0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}}

	// CLSID_CLRRuntimeHost  {90F1A06E-7712-4762-86B5-7A5EBA6BDB02}
	clsidCLRRuntimeHost = clrGUID{0x90F1A06E, 0x7712, 0x4762,
		[8]byte{0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02}}

	// IID_ICLRRuntimeHost  {90F1A06C-7712-4762-86B5-7A5EBA6BDB02}
	iidICLRRuntimeHost = clrGUID{0x90F1A06C, 0x7712, 0x4762,
		[8]byte{0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02}}
)

// ─── ICLRMetaHost vtable offsets ─────────────────────────────────────────────
//
// We use raw vtable calls (pointer arithmetic) to avoid importing the full COM
// runtime.  vtable layout for ICLRMetaHost:
//   [0] QueryInterface, [1] AddRef, [2] Release,
//   [3] GetRuntime, [4] GetVersionFromFile, [5] EnumerateInstalledRuntimes,
//   [6] EnumerateLoadedRuntimes, [7] RequestRuntimeLoadedNotification,
//   [8] QueryLegacyV2RuntimeBinding, [9] ExitProcess

const (
	vtGetRuntime                   = 3
	vtGetInterface                 = 9  // ICLRRuntimeInfo
	vtICLRRuntimeHostStart         = 3  // ICLRRuntimeHost
	vtExecuteInDefaultAppDomain    = 11 // ICLRRuntimeHost
)

// comVtCall calls vtable[index](this, args...).
func comVtCall(this uintptr, idx int, args ...uintptr) (uintptr, error) {
	vtbl := *(*uintptr)(unsafe.Pointer(this))
	fn := *(*uintptr)(unsafe.Pointer(vtbl + uintptr(idx)*8))
	r, _, _ := syscallNVarargs(fn, append([]uintptr{this}, args...)...)
	if r != 0 && r != 1 { // S_OK=0, S_FALSE=1 are success
		return r, fmt.Errorf("COM call vtable[%d] HRESULT 0x%08X", idx, uint32(r))
	}
	return r, nil
}

func syscallNVarargs(fn uintptr, args ...uintptr) (uintptr, uintptr, uintptr) {
	a := make([]uintptr, 15)
	copy(a, args)
	r1, r2, e := syscall.Syscall15(fn,
		uintptr(len(args)),
		a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
		a[8], a[9], a[10], a[11], a[12], a[13], a[14])
	return r1, r2, uintptr(e)
}

// ─── Public API ───────────────────────────────────────────────────────────────

// dotnetExecute loads a .NET assembly from assemblyPath and invokes
// typeName.methodName(argument) in the default app domain.
//
// assemblyPath must be the full path to the .dll (on disk or via UNC).
// For in-memory execution, write to a temp file first or use AppDomain.Load.
func dotnetExecute(assemblyPath, typeName, methodName, argument string) (int32, error) {
	// Step 1: CLRCreateInstance → ICLRMetaHost
	var metaHost uintptr
	r, _, e := procCLRCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidCLRMetaHost)),
		uintptr(unsafe.Pointer(&iidICLRMetaHost)),
		uintptr(unsafe.Pointer(&metaHost)),
	)
	if r != 0 {
		return 0, fmt.Errorf("CLRCreateInstance: HRESULT 0x%08X (%v)", uint32(r), e)
	}
	defer comVtCall(metaHost, 2) // Release //nolint:errcheck

	// Step 2: Get highest installed runtime version.
	version, err := clrGetLatestVersion(metaHost)
	if err != nil {
		return 0, fmt.Errorf("get CLR version: %w", err)
	}

	// Step 3: GetRuntime(version) → ICLRRuntimeInfo
	versionPtr, _ := windows.UTF16PtrFromString(version)
	var runtimeInfo uintptr
	if _, err := comVtCall(metaHost, vtGetRuntime,
		uintptr(unsafe.Pointer(versionPtr)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&runtimeInfo)),
	); err != nil {
		return 0, fmt.Errorf("GetRuntime(%s): %w", version, err)
	}
	defer comVtCall(runtimeInfo, 2) // Release //nolint:errcheck

	// Step 4: GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost) → ICLRRuntimeHost
	var runtimeHost uintptr
	if _, err := comVtCall(runtimeInfo, vtGetInterface,
		uintptr(unsafe.Pointer(&clsidCLRRuntimeHost)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeHost)),
		uintptr(unsafe.Pointer(&runtimeHost)),
	); err != nil {
		return 0, fmt.Errorf("GetInterface(ICLRRuntimeHost): %w", err)
	}
	defer comVtCall(runtimeHost, 2) // Release //nolint:errcheck

	// Step 5: Start the CLR.
	if _, err := comVtCall(runtimeHost, vtICLRRuntimeHostStart); err != nil {
		return 0, fmt.Errorf("ICLRRuntimeHost::Start: %w", err)
	}

	// Step 6: ExecuteInDefaultAppDomain(assemblyPath, typeName, methodName, argument, &retVal)
	asmPtr, _ := windows.UTF16PtrFromString(assemblyPath)
	typePtr, _ := windows.UTF16PtrFromString(typeName)
	methPtr, _ := windows.UTF16PtrFromString(methodName)
	argPtr, _ := windows.UTF16PtrFromString(argument)
	var retVal uint32

	if _, err := comVtCall(runtimeHost, vtExecuteInDefaultAppDomain,
		uintptr(unsafe.Pointer(asmPtr)),
		uintptr(unsafe.Pointer(typePtr)),
		uintptr(unsafe.Pointer(methPtr)),
		uintptr(unsafe.Pointer(argPtr)),
		uintptr(unsafe.Pointer(&retVal)),
	); err != nil {
		return 0, fmt.Errorf("ExecuteInDefaultAppDomain: %w", err)
	}

	return int32(retVal), nil
}

// clrGetLatestVersion enumerates installed runtimes and returns the highest version string.
func clrGetLatestVersion(metaHost uintptr) (string, error) {
	// EnumerateInstalledRuntimes = vtable index 5.
	var enumPtr uintptr
	if _, err := comVtCall(metaHost, 5, uintptr(unsafe.Pointer(&enumPtr))); err != nil {
		return "v4.0.30319", nil // fallback: assume .NET 4
	}
	defer comVtCall(enumPtr, 2) //nolint:errcheck

	// IEnumUnknown::Next — vtable index 3.
	var latest [32]uint16
	var elem uintptr
	var fetched uint32
	for {
		r, _, _ := syscall.Syscall15(
			*(*uintptr)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(enumPtr))+3*8)),
			5,
			enumPtr, 1, uintptr(unsafe.Pointer(&elem)), uintptr(unsafe.Pointer(&fetched)), 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		)
		if r != 0 || fetched == 0 {
			break
		}
		// ICLRRuntimeInfo::GetVersionString (vtable 3), buf size via buf=nil first.
		var bufLen uint32 = 32
		syscall.Syscall15( //nolint:errcheck
			*(*uintptr)(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(elem))+3*8)),
			3,
			elem, uintptr(unsafe.Pointer(&latest[0])), uintptr(unsafe.Pointer(&bufLen)), 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		)
		comVtCall(elem, 2) //nolint:errcheck
	}

	if latest[0] == 0 {
		return "v4.0.30319", nil
	}
	return windows.UTF16ToString(latest[:]), nil
}
