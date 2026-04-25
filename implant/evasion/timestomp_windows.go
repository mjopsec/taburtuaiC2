//go:build windows

package evasion

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// TimestompFile changes the timestamps of targetPath.
// If refPath is set, copies from that file. If setTime is set, applies that time.
// Default reference: C:\Windows\System32\kernel32.dll
func TimestompFile(targetPath, refPath string, setTime *time.Time) error {
	var ctime, atime, mtime windows.Filetime

	switch {
	case refPath != "":
		var err error
		ctime, atime, mtime, err = readFileTimes(refPath)
		if err != nil {
			return fmt.Errorf("read ref timestamps: %w", err)
		}
	case setTime != nil:
		ft := windows.NsecToFiletime(setTime.UnixNano())
		ctime, atime, mtime = ft, ft, ft
	default:
		var err error
		ctime, atime, mtime, err = readFileTimes(`C:\Windows\System32\kernel32.dll`)
		if err != nil {
			return fmt.Errorf("read default ref: %w", err)
		}
	}

	return writeFileTimes(targetPath, ctime, atime, mtime)
}

func readFileTimes(path string) (ctime, atime, mtime windows.Filetime, err error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return ctime, atime, mtime, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if e != nil {
		return ctime, atime, mtime, fmt.Errorf("open %q: %w", path, e)
	}
	defer windows.CloseHandle(h)
	e = windows.GetFileTime(h, &ctime, &atime, &mtime)
	return ctime, atime, mtime, e
}

func writeFileTimes(path string, ctime, atime, mtime windows.Filetime) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fmt.Errorf("open %q for write: %w", path, err)
	}
	defer windows.CloseHandle(h)
	return windows.SetFileTime(h, &ctime, &atime, &mtime)
}
