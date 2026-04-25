//go:build windows

package exec

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// ─── bofSprintf ───────────────────────────────────────────────────────────────

func cstr(s string) uintptr {
	b := append([]byte(s), 0)
	return uintptr(unsafe.Pointer(&b[0]))
}

func TestBofSprintf(t *testing.T) {
	tests := []struct {
		name   string
		format string
		args   []uintptr
		want   string
	}{
		{"no args", "hello world", nil, "hello world"},
		{"percent literal", "100%%", nil, "100%"},
		{"string", "%s", []uintptr{cstr("beacon")}, "beacon"},
		{"decimal", "%d", []uintptr{42}, "42"},
		{"decimal negative", "%d", []uintptr{^uintptr(0) & 0xFFFFFFFF}, "-1"},
		{"unsigned", "%u", []uintptr{4294967295}, "4294967295"},
		{"hex lower", "%x", []uintptr{255}, "ff"},
		{"hex upper", "%X", []uintptr{255}, "FF"},
		{"pointer", "%p", []uintptr{0xDEAD}, "0xDEAD"},
		{"long decimal", "%ld", []uintptr{1234567890}, "1234567890"},
		{"long hex", "%lx", []uintptr{0xABCD}, "abcd"},
		{"mixed", "pid=%d name=%s", []uintptr{1337, cstr("svchost")}, "pid=1337 name=svchost"},
		{"unknown spec passthrough", "%q", []uintptr{0}, "%q"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bofSprintf(tt.format, tt.args...)
			if got != tt.want {
				t.Errorf("bofSprintf(%q, ...) = %q, want %q", tt.format, got, tt.want)
			}
		})
	}
}

// ─── BeaconData cursor ────────────────────────────────────────────────────────

// packInt packs a little-endian int32 into a byte slice (matches BOF arg format).
func packInt(v int32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b
}

func packShort(v int16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(v))
	return b
}

func packBlob(data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(b, uint32(len(data)))
	copy(b[4:], data)
	return b
}

func TestBeaconDataInt(t *testing.T) {
	buf := packInt(12345678)
	buf = append(buf, packInt(-99)...)

	var p dataBOF
	beaconDataParse(&p, &buf[0], int32(len(buf)))

	if got := beaconDataInt(&p); got != 12345678 {
		t.Errorf("first int: got %d, want 12345678", got)
	}
	if got := beaconDataInt(&p); got != -99 {
		t.Errorf("second int: got %d, want -99", got)
	}
	if got := beaconDataLength(&p); got != 0 {
		t.Errorf("remaining length: got %d, want 0", got)
	}
}

func TestBeaconDataShort(t *testing.T) {
	buf := packShort(1000)
	buf = append(buf, packShort(-32768)...)

	var p dataBOF
	beaconDataParse(&p, &buf[0], int32(len(buf)))

	if got := beaconDataShort(&p); got != 1000 {
		t.Errorf("first short: got %d, want 1000", got)
	}
	if got := beaconDataShort(&p); got != -32768 {
		t.Errorf("second short: got %d, want -32768", got)
	}
}

func TestBeaconDataExtract(t *testing.T) {
	payload := []byte("ICSSI\x00C2\x00")
	buf := packBlob(payload)

	var p dataBOF
	beaconDataParse(&p, &buf[0], int32(len(buf)))

	var size int32
	ptr := beaconDataExtract(&p, &size)
	if ptr == nil {
		t.Fatal("beaconDataExtract returned nil")
	}
	if int(size) != len(payload) {
		t.Errorf("size: got %d, want %d", size, len(payload))
	}
	got := unsafe.Slice(ptr, size)
	for i, b := range payload {
		if got[i] != b {
			t.Errorf("byte[%d]: got %02x, want %02x", i, got[i], b)
		}
	}
	if beaconDataLength(&p) != 0 {
		t.Errorf("remaining after extract: %d", beaconDataLength(&p))
	}
}

func TestBeaconDataMixed(t *testing.T) {
	// Pack: int32(7) + blob("hi") + short(3)
	var buf []byte
	buf = append(buf, packInt(7)...)
	buf = append(buf, packBlob([]byte("hi"))...)
	buf = append(buf, packShort(3)...)

	var p dataBOF
	beaconDataParse(&p, &buf[0], int32(len(buf)))

	if v := beaconDataInt(&p); v != 7 {
		t.Errorf("int: got %d", v)
	}
	var sz int32
	ptr := beaconDataExtract(&p, &sz)
	if ptr == nil || sz != 2 {
		t.Errorf("extract: ptr=%v sz=%d", ptr, sz)
	}
	if v := beaconDataShort(&p); v != 3 {
		t.Errorf("short: got %d", v)
	}
}

func TestBeaconDataUnderflow(t *testing.T) {
	buf := packInt(1) // 4 bytes — not enough for another int32
	var p dataBOF
	beaconDataParse(&p, &buf[0], int32(len(buf)))
	beaconDataInt(&p) // consume it

	// These should return zero-values, not panic.
	if v := beaconDataInt(&p); v != 0 {
		t.Errorf("underflow int: got %d, want 0", v)
	}
	if v := beaconDataShort(&p); v != 0 {
		t.Errorf("underflow short: got %d, want 0", v)
	}
	if ptr := beaconDataExtract(&p, nil); ptr != nil {
		t.Errorf("underflow extract: got non-nil ptr")
	}
}
