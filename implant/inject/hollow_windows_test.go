//go:build windows

package inject

import (
	"encoding/binary"
	"testing"
)

// buildRelocBlock builds a minimal IMAGE_BASE_RELOCATION block at pageRVA
// containing one DIR64 (type 10) entry at given offset within the page.
func buildRelocBlock(pageRVA uint32, offsetInPage uint16) []byte {
	// Block layout: pageRVA(4) + blockSize(4) + entry(2)
	block := make([]byte, 10)
	binary.LittleEndian.PutUint32(block[0:], pageRVA)
	binary.LittleEndian.PutUint32(block[4:], 10) // 8 header + 2 entry
	entry := (uint16(10) << 12) | (offsetInPage & 0x0FFF)
	binary.LittleEndian.PutUint16(block[8:], entry)
	return block
}

func TestHollowApplyRelocs_NoDelta(t *testing.T) {
	const imageSize = 0x1000
	staging := make([]byte, imageSize)

	// Put a sentinel value at offset 0x100.
	const patchOff = 0x100
	const sentinel uint64 = 0xDEADBEEFCAFEBABE
	binary.LittleEndian.PutUint64(staging[patchOff:], sentinel)

	block := buildRelocBlock(0, patchOff)
	copy(staging[0x800:], block)

	hollowApplyRelocs(staging, 0x800, uint32(len(block)), 0) // delta = 0

	got := binary.LittleEndian.Uint64(staging[patchOff:])
	if got != sentinel {
		t.Errorf("with delta=0: value changed from %X to %X", sentinel, got)
	}
}

func TestHollowApplyRelocs_PositiveDelta(t *testing.T) {
	const imageSize = 0x2000
	staging := make([]byte, imageSize)

	const patchOff = 0x200
	const original uint64 = 0x0000000140001000
	binary.LittleEndian.PutUint64(staging[patchOff:], original)

	const delta int64 = 0x10000
	block := buildRelocBlock(0, patchOff)
	copy(staging[0x1000:], block)

	hollowApplyRelocs(staging, 0x1000, uint32(len(block)), delta)

	got := binary.LittleEndian.Uint64(staging[patchOff:])
	want := original + uint64(delta)
	if got != want {
		t.Errorf("positive delta: got %X, want %X", got, want)
	}
}

func TestHollowApplyRelocs_NegativeDelta(t *testing.T) {
	const imageSize = 0x2000
	staging := make([]byte, imageSize)

	const patchOff = 0x300
	const original uint64 = 0x0000000180002000
	binary.LittleEndian.PutUint64(staging[patchOff:], original)

	const delta int64 = -0x40000000
	block := buildRelocBlock(0, patchOff)
	copy(staging[0x1000:], block)

	hollowApplyRelocs(staging, 0x1000, uint32(len(block)), delta)

	got := binary.LittleEndian.Uint64(staging[patchOff:])
	want := uint64(int64(original) + delta)
	if got != want {
		t.Errorf("negative delta: got %X, want %X", got, want)
	}
}

func TestHollowApplyRelocs_SkipsNonDIR64(t *testing.T) {
	const imageSize = 0x1000
	staging := make([]byte, imageSize)

	const patchOff = 0x100
	const sentinel uint64 = 0x1111222233334444
	binary.LittleEndian.PutUint64(staging[patchOff:], sentinel)

	// Build a block with entry type=3 (ADDR32NB), not DIR64 (10).
	block := make([]byte, 10)
	binary.LittleEndian.PutUint32(block[0:], 0)
	binary.LittleEndian.PutUint32(block[4:], 10)
	entry := (uint16(3) << 12) | uint16(patchOff)
	binary.LittleEndian.PutUint16(block[8:], entry)
	copy(staging[0x800:], block)

	hollowApplyRelocs(staging, 0x800, uint32(len(block)), 0x10000)

	got := binary.LittleEndian.Uint64(staging[patchOff:])
	if got != sentinel {
		t.Errorf("non-DIR64 entry was patched: got %X, want %X", got, sentinel)
	}
}

func TestHollowApplyRelocs_MultipleBlocks(t *testing.T) {
	const imageSize = 0x3000
	staging := make([]byte, imageSize)

	const delta int64 = 0x5000
	const base1 = 0x100
	const base2 = 0x200
	const val1 uint64 = 0x0000000140000000
	const val2 uint64 = 0x0000000140001000

	binary.LittleEndian.PutUint64(staging[base1:], val1)
	binary.LittleEndian.PutUint64(staging[base2:], val2)

	// Two consecutive blocks, each at page 0 but different offsets.
	var relocs []byte
	relocs = append(relocs, buildRelocBlock(0, base1)...)
	relocs = append(relocs, buildRelocBlock(0, base2)...)
	copy(staging[0x2000:], relocs)

	hollowApplyRelocs(staging, 0x2000, uint32(len(relocs)), delta)

	if got, want := binary.LittleEndian.Uint64(staging[base1:]), val1+uint64(delta); got != want {
		t.Errorf("block1: got %X want %X", got, want)
	}
	if got, want := binary.LittleEndian.Uint64(staging[base2:]), val2+uint64(delta); got != want {
		t.Errorf("block2: got %X want %X", got, want)
	}
}
