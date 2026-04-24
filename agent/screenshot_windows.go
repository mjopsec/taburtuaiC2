//go:build windows

package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"unsafe"
)

type BITMAPINFOHEADER struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type BITMAPINFO struct {
	BmiHeader BITMAPINFOHEADER
	BmiColors [1]uint32
}

// acquireDesktopDC tries GetDC(0) first, then falls back to GetWindowDC(GetDesktopWindow()).
// Returns (hDC, releaseFunc, error). Caller must call releaseFunc() to free the DC.
func acquireDesktopDC() (uintptr, func(), error) {
	hDC, _, _ := procGetDC.Call(0)
	if hDC != 0 {
		return hDC, func() { procReleaseDC.Call(0, hDC) }, nil
	}
	// Fallback: GetWindowDC on the desktop window (works in some RDP/headless sessions)
	hwndDesktop, _, _ := procGetDesktopWindow.Call()
	if hwndDesktop != 0 {
		hDC, _, _ = procGetWindowDC.Call(hwndDesktop)
		if hDC != 0 {
			return hDC, func() { procReleaseDC.Call(hwndDesktop, hDC) }, nil
		}
	}
	return 0, func() {}, fmt.Errorf("cannot acquire desktop DC (headless/service session?)")
}

// captureScreen captures the full desktop and returns PNG bytes.
func captureScreen() ([]byte, error) {
	width, _, _ := procGetSystemMetrics.Call(uintptr(smCxscreen))
	height, _, _ := procGetSystemMetrics.Call(uintptr(smCyscreen))
	w, h := int(int32(width)), int(int32(height))
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("invalid screen dimensions: %dx%d (no display attached?)", w, h)
	}

	// Get desktop DC with fallback for RDP/headless sessions
	hDC, releaseHDC, err := acquireDesktopDC()
	if err != nil {
		return nil, err
	}
	defer releaseHDC()

	// Create memory DC
	memDC, _, _ := procCreateCompatibleDC.Call(hDC)
	if memDC == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer procDeleteDC.Call(memDC)

	// Create bitmap
	hBitmap, _, _ := procCreateCompatibleBitmap.Call(hDC, uintptr(w), uintptr(h))
	if hBitmap == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer procDeleteObject.Call(hBitmap)

	// Select bitmap into memory DC
	procSelectObject.Call(memDC, hBitmap)

	// Copy screen content
	r, _, e := procBitBlt.Call(memDC, 0, 0, uintptr(w), uintptr(h), hDC, 0, 0, uintptr(srccopy))
	if r == 0 {
		return nil, fmt.Errorf("BitBlt: %v (session may be headless or locked)", e)
	}

	// Prepare BITMAPINFO for DIB extraction (32-bit BGRA)
	bi := BITMAPINFO{}
	bi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bi.BmiHeader))
	bi.BmiHeader.BiWidth = int32(w)
	bi.BmiHeader.BiHeight = -int32(h) // negative = top-down
	bi.BmiHeader.BiPlanes = 1
	bi.BmiHeader.BiBitCount = 32
	bi.BmiHeader.BiCompression = uint32(biRgb)

	pixels := make([]byte, w*h*4)
	r, _, e = procGetDIBits.Call(
		memDC, hBitmap,
		0, uintptr(h),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bi)),
		uintptr(dibRGBColors),
	)
	if r == 0 {
		return nil, fmt.Errorf("GetDIBits: %v", e)
	}

	// Build Go image (BGRA → RGBA)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			idx := (y*w + x) * 4
			img.SetRGBA(x, y, color.RGBA{
				R: pixels[idx+2],
				G: pixels[idx+1],
				B: pixels[idx+0],
				A: 255,
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("png.Encode: %w", err)
	}
	return buf.Bytes(), nil
}
