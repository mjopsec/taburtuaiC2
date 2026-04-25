// Package inject provides process injection techniques for the agent implant.
//
// Techniques:
//   - Classic remote thread (CRT) injection
//   - APC queue injection
//   - Process hollowing
//   - Thread hijacking
//   - Module stomping
//   - Section-mapped injection (NtCreateSection/NtMapViewOfSection)
//   - PPID spoofing (CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)
//   - Threadless injection
//
// All Windows-specific code is gated behind //go:build windows build tags.
package inject
