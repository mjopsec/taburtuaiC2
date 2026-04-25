// Package evasion provides EDR/AV evasion techniques for the agent implant.
//
// Techniques:
//   - AMSI/ETW byte-patch bypass (patchless HWBP variant preferred)
//   - Hardware breakpoint (HWBP) + VEH handler installation
//   - ntdll.dll in-memory unhooking (fresh disk remap)
//   - Anti-debug and anti-VM detection
//   - Sleep obfuscation is handled by the winsyscall package.
//
// All Windows-specific code is gated behind //go:build windows build tags.
// This package imports winsyscall for direct NT syscall access.
package evasion
