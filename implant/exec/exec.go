// Package exec provides execution primitives for the agent implant.
//
// Techniques:
//   - Shell command execution (cmd.exe / PowerShell)
//   - BOF (Beacon Object File) loader — runs COFF .o in-process
//   - .NET / CLR in-memory hosting (CLRCreateInstance)
//   - PowerShell runspace (IPC via named pipe)
//   - LOLBin execution helpers (certutil, mshta, wmic, etc.)
//   - Alternate Data Stream (ADS) write + execute
//   - PE reflective loader
//   - Token / privilege manipulation
//   - Timegate / OPSEC scheduling
//
// Mixed dependency: BOF/peloader use winsyscall; shell/lolbin use exec.Command.
package exec
