// Package persist provides persistence establishment techniques for the agent implant.
//
// Mechanisms:
//   - HKCU/HKLM Run registry keys
//   - Scheduled task (schtasks.exe)
//   - Service creation (OpenSCManager/CreateService)
//   - Startup folder LNK/copy
//
// Does not depend on winsyscall; all techniques use exec.Command or registry APIs.
package persist
