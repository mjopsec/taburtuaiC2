// Package pivot provides network pivoting capabilities for the agent implant.
//
// Features:
//   - SOCKS5 proxy server (agent acts as SOCKS5 over C2 channel)
//   - TCP port forwarding (agent-side listener → target:port)
//
// No winsyscall dependency; pure Go networking.
package pivot
