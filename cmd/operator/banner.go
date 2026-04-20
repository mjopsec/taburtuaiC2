package main

import (
	"fmt"
	"runtime"
	"time"
)

const version = "2.0.0"
const phase = "2 — Core Operations"

func printBanner() {
	R := ColorRed
	C := ColorCyan
	Y := ColorYellow
	G := ColorGreen
	P := ColorPurple
	W := ColorWhite
	D := "\033[2m"   // dim
	B := "\033[1m"   // bold
	rst := ColorReset

	fmt.Println()

	// ── TABUR (top half of name) ─────────────────────────────────────────
	fmt.Println(B + C + "  ████████╗ █████╗  ██████╗  ██╗   ██╗ ██████╗ " + rst)
	fmt.Println(B + C + "  ╚══██╔══╝██╔══██╗ ██╔══██╗ ██║   ██║ ██╔══██╗" + rst)
	fmt.Println(B + C + "     ██║   ███████║ ██████╔╝ ██║   ██║ ██████╔╝ " + rst)
	fmt.Println(B + C + "     ██║   ██╔══██║ ██╔══██╗ ██║   ██║ ██╔══██╗ " + rst)
	fmt.Println(B + C + "     ██║   ██║  ██║ ██████╔╝ ╚██████╔╝ ██║  ██║ " + rst)
	fmt.Println(B + C + "     ╚═╝   ╚═╝  ╚═╝ ╚═════╝   ╚═════╝  ╚═╝  ╚═╝ " + rst)

	// ── TUAI C2 (bottom half — red to signal aggression) ──────────────────
	fmt.Println(B + R + "  ████████╗ ██╗   ██╗  █████╗  ██╗    ██████╗ ██████╗  " + rst)
	fmt.Println(B + R + "  ╚══██╔══╝ ██║   ██║ ██╔══██╗ ██║   ██╔════╝╚════██╗ " + rst)
	fmt.Println(B + R + "     ██║    ██║   ██║ ███████║ ██║   ██║      █████╔╝  " + rst)
	fmt.Println(B + R + "     ██║    ╚██╗ ██╔╝ ██╔══██║ ██║   ██║     ██╔═══╝   " + rst)
	fmt.Println(B + R + "     ██║     ╚████╔╝  ██║  ██║ ███████╗╚██████╗███████╗ " + rst)
	fmt.Println(B + R + "     ╚═╝      ╚═══╝   ╚═╝  ╚═╝ ╚══════╝ ╚═════╝╚══════╝" + rst)

	fmt.Println()

	// ── Separator ─────────────────────────────────────────────────────────
	fmt.Println(D + "  ╔══════════════════════════════════════════════════════════╗" + rst)

	// ── Info block ────────────────────────────────────────────────────────
	fmt.Printf(D+"  ║"+rst+"  "+Y+"%-12s"+rst+" %-22s"+
		Y+"%-10s"+rst+" %-14s"+
		D+"║"+rst+"\n",
		"Author", W+B+"mjopsec"+rst,
		"Version", W+B+version+rst)

	fmt.Printf(D+"  ║"+rst+"  "+Y+"%-12s"+rst+" %-22s"+
		Y+"%-10s"+rst+" %-14s"+
		D+"║"+rst+"\n",
		"Framework", W+"C2 Red Team"+rst,
		"Phase", G+phase+rst)

	fmt.Printf(D+"  ║"+rst+"  "+Y+"%-12s"+rst+" %-22s"+
		Y+"%-10s"+rst+" %-14s"+
		D+"║"+rst+"\n",
		"Platform", W+runtime.GOOS+"/"+runtime.GOARCH+rst,
		"Date", W+time.Now().Format("2006-01-02")+rst)

	fmt.Printf(D+"  ║"+rst+"  "+Y+"%-12s"+rst+" %-22s"+
		Y+"%-10s"+rst+" %-14s"+
		D+"║"+rst+"\n",
		"Language", W+"Go "+runtime.Version()[2:]+rst,
		"License", W+"MIT"+rst)

	fmt.Println(D + "  ╠══════════════════════════════════════════════════════════╣" + rst)

	fmt.Printf(D+"  ║"+rst+"  "+P+
		"  For authorized red team engagements only.              "+
		rst+D+"║"+rst+"\n")
	fmt.Printf(D+"  ║"+rst+"  "+P+
		"  Unauthorized access is illegal and unethical.          "+
		rst+D+"║"+rst+"\n")

	fmt.Println(D + "  ╚══════════════════════════════════════════════════════════╝" + rst)
	fmt.Println()
}
