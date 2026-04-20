package main

import "fmt"

const version = "2.0.0"

func printBanner() {
	C   := ColorCyan
	R   := ColorRed
	Y   := ColorYellow
	W   := ColorWhite
	D   := "\033[2m"
	B   := "\033[1m"
	rst := ColorReset

	fmt.Println()
	// TABUR (cyan)
	fmt.Println(B + C + "  ▀█▀ ▄▀█ █▄▄ █ █ █▀█" + rst)
	fmt.Println(B + C + "  ░█░ █▀█ █▄█ █▄█ █▀▄" + rst)
	// TUAI C2 (red)
	fmt.Println(B + R + "  ▀█▀ █ █ ▄▀█ █  █▀▀ ▀▀█" + rst)
	fmt.Println(B + R + "  ░█░ █▄█ █▀█ █  █▄▄ ▄▄▀" + rst)
	fmt.Println()
	fmt.Println("  " + D + "author" + rst + "  " + W + B + "mjopsec" + rst +
		"   " + D + "version" + rst + "  " + Y + B + version + rst)
	fmt.Println()
}
