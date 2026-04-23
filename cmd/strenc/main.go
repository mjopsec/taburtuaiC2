// strenc — compile-time string encryption helper.
// Usage: strenc enc <string> <hex-key-byte>
//        strenc dec <hex-string> <hex-key-byte>
// Example: strenc enc "http://192.168.1.10:8080" 5a
//          → prints the hex-encrypted string for use in ldflags
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/mjopsec/taburtuaiC2/pkg/strenc"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: strenc <enc|dec> <string> <hex-key-byte>\n")
		fmt.Fprintf(os.Stderr, "  enc: encrypt plaintext → hex output\n")
		fmt.Fprintf(os.Stderr, "  dec: decrypt hex input  → plaintext output\n")
		fmt.Fprintf(os.Stderr, "example: strenc enc \"http://c2.example.com\" 5a\n")
		os.Exit(1)
	}

	op := os.Args[1]
	input := os.Args[2]
	keyHex := os.Args[3]

	keyVal, err := strconv.ParseUint(keyHex, 16, 8)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid key byte %q — must be 2-digit hex (00–ff)\n", keyHex)
		os.Exit(1)
	}
	key := byte(keyVal)

	switch op {
	case "enc":
		fmt.Print(strenc.Enc(input, key))
	case "dec":
		result := strenc.Dec(input, key)
		if result == "" {
			fmt.Fprintf(os.Stderr, "[-] Decode failed — invalid hex string\n")
			os.Exit(1)
		}
		fmt.Print(result)
	default:
		fmt.Fprintf(os.Stderr, "[-] Unknown operation %q — use enc or dec\n", op)
		os.Exit(1)
	}
}
