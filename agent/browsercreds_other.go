//go:build !windows

package main

import "fmt"

type BrowserCred struct {
	Browser  string `json:"browser"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func BrowserCredsAll() ([]BrowserCred, error) {
	return nil, fmt.Errorf("browser credential harvesting is Windows-only")
}
