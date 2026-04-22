//go:build !windows

package main

import (
	"fmt"
	"time"
)

func timestompFile(targetPath, refPath string, setTime *time.Time) error {
	return fmt.Errorf("timestomping is only supported on Windows")
}
