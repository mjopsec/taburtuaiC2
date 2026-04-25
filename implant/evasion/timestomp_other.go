//go:build !windows

package evasion

import (
	"fmt"
	"time"
)

func TimestompFile(_, _ string, _ *time.Time) error {
	return fmt.Errorf("timestomping is Windows-only")
}
