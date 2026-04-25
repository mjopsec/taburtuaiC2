package exec

import (
	"fmt"
	"time"
)

// TimeGate holds working-hours and kill-date configuration.
type TimeGate struct {
	WorkStart int
	WorkEnd   int
	KillDate  string
}

// IsActive returns true if execution should proceed according to the time gate.
func (tg *TimeGate) IsActive() (bool, string) {
	now := time.Now().Local()

	if tg.KillDate != "" {
		kd, err := parseDate(tg.KillDate)
		if err == nil && now.After(kd) {
			return false, fmt.Sprintf("kill date %s passed — terminating", tg.KillDate)
		}
	}

	if tg.WorkStart >= 0 && tg.WorkEnd >= 0 {
		h := now.Hour()
		if tg.WorkStart < tg.WorkEnd {
			if h < tg.WorkStart || h >= tg.WorkEnd {
				return false, fmt.Sprintf("outside working hours (%02d:xx–%02d:xx)", tg.WorkStart, tg.WorkEnd)
			}
		} else {
			if h < tg.WorkStart && h >= tg.WorkEnd {
				return false, fmt.Sprintf("outside working hours (%02d:xx–%02d:xx)", tg.WorkStart, tg.WorkEnd)
			}
		}
	}

	return true, ""
}

// SleepUntilActive blocks until the time gate allows execution.
func (tg *TimeGate) SleepUntilActive() error {
	for {
		ok, reason := tg.IsActive()
		if ok {
			return nil
		}
		if tg.KillDate != "" {
			kd, err := parseDate(tg.KillDate)
			if err == nil && time.Now().After(kd) {
				return fmt.Errorf("kill date reached: %s", reason)
			}
		}
		time.Sleep(time.Minute)
	}
}

func parseDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unparseable date: %s", s)
}
