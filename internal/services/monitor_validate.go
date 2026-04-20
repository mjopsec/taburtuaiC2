package services

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// getString safely extracts a non-empty trimmed string from a map
func getString(data map[string]interface{}, key string) (string, bool) {
	v, ok := data[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return strings.TrimSpace(s), true
}

// getInt safely extracts an integer from int, float64, or string map values
func getInt(data map[string]interface{}, key string) (int, bool) {
	v, ok := data[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	case string:
		if i, err := strconv.Atoi(n); err == nil {
			return i, true
		}
	}
	return 0, false
}

// isValidAgentUUID validates UUID v4 format
func isValidAgentUUID(id string) bool {
	r := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	return r.MatchString(strings.ToLower(id))
}

// validateAgentData checks required fields and basic format constraints
func validateAgentData(data map[string]interface{}) error {
	for _, field := range []string{"id", "hostname", "username", "os"} {
		v, ok := data[field]
		if !ok || v == "" {
			return fmt.Errorf("required field '%s' is missing or empty", field)
		}
	}

	if hostname, ok := data["hostname"].(string); ok {
		if len(hostname) > 255 || !isValidHostname(hostname) {
			return fmt.Errorf("invalid hostname: %s", hostname)
		}
	}

	if osName, ok := data["os"].(string); ok {
		valid := map[string]bool{
			"windows": true, "linux": true, "darwin": true,
			"freebsd": true, "openbsd": true, "netbsd": true,
		}
		if !valid[strings.ToLower(osName)] {
			return fmt.Errorf("unsupported OS: %s", osName)
		}
	}
	return nil
}

// isValidHostname checks basic hostname format
func isValidHostname(h string) bool {
	if len(h) == 0 || len(h) > 255 {
		return false
	}
	r := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return r.MatchString(h)
}
