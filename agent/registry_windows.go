//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// resolveHive maps hive name strings to registry.Key constants.
func resolveHive(hive string) (registry.Key, error) {
	switch strings.ToUpper(hive) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return registry.CLASSES_ROOT, nil
	case "HKU", "HKEY_USERS":
		return registry.USERS, nil
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, fmt.Errorf("unknown hive: %q", hive)
	}
}

// RegRead reads a single registry value and returns it as a string.
func RegRead(hive, key, value string) (string, error) {
	h, err := resolveHive(hive)
	if err != nil {
		return "", err
	}
	k, err := registry.OpenKey(h, key, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("open %s\\%s: %w", hive, key, err)
	}
	defer k.Close()

	s, _, err := k.GetStringValue(value)
	if err == nil {
		return s, nil
	}
	// Try DWORD
	d, _, err2 := k.GetIntegerValue(value)
	if err2 == nil {
		return fmt.Sprintf("%d", d), nil
	}
	// Try binary
	b, _, err3 := k.GetBinaryValue(value)
	if err3 == nil {
		return fmt.Sprintf("%X", b), nil
	}
	return "", fmt.Errorf("read value %q: %w", value, err)
}

// RegWrite writes a registry value. kind: "sz" | "dword" | "binary" | "expand_sz" | "multi_sz"
func RegWrite(hive, key, value, data, kind string) error {
	h, err := resolveHive(hive)
	if err != nil {
		return err
	}
	k, _, err := registry.CreateKey(h, key, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("create/open %s\\%s: %w", hive, key, err)
	}
	defer k.Close()

	switch strings.ToLower(kind) {
	case "sz", "string", "":
		return k.SetStringValue(value, data)
	case "expand_sz":
		return k.SetExpandStringValue(value, data)
	case "multi_sz":
		parts := strings.Split(data, "|")
		return k.SetStringsValue(value, parts)
	case "dword":
		var d uint64
		fmt.Sscanf(data, "%d", &d)
		return k.SetDWordValue(value, uint32(d))
	case "qword":
		var q uint64
		fmt.Sscanf(data, "%d", &q)
		return k.SetQWordValue(value, q)
	default:
		return fmt.Errorf("unknown type %q (use: sz, dword, qword, expand_sz, multi_sz)", kind)
	}
}

// RegDelete deletes a registry value (or key if value is "").
func RegDelete(hive, key, value string) error {
	h, err := resolveHive(hive)
	if err != nil {
		return err
	}
	if value == "" {
		return registry.DeleteKey(h, key)
	}
	k, err := registry.OpenKey(h, key, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s\\%s: %w", hive, key, err)
	}
	defer k.Close()
	return k.DeleteValue(value)
}

// RegList enumerates subkeys and values under a registry key.
func RegList(hive, key string) ([]string, error) {
	h, err := resolveHive(hive)
	if err != nil {
		return nil, err
	}
	k, err := registry.OpenKey(h, key, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("open %s\\%s: %w", hive, key, err)
	}
	defer k.Close()

	var out []string

	subkeys, err := k.ReadSubKeyNames(-1)
	if err == nil {
		for _, s := range subkeys {
			out = append(out, "[KEY] "+s)
		}
	}

	values, err := k.ReadValueNames(-1)
	if err == nil {
		for _, v := range values {
			s, _, e := k.GetStringValue(v)
			if e == nil {
				out = append(out, fmt.Sprintf("[VAL] %s = %q", v, s))
				continue
			}
			d, _, e := k.GetIntegerValue(v)
			if e == nil {
				out = append(out, fmt.Sprintf("[VAL] %s = %d", v, d))
				continue
			}
			out = append(out, fmt.Sprintf("[VAL] %s = (binary)", v))
		}
	}

	return out, nil
}
