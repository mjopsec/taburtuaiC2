//go:build !windows

package main

import "fmt"

func dotnetExecute(assemblyPath, typeName, methodName, argument string) (int32, error) {
	return 0, fmt.Errorf("dotnetExecute is Windows-only")
}
