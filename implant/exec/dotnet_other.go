//go:build !windows

package exec

import "fmt"

func DotnetExecute(assemblyPath, typeName, methodName, argument string) (int32, error) {
	return 0, fmt.Errorf("DotnetExecute is Windows-only")
}
