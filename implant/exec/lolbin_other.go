//go:build !windows

package exec

import "fmt"

func LolbinFetch(url, localPath, method string) error {
	return fmt.Errorf("lolbin_fetch is only supported on Windows (got method=%q)", method)
}
