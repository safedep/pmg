//go:build windows

package shim

import "os"

func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	return 0, false
}
