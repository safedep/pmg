//go:build windows

package platform

import "os"

func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	return 0, false
}
