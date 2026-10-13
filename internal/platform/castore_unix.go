//go:build darwin || linux

package platform

import "github.com/safedep/dry/log"

// runElevated prefixes sudo unless the process is root, so only the system
// trust store write is elevated.
func runElevated(name string, args ...string) ([]byte, error) {
	if !IsPrivileged() {
		log.Infof("Elevating via sudo to modify the system trust store")
		return commandRunner("sudo", append([]string{name}, args...)...)
	}
	return commandRunner(name, args...)
}
