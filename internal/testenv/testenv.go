// Package testenv prepares the environment of a test binary.
package testenv

import (
	"os"
	"testing"
)

// Main runs the tests of a package without PMG_STATE_DIR. A test that sets
// only PMG_CONFIG_DIR expects every file under that directory. An exported
// PMG_STATE_DIR would send the logs, the cloud queue and the policy cache of
// the test into the state directory of the developer or the CI runner.
// Package init loads the config before Main runs, so Main calls reload after
// it clears the variable.
func Main(m *testing.M, reload func()) {
	if err := os.Unsetenv("PMG_STATE_DIR"); err != nil {
		panic(err)
	}
	reload()
	os.Exit(m.Run())
}
