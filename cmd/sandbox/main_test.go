package sandbox

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
)

func TestMain(m *testing.M) {
	oldErrorExit := sandboxErrorExit
	sandboxErrorExit = func(cmd *cobra.Command, err error) error {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		return err
	}
	code := m.Run()
	sandboxErrorExit = oldErrorExit
	os.Exit(code)
}
