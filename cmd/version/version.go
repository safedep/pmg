package version

import (
	"fmt"
	"os"
	runtimeDebug "runtime/debug"

	"github.com/spf13/cobra"
)

var (
	version string
	commit  string
)

func init() {
	if version == "" {
		buildInfo, _ := runtimeDebug.ReadBuildInfo()
		version = buildInfo.Main.Version
	}
}

func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version and build information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stdout, "Version: %s\n", version)
			fmt.Fprintf(os.Stdout, "CommitSHA: %s\n", commit)

			return nil
		},
	}
}
