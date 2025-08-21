package version

import (
	"fmt"
	"os"

	"github.com/safedep/pmg/internal/ui"
	"github.com/safedep/pmg/internal/version"
	"github.com/spf13/cobra"
)

func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version and build information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(ui.GeneratePMGBanner(version.Version, version.Commit))

			fmt.Fprintf(os.Stdout, "Version: %s\n", version.Version)
			fmt.Fprintf(os.Stdout, "CommitSHA: %s\n", version.Commit)

			return nil
		},
	}
}
