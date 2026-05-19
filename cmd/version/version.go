package version

import (
	"fmt"
	"os"

	"github.com/safedep/dry/log"
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

			if _, err := fmt.Fprintf(os.Stdout, "Version: %s\n", version.Version); err != nil {
				log.Warnf("failed to write version line: %v", err)
			}
			if _, err := fmt.Fprintf(os.Stdout, "CommitSHA: %s\n", version.Commit); err != nil {
				log.Warnf("failed to write commit line: %v", err)
			}

			return nil
		},
	}
}
