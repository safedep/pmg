//go:build !windows

package setup

import (
	"errors"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

func requireSystemPrivilege() error {
	if setupGeteuid() == 0 {
		return nil
	}
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError("system install requires root").
		WithHelp("Re-run as root, e.g. `sudo pmg setup install --system`").
		Wrap(errors.New("not root"))
}
