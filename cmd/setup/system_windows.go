//go:build windows

package setup

import (
	"errors"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/safedep/pmg/internal/winacl"
)

var setupIsElevated = winacl.ProcessIsElevated

// requireSystemPrivilege needs UAC elevation. Program Files and the machine
// PATH are writable by administrators only.
func requireSystemPrivilege() error {
	if setupIsElevated() {
		return nil
	}
	return usefulerror.NewUsefulError().
		WithCode(errcodes.PermissionDenied).
		WithHumanError("system install requires an administrator").
		WithHelp("Re-run `pmg setup install --system` from a terminal started as administrator").
		Wrap(errors.New("not elevated"))
}
