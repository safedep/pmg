//go:build windows

package proxyserver

import (
	"errors"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

func Daemonize(_ ProxyDaemonConfig, _, _ string, _ []string) (State, error) {
	return State{}, usefulerror.NewUsefulError().
		WithCode(errcodes.UnsupportedPlatform).
		WithHumanError("pmg proxy start --daemon is not supported on Windows").
		WithHelp("Run 'pmg proxy start' in the foreground instead").
		Wrap(errors.New("daemon mode is not supported on windows"))
}
