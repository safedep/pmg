//go:build windows

package proxyserver

import (
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
)

func Daemonize(_ ProxyDaemonConfig, _, _ string, _ []string) (State, error) {
	return State{}, usefulerror.NewUsefulError().
		WithCode(errcodes.UnsupportedPlatform).
		WithMsg("pmg proxy start --daemon is not supported on Windows").
		WithHelp("Run 'pmg proxy start' in the foreground instead")
}
