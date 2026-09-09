//go:build !windows

package shim

import (
	"fmt"
	"os"
	"strings"

	"github.com/safedep/dry/log"
)

// ShimFileName is the shim file for a package manager.
func ShimFileName(pm string) string { return pm }

func shimScript(pmgBin, pm string) string {
	return fmt.Sprintf(`#!/bin/sh
%[1]s
%[2]s=%[3]s
if [ ! -x "$%[2]s" ]; then
  echo "[pmg] error: PMG binary not found or not executable: $%[2]s" >&2
  echo "[pmg] error: run 'pmg setup install' again or remove shims with 'pmg setup remove'" >&2
  exit 127
fi
PMG_SHIM_PATH=$(cd -- "$(dirname -- "$0")" && pwd)/$(basename -- "$0")
export PMG_SHIM_PATH
exec "$%[2]s" %[4]s "$@"
`, shimScriptMarker, shimPMGBinVar, shellQuote(pmgBin), pm)
}

// The shim directory reaches PATH through each shell's rc file.
func (m *ShimManager) installPath() error { return m.addPathToShells() }

func (m *ShimManager) removePath() error { return m.removePathFromShells() }

func (m *ShimManager) pathInstalled() (bool, error) {
	for _, shell := range m.config.Shells {
		for _, configPath := range shell.CandidateRcFiles(m.config.HomeDir) {
			data, err := os.ReadFile(configPath)
			if err != nil {
				if os.IsNotExist(err) {
					continue
				}
				log.Warnf("Warning: could not read %s (%s)", configPath, err)
				continue
			}

			if strings.Contains(string(data), shimMarker) {
				return true, nil
			}
		}
	}

	return false, nil
}
