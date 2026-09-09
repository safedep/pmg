//go:build windows

package shim

import (
	"fmt"
	"strings"
)

// A .cmd file is what every caller that applies PATHEXT finds: cmd.exe,
// PowerShell and Go's exec.LookPath.
func shimFileName(pm string) string { return pm + ".cmd" }

// shimScript is the batch body. setlocal alone inherits delayed expansion
// from the caller, which would make !NAME! expand inside the captured tail,
// so DisableDelayedExpansion is explicit. PMG_RAW_ARGS carries the argument
// tail byte for byte so PMG can replay it to cmd.exe without a second
// serialisation. The marker sits in a rem line so shimsPresent finds it.
func shimScript(pmgBin, pm string) string {
	lines := []string{
		"@echo off",
		"rem " + shimScriptMarker,
		"setlocal DisableDelayedExpansion",
		`set "PMG_SHIM_PATH=%~f0"`,
		`set "PMG_RAW_ARGS=%*"`,
		fmt.Sprintf(`"%s" %s %%*`, batchEscape(pmgBin), pm),
		"exit /b %ERRORLEVEL%",
		"",
	}
	return strings.Join(lines, "\r\n")
}

// batchEscape keeps a literal percent sign in a batch file, where a bare
// one starts a variable expansion.
func batchEscape(value string) string {
	return strings.ReplaceAll(value, "%", "%%")
}

// The shim directory reaches PATH through HKCU\Environment, which every new
// shell reads.
func (m *ShimManager) installPath() error { return registerUserPath(m.config.BinDir) }

func (m *ShimManager) removePath() error { return unregisterUserPath(m.config.BinDir) }

func (m *ShimManager) pathInstalled() (bool, error) { return userPathContains(m.config.BinDir) }
