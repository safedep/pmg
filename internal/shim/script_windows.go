//go:build windows

package shim

import (
	"fmt"
	"strings"
)

// A .cmd file is what every caller that applies PATHEXT finds: cmd.exe,
// PowerShell and Go's exec.LookPath.
func shimFileName(pm string) string { return pm + ".cmd" }

// parseShimBinary reads the pmg path out of the launch line, the one line
// that starts with a quote. A substring search over the whole body would
// match inside the echo line and would reject a path that differs only in
// separator or case, which fsutil.SamePath accepts.
func parseShimBinary(content string) (string, bool) {
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		end := strings.Index(line[1:], `"`)
		if end < 0 {
			return "", false
		}
		// writeShimScript doubled every percent sign in the path.
		return strings.ReplaceAll(line[1:1+end], "%%", "%"), true
	}
	return "", false
}

// shimScript is the batch body. setlocal alone inherits delayed expansion
// from the caller, which would make !NAME! expand inside the captured tail,
// so DisableDelayedExpansion is explicit. PMG_RAW_ARGS carries the argument
// tail byte for byte so PMG can replay it to cmd.exe without a second
// serialisation. The marker sits in a rem line so shimsPresent finds it.
func shimScript(pmgBin, pm string) string {
	bin := batchEscape(pmgBin)
	lines := []string{
		"@echo off",
		"rem " + shimScriptMarker,
		"setlocal DisableDelayedExpansion",
		// The paths in the echo lines are quoted. cmd.exe reads the whole
		// `( ... )` block before it runs the `if`. An unquoted `)` in a path
		// such as `Program Files (x86)` would end the block early, and an
		// unquoted `&` would start a second command. Inside double quotes
		// both characters are plain text.
		fmt.Sprintf(`if not exist "%s" (`, bin),
		fmt.Sprintf(`  echo [pmg] error: PMG binary not found: "%s" 1>&2`, bin),
		`  echo [pmg] error: reinstall PMG and run 'pmg setup install', or delete "%~dp0" to remove the shims 1>&2`,
		"  exit /b 127",
		")",
		fmt.Sprintf(`set "%s=%%~f0"`, pmgShimPathEnv),
		// The value is not wrapped in quotes on purpose. cmd.exe flips an
		// "inside quotes" flag at every double quote, and the characters
		// `>`, `<`, `&` and `|` act only outside quotes. With
		// `set "VAR=%*"` the wrapping quote makes the user's own quotes
		// close instead of open: for `install "lodash@>=4"` the `>` lands
		// outside quotes, cmd.exe writes a file named `=4`, and the variable
		// holds a truncated tail. Without the wrapping quotes this line reads
		// the tail exactly as the launch line below does. A bare command
		// sets an empty value, which cmd.exe treats as unset.
		fmt.Sprintf(`set %s=%%*`, pmgRawArgsEnv),
		fmt.Sprintf(`"%s" %s %%*`, bin, pm),
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
// shell reads. Windows puts the machine PATH ahead of that, so an elevated
// install registers the directory there too, as a per-user variable
// reference. Without elevation the user PATH is all PMG can write.
func (m *ShimManager) installPath() error {
	if err := registerUserPath(m.config.BinDir); err != nil {
		return err
	}
	if !isElevated() {
		return nil
	}
	return registerMachinePath(machinePathEntry(m.config.BinDir))
}

func (m *ShimManager) removePath() error {
	if err := unregisterUserPath(m.config.BinDir); err != nil {
		return err
	}
	if !isElevated() {
		return nil
	}
	return unregisterMachinePath(machinePathEntry(m.config.BinDir))
}

func (m *ShimManager) pathInstalled() (bool, error) { return userPathContains(m.config.BinDir) }
