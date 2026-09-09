//go:build windows

package shim

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The byte tests prove what the shim says. This file proves what cmd.exe
// does with it. The test binary doubles as pmg.exe: with PMG_SHIM_TEST_HELPER
// set it reports the shim's exports and its own argv as JSON, then exits with
// the code the test asked for.
const (
	helperEnv     = "PMG_SHIM_TEST_HELPER"
	helperExitEnv = "PMG_SHIM_TEST_EXIT"
)

type helperReport struct {
	RawArgs  string   `json:"raw_args"`
	ShimPath string   `json:"shim_path"`
	Args     []string `json:"args"`
}

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "" {
		os.Exit(m.Run())
	}

	report := helperReport{
		RawArgs:  os.Getenv(pmgRawArgsEnv),
		ShimPath: os.Getenv(pmgShimPathEnv),
		Args:     os.Args[1:],
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		os.Exit(3)
	}
	code, _ := strconv.Atoi(os.Getenv(helperExitEnv))
	os.Exit(code)
}

// TestCmdShimOnCmdExe runs the generated .cmd through a real cmd.exe. The
// pmg.exe path carries a space, a parenthesis, an ampersand and a percent
// sign, because the shim quotes it and any of those breaks an unquoted form.
func TestCmdShimOnCmdExe(t *testing.T) {
	isolateUserPath(t)
	root := t.TempDir()

	testBin, err := os.Executable()
	require.NoError(t, err)
	pmgBin := filepath.Join(root, "100% (x86) & co", "pmg.exe")
	require.NoError(t, os.MkdirAll(filepath.Dir(pmgBin), 0o755))
	copyFile(t, testBin, pmgBin)

	shimDir := filepath.Join(root, "shims (user)")
	require.NoError(t, NewShimManager(ShimConfig{
		BinDir:          shimDir,
		PMGBin:          pmgBin,
		PackageManagers: []string{"npm"},
		SkipUserPath:    true,
	}).Install())
	shimPath := filepath.Join(shimDir, "npm.cmd")

	tails := []struct {
		name string
		tail string
	}{
		{"quoted redirect character", `install "lodash@>=4"`},
		{"quoted ampersand", `install "a & b"`},
		{"quoted pipe and carets", `install "^1 || ^2"`},
		{"percent sign", `install 100%`},
		{"delayed-expansion marker", `install !x!`},
		{"empty tail", ``},
	}

	for _, tc := range tails {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			report, code := runShim(t, shimPath, tc.tail, workDir, 7)

			assert.Equal(t, 7, code, "exit /b must carry the pmg exit code")
			assert.Equal(t, tc.tail, report.RawArgs, "PMG_RAW_ARGS must be the tail byte for byte")
			assert.Equal(t, shimPath, report.ShimPath)
			assert.Equal(t, "npm", report.Args[0])

			leftovers, err := os.ReadDir(workDir)
			require.NoError(t, err)
			assert.Empty(t, leftovers, "a live > or & would create a file or run a command here")
		})
	}

	t.Run("missing pmg.exe fails closed with the pmg message", func(t *testing.T) {
		require.NoError(t, os.Remove(pmgBin))
		out, code := runCmd(t, `"`+shimPath+`" install x`, t.TempDir(), nil)
		assert.Equal(t, 127, code)
		assert.Contains(t, string(out), "[pmg] error: PMG binary not found")
		assert.Contains(t, string(out), "pmg setup install")
	})
}

// runShim runs `<shim> <tail>` through cmd.exe in workDir with the helper
// role armed, and decodes the helper's report.
func runShim(t *testing.T, shimPath, tail, workDir string, exitCode int) (helperReport, int) {
	t.Helper()
	env := append(os.Environ(), helperEnv+"=1", helperExitEnv+"="+strconv.Itoa(exitCode))
	line := `"` + shimPath + `"`
	if tail != "" {
		line += " " + tail
	}
	out, code := runCmd(t, line, workDir, env)

	var report helperReport
	require.NoError(t, json.Unmarshal(out, &report), "helper output: %s", out)
	return report, code
}

// runCmd hands cmd.exe one raw command line, the way a typed command
// reaches it. /s keeps the outer quote pair intact so a shim path with a
// space survives.
func runCmd(t *testing.T, line, workDir string, env []string) ([]byte, int) {
	t.Helper()
	cmd := exec.Command(comspecForTest())
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: fmt.Sprintf(`cmd.exe /d /s /c "%s"`, line)}
	cmd.Dir = workDir
	cmd.Env = env

	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return out, 0
	case errors.As(err, &exitErr):
		return out, exitErr.ExitCode()
	default:
		require.NoError(t, err)
		return nil, -1
	}
}

func comspecForTest() string {
	if c := os.Getenv("COMSPEC"); c != "" {
		return c
	}
	return "cmd.exe"
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	require.NoError(t, err)
	defer in.Close()
	out, err := os.Create(dst)
	require.NoError(t, err)
	_, err = io.Copy(out, in)
	require.NoError(t, err)
	require.NoError(t, out.Close())
}
