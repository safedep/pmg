//go:build windows

package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/ptyx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file holds one test, and it is the only thing that decides whether
// the Windows launch contract is correct.
//
// The contract in exec_windows.go starts a .cmd manager through cmd.exe and
// replays the argument tail the shim captured, rather than serialising the
// arguments a second time. Whether that is right cannot be argued from the
// code: cmd.exe parses its own metacharacters, PowerShell and cmd.exe quote
// differently, and CreateProcess and CommandLineToArgvW add rules of their
// own. `exec_windows_test.go` proves only that PMG builds the command line
// it means to build.
//
// So this test measures the property that matters instead. For one typed
// command it captures the argv the manager receives with no PMG at all, then
// the argv it receives through the real .cmd shim and PMG, and requires the
// two arrays to be equal. It repeats that from cmd.exe and from PowerShell,
// in the direct mode and in the PTY mode under a conpty.
//
// Three things about its shape are deliberate:
//
//   - The final process is a native program that writes its own argv. A .cmd
//     that echoes would report a shell representation, not what the process
//     received.
//   - The PTY mode is covered because `runPTY` builds its session from
//     cmd.Path and cmd.Args and would silently drop SysProcAttr. That is the
//     regression this test exists to catch.
//   - It spawns about 70 processes and is slow by nature. That is the cost of
//     measuring a real parse rather than modelling one.
//
// It is standalone: it shares no state with the other tests in this package,
// and it needs no fixture beyond a temporary directory.
//
// The test binary plays three roles, selected by PMG_TEST_ROLE:
//
//   - unset: the test itself.
//   - pmg:   the binary the shim starts. It runs ExecuteWithOptions for
//     os.Args[1:], the way `pmg npm ...` does.
//   - dump:  the native program the fake npm.cmd forwards to. It writes its
//     own argv as JSON.
const (
	roleEnv     = "PMG_TEST_ROLE"
	modeEnv     = "PMG_TEST_MODE"
	dumpFileEnv = "PMG_TEST_DUMP_FILE"
)

func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case "dump":
		dumpArgv()
	case "pmg":
		runAsPMG()
	default:
		os.Exit(m.Run())
	}
}

func dumpArgv() {
	data, err := json.Marshal(os.Args[1:])
	if err == nil {
		err = os.WriteFile(os.Getenv(dumpFileEnv), data, 0o600)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dump:", err)
		os.Exit(3)
	}
	os.Exit(0)
}

func runAsPMG() {
	mode := ExecutionModeDirect
	if os.Getenv(modeEnv) == "pty" {
		mode = ExecutionModePTY
	}
	pc := &packagemanager.ParsedCommand{
		Command: packagemanager.Command{Exe: os.Args[1], Args: os.Args[2:]},
	}
	err := ExecuteWithOptions(context.Background(), pc, ExecuteOptions{
		PackageManagerName: os.Args[1],
		Mode:               mode,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "pmg:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// TestArgvEquivalence requires the argv a manager receives through the shim
// and PMG to equal the argv it receives with no PMG, for the same typed
// command, in both shells and both execution modes.
func TestArgvEquivalence(t *testing.T) {
	testBin, err := os.Executable()
	require.NoError(t, err)

	root := t.TempDir()
	managerDir := filepath.Join(root, "manager")
	shimDir := filepath.Join(root, "shims")
	require.NoError(t, os.Mkdir(managerDir, 0o755))

	// The fake npm.cmd has the shape of the real one: a batch file that
	// forwards %* to a native program.
	fakeNpm := strings.Join([]string{
		"@echo off",
		`set "` + roleEnv + `=dump"`,
		`"` + testBin + `" %*`,
		"exit /b %ERRORLEVEL%",
		"",
	}, "\r\n")
	require.NoError(t, os.WriteFile(filepath.Join(managerDir, "npm.cmd"), []byte(fakeNpm), 0o644))

	require.NoError(t, shim.NewShimManager(shim.ShimConfig{
		BinDir:          shimDir,
		PMGBin:          testBin,
		PackageManagers: []string{"npm"},
		SkipUserPath:    true,
	}).Install())

	cases := []struct {
		name string
		tail string
	}{
		{"caret in a semver range", `install lodash@^4.17.0`},
		{"quoted argument with a space", `install "a b" c`},
		{"empty argument", `install "" c`},
		{"embedded double quote", `run build -- --name="a b"`},
		{"trailing backslash", `install C:\pkg\`},
		{"unicode", `install héllo-wörld`},
		{"percent variable", `install %USERNAME%`},
		{"delayed-expansion marker", `install !USERNAME!`},
		// Quoted, because that is how a person passes these to a shell. An
		// unquoted & or ( splits the line in cmd.exe before any shim runs.
		{"quoted ampersand", `install "a&b"`},
		{"quoted pipe", `install "x | y"`},
		{"quoted parentheses", `install "(x)"`},
		{"percent-encoded URL", `install https://example.com/pkg%20name.tgz`},
		{"near the length limit", `install ` + strings.Repeat("a", 7000)},
	}

	shells := map[string]func(tail string) string{
		"cmd": func(tail string) string {
			return comspec() + ` /d /c npm ` + tail
		},
		"powershell": func(tail string) string {
			return `powershell.exe -NoProfile -NonInteractive -Command npm ` + tail
		},
	}

	for shell, commandLine := range shells {
		for _, tc := range cases {
			t.Run(shell+"/"+tc.name, func(t *testing.T) {
				line := commandLine(tc.tail)

				baseline := runCase(t, line, childEnv(managerDir, "", ""), false)
				require.NotNil(t, baseline, "the baseline must produce an argv, or the comparison is empty")

				direct := runCase(t, line, childEnv(shimDir+";"+managerDir, "pmg", "direct"), false)
				assert.Equal(t, baseline, direct, "direct mode")

				pty := runCase(t, line, childEnv(shimDir+";"+managerDir, "pmg", "pty"), true)
				assert.Equal(t, baseline, pty, "pty mode")
			})
		}
	}
}

// childEnv is the process environment for one run. PATH puts the given
// directories first, then the test's own PATH so cmd.exe and PowerShell
// resolve.
func childEnv(pathPrefix, role, mode string) []string {
	var env []string
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		switch {
		case strings.EqualFold(key, "PATH"),
			strings.EqualFold(key, roleEnv),
			strings.EqualFold(key, modeEnv),
			strings.EqualFold(key, dumpFileEnv),
			strings.HasPrefix(strings.ToUpper(key), "PMG_SHIM"),
			strings.HasPrefix(strings.ToUpper(key), "PMG_RAW"):
			continue
		}
		env = append(env, entry)
	}
	env = append(env, "PATH="+pathPrefix+";"+os.Getenv("PATH"))
	if role != "" {
		env = append(env, roleEnv+"="+role, modeEnv+"="+mode)
	}
	return env
}

// runCase starts commandLine verbatim, waits for it, and returns the argv
// the dumper wrote. It returns nil when nothing was written. The PTY run
// spawns under a conpty so the pmg role has a console to attach to.
func runCase(t *testing.T, commandLine string, env []string, underPTY bool) []string {
	t.Helper()
	dumpFile := filepath.Join(t.TempDir(), "argv.json")
	env = append(env, dumpFileEnv+"="+dumpFile)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	prog, _, _ := strings.Cut(commandLine, " ")
	if underPTY {
		sess, err := ptyx.Spawn(ctx, ptyx.SpawnOpts{Prog: prog, CmdLine: commandLine, Env: env, Cols: 120, Rows: 30})
		require.NoError(t, err)
		defer sess.Close()

		// The reader must drain the PTY, or the child blocks on a full pipe.
		// Its output is the only diagnostic when the pmg role fails.
		var out bytes.Buffer
		go io.Copy(&out, sess.PtyReader())

		// ptyx.Spawn does not stop the child when ctx ends, so a hung child
		// would hold the whole package's test budget.
		done := make(chan error, 1)
		go func() { done <- sess.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Logf("pty run exited with: %v\n%s", err, out.String())
			}
		case <-ctx.Done():
			_ = sess.Kill()
			<-done
			t.Logf("pty run timed out\n%s", out.String())
		}
	} else {
		cmd := exec.CommandContext(ctx, prog)
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: commandLine}
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("run exited with: %v\n%s", err, out)
		}
	}

	data, err := os.ReadFile(dumpFile)
	if err != nil {
		return nil
	}
	var argv []string
	require.NoError(t, json.Unmarshal(data, &argv))
	return argv
}
