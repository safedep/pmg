//go:build windows

package runner

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"unicode/utf16"

	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/packagemanager"
	"github.com/safedep/ptyx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One test: for the same typed command, the argv a package manager receives
// through the .cmd shim and PMG must equal the argv it receives with no PMG.
// It runs each case from cmd.exe and from PowerShell, in the direct mode and
// in the PTY mode.
//
// This is the only thing that proves the launch contract.
// exec_windows_test.go proves only that PMG builds the command line it means
// to, and cmd.exe, PowerShell and CommandLineToArgvW each parse it again.
// Standalone and slow: about 70 process spawns.
//
// The test binary plays three roles, selected by PMG_TEST_ROLE:
//
//   - unset: the test itself.
//   - pmg:   the binary the shim starts, running ExecuteWithOptions.
//   - dump:  the native program the fake npm.cmd forwards to. It writes its
//     own argv as JSON, because an echoing .cmd would report a shell
//     representation instead.
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
// and PMG to equal the argv it receives with no PMG, from cmd.exe and from
// PowerShell, in both execution modes. The PTY mode is here because runPTY
// builds its session from cmd.Path and cmd.Args, so it can drop SysProcAttr
// and nothing else would notice.
func TestArgvEquivalence(t *testing.T) {
	testBin, err := os.Executable()
	require.NoError(t, err)

	root := t.TempDir()
	managerDir := filepath.Join(root, "manager")
	shimDir := filepath.Join(root, "shims")
	require.NoError(t, os.Mkdir(managerDir, 0o755))

	writeFakeNpm(t, managerDir, testBin)

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

	// A slice, not a map, so the subtest order is the same on every run.
	shells := []struct {
		name        string
		commandLine func(tail string) string
	}{
		{"cmd", func(tail string) string {
			return `"` + interpreterPath() + `" /d /c npm ` + tail
		}},
		// -EncodedCommand, because -Command is parsed by the Windows command
		// line rules before PowerShell starts, and those consume the quotes.
		// `-Command npm install "a&b"` would reach PowerShell as
		// `npm install a&b` and fail with a ParserError, before any PMG code
		// runs. Base64 of UTF-16LE carries any tail verbatim.
		{"powershell", func(tail string) string {
			script := utf16LEBase64("npm " + tail)
			return `powershell.exe -NoProfile -NonInteractive -EncodedCommand ` + script
		}},
	}

	for _, shell := range shells {
		for _, tc := range cases {
			t.Run(shell.name+"/"+tc.name, func(t *testing.T) {
				line := shell.commandLine(tc.tail)

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

// utf16LEBase64 encodes a script the way PowerShell's -EncodedCommand wants
// it.
func utf16LEBase64(script string) string {
	units := utf16.Encode([]rune(script))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// PMG hands the PTY path one raw command line, and ptyx passes nil for
// lpApplicationName, so CreateProcess resolves the first token itself and
// its search order puts the current directory ahead of System32. The
// interpreter is therefore named by absolute path. A repository that carries
// a cmd.exe must not run on `npm install`.
func TestPTYIgnoresACmdExeInTheWorkingDirectory(t *testing.T) {
	testBin, err := os.Executable()
	require.NoError(t, err)

	root := t.TempDir()
	managerDir := filepath.Join(root, "manager")
	shimDir := filepath.Join(root, "shims")
	workDir := filepath.Join(root, "repo")
	for _, dir := range []string{managerDir, workDir} {
		require.NoError(t, os.Mkdir(dir, 0o755))
	}

	writeFakeNpm(t, managerDir, testBin)
	require.NoError(t, shim.NewShimManager(shim.ShimConfig{
		BinDir:          shimDir,
		PMGBin:          testBin,
		PackageManagers: []string{"npm"},
		SkipUserPath:    true,
	}).Install())

	// A cmd.exe in the working directory that reports itself if it ever runs.
	marker := filepath.Join(root, "hijacked.txt")
	hijack := strings.Join([]string{
		"@echo off",
		`echo hijacked > "` + marker + `"`,
		"exit /b 0",
		"",
	}, "\r\n")
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "cmd.exe"), []byte(hijack), 0o755))

	line := `"` + interpreterPath() + `" /d /c npm install lodash`
	argv := runCaseIn(t, line, childEnv(shimDir+";"+managerDir, "pmg", "pty"), true, workDir)

	assert.NoFileExists(t, marker, "PMG ran a cmd.exe from the working directory")
	assert.Equal(t, []string{"install", "lodash"}, argv)
}

// writeFakeNpm writes a batch file with the shape of the real npm.cmd: it
// forwards %* to a native program, which is what makes the tail worth
// measuring.
func writeFakeNpm(t *testing.T, dir, testBin string) {
	t.Helper()
	body := strings.Join([]string{
		"@echo off",
		`set "` + roleEnv + `=dump"`,
		`"` + testBin + `" %*`,
		"exit /b %ERRORLEVEL%",
		"",
	}, "\r\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "npm.cmd"), []byte(body), 0o644))
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

func runCase(t *testing.T, commandLine string, env []string, underPTY bool) []string {
	t.Helper()
	return runCaseIn(t, commandLine, env, underPTY, t.TempDir())
}

// runCaseIn starts commandLine verbatim in workDir, waits for it, and returns
// the argv the dumper wrote. It returns nil when nothing was written. The PTY
// run spawns under a conpty so the pmg role has a console to attach to.
func runCaseIn(t *testing.T, commandLine string, env []string, underPTY bool, workDir string) []string {
	t.Helper()
	dumpFile := filepath.Join(t.TempDir(), "argv.json")
	env = append(env, dumpFileEnv+"="+dumpFile)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	prog, _, _ := strings.Cut(strings.TrimPrefix(commandLine, `"`), `"`)
	if underPTY {
		sess, err := ptyx.Spawn(ctx, ptyx.SpawnOpts{
			Prog: prog, CmdLine: commandLine, Env: env, Dir: workDir, Cols: 120, Rows: 30,
		})
		require.NoError(t, err)
		defer sess.Close()

		// The reader must drain the PTY, or the child blocks on a full pipe.
		// Its output is the only diagnostic when the pmg role fails, and
		// copyDone hands the buffer over so nothing reads it while the
		// copier still writes.
		var out bytes.Buffer
		copyDone := make(chan struct{})
		go func() {
			defer close(copyDone)
			_, _ = io.Copy(&out, sess.PtyReader())
		}()

		// ptyx.Spawn does not stop the child when ctx ends, so a hung child
		// would hold the whole package's test budget.
		waitDone := make(chan error, 1)
		go func() { waitDone <- sess.Wait() }()

		var waitErr error
		timedOut := false
		select {
		case waitErr = <-waitDone:
		case <-ctx.Done():
			timedOut = true
			_ = sess.Kill()
			<-waitDone
		}

		// Close before reading out: the copier ends when the PTY reports EOF.
		_ = sess.Close()
		<-copyDone

		switch {
		case timedOut:
			t.Logf("pty run timed out\n%s", out.String())
		case waitErr != nil:
			t.Logf("pty run exited with: %v\n%s", waitErr, out.String())
		}
	} else {
		cmd := exec.CommandContext(ctx, prog)
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: commandLine}
		cmd.Env = env
		cmd.Dir = workDir
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
