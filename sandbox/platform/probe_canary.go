package platform

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
)

// canaryTimeout bounds the runtime of a single canary smoke test so a misconfigured
// kernel cannot wedge the doctor command.
const canaryTimeout = 15 * time.Second

// canaryTargetPath is the file the canary policy denies and the canary tries
// to read. It exists on every supported host. macOS has no /etc/hostname.
// A test points it at a missing file.
var canaryTargetPath = "/etc/hosts"

// canarySandboxFactory builds the sandbox driver under test. Separated from the
// probe body so tests can stub it.
type canarySandboxFactory func() (sandbox.Sandbox, error)

// canaryCommandFactory builds the command the canary attempts to run. Tests
// stub it. The default runs cat on canaryTargetPath.
type canaryCommandFactory func(ctx context.Context) *exec.Cmd

func defaultCanaryCommand(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "cat", canaryTargetPath)
}

// canaryDenyPaths is the canary target and its resolved path. Seatbelt
// matches the resolved path, and on macOS /etc is a link to /private/etc.
func canaryDenyPaths() []string {
	resolved, err := filepath.EvalSymlinks(canaryTargetPath)
	if err != nil || resolved == canaryTargetPath {
		return []string{canaryTargetPath}
	}
	return []string{canaryTargetPath, resolved}
}

// canaryPolicy denies one file inside an allowed root. ValidateResolved
// requires at least one rule, and the deny on canaryTargetPath is the rule
// the probe checks. The read allowance lets the canary start on Seatbelt,
// which denies by default. Deny rules win on every driver, as the exec
// profile relies on.
func canaryPolicy() *sandbox.SandboxPolicy {
	return &sandbox.SandboxPolicy{
		Name:            "pmg-canary",
		Description:     "canary probe: deny one file inside an allowed root",
		PackageManagers: []string{"npm", "pip", "uv", "pypi"},
		Filesystem: sandbox.FilesystemPolicy{
			AllowRead: []string{"/"},
			DenyRead:  canaryDenyPaths(),
		},
		AllowGitConfig:   utils.PtrTo(false),
		AllowPTY:         utils.PtrTo(false),
		AllowNetworkBind: utils.PtrTo(false),
	}
}

// runCanary executes the canary smoke test. The probe is OK when cat exits
// with a status and names the target, or when the output is not the file.
func runCanary(ctx context.Context, name string, driver sandbox.DriverName, factory canarySandboxFactory, cmdFactory canaryCommandFactory) sandbox.ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, canaryTimeout)
	defer cancel()

	d := string(driver)

	sb, err := factory()
	if err != nil {
		return sandbox.ProbeResult{
			Name:    name,
			Status:  sandbox.ProbeStatusFail,
			Summary: d + " sandbox could not be constructed",
			Detail:  err.Error(),
			Fixes:   []sandbox.ProbeFix{driverInstallFix(driver)},
		}
	}

	defer func() { _ = sb.Close() }()

	if !sb.IsAvailable() {
		return sandbox.ProbeResult{
			Name:    name,
			Status:  sandbox.ProbeStatusSkipped,
			Summary: d + " driver not available on this host",
			Fixes:   []sandbox.ProbeFix{driverInstallFix(driver)},
		}
	}

	cmd := cmdFactory(ctx)
	isCanaryRead := isCanaryReadCommand(cmd)
	var expected []byte
	if isCanaryRead {
		var readErr error
		expected, readErr = os.ReadFile(canaryTargetPath)
		if readErr != nil {
			return sandbox.ProbeResult{
				Name:    name,
				Status:  sandbox.ProbeStatusFail,
				Summary: d + " canary target " + canaryTargetPath + " not found",
				Detail:  readErr.Error(),
			}
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	policy := canaryPolicy()

	result, err := sb.Execute(ctx, cmd, policy, nil)
	if err != nil {
		return sandbox.ProbeResult{
			Name:    name,
			Status:  sandbox.ProbeStatusFail,
			Summary: d + " sandbox setup failed",
			Detail:  err.Error(),
			Fixes:   []sandbox.ProbeFix{driverInstallFix(driver)},
		}
	}
	defer func() { _ = result.Close() }()

	if result.ShouldRun() {
		err = cmd.Run()
	}

	if err == nil {
		if isCanaryRead && len(expected) > 0 && !bytes.Equal(stdout.Bytes(), expected) {
			return sandbox.ProbeResult{
				Name:    name,
				Status:  sandbox.ProbeStatusOK,
				Summary: d + " masked canary read",
				Detail:  "the sandbox hid the contents of " + canaryTargetPath,
			}
		}

		return sandbox.ProbeResult{
			Name:    name,
			Status:  sandbox.ProbeStatusFail,
			Summary: d + " did not block canary read of " + canaryTargetPath,
			Detail:  "the sandbox executed `cat " + canaryTargetPath + "` without denial",
			Fixes: []sandbox.ProbeFix{{
				Description: "Driver appears installed but not enforcing. Re-run with PMG_LOG_LEVEL=debug to inspect the translated policy.",
			}},
		}
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return sandbox.ProbeResult{
			Name:    name,
			Status:  sandbox.ProbeStatusFail,
			Summary: d + " canary timed out",
			Detail:  err.Error(),
		}
	}

	// A denied read makes the canary exit with a status. A canary that a
	// signal stopped, or that did not start, proves nothing about the policy.
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || !exitErr.Exited() {
		return sandbox.ProbeResult{
			Name:    name,
			Status:  sandbox.ProbeStatusFail,
			Summary: d + " canary did not run to completion",
			Detail:  err.Error(),
		}
	}

	// cat names the file it cannot read, in every locale. A failure that
	// does not name the target is not a denial.
	if !bytes.Contains(stderr.Bytes(), []byte(canaryTargetPath)) {
		return sandbox.ProbeResult{
			Name:    name,
			Status:  sandbox.ProbeStatusFail,
			Summary: d + " canary failed without a denial of " + canaryTargetPath,
			Detail:  strings.TrimSpace(err.Error() + "\n" + stderr.String()),
		}
	}

	return sandbox.ProbeResult{
		Name:    name,
		Status:  sandbox.ProbeStatusOK,
		Summary: d + " correctly blocked canary read",
	}
}

func isCanaryReadCommand(cmd *exec.Cmd) bool {
	if cmd == nil {
		return false
	}

	if len(cmd.Args) == 0 || filepath.Base(cmd.Args[0]) != "cat" {
		return false
	}

	for _, arg := range cmd.Args[1:] {
		if arg == canaryTargetPath {
			return true
		}
	}

	return false
}

func driverInstallFix(driver sandbox.DriverName) sandbox.ProbeFix {
	switch driver {
	case sandbox.DriverBubblewrap:
		return bubblewrapInstallFix()
	case sandbox.DriverLandlock:
		return sandbox.ProbeFix{
			Description: "Upgrade to Linux 5.13+ for Landlock support.",
			Docs:        "https://docs.kernel.org/userspace-api/landlock.html",
		}
	case sandbox.DriverSeatbelt:
		return sandbox.ProbeFix{
			Description: "sandbox-exec ships with macOS — check SIP and PATH.",
		}
	}
	return sandbox.ProbeFix{Description: "Install the " + string(driver) + " sandbox driver."}
}

func bubblewrapInstallFix() sandbox.ProbeFix {
	return sandbox.ProbeFix{
		Description: "Install bubblewrap using your distribution package manager and verify unprivileged user namespaces are enabled.",
		Docs:        "https://github.com/containers/bubblewrap",
	}
}
