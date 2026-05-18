package platform

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/pmg/sandbox"
)

// canaryTimeout bounds the runtime of a single canary smoke test so a misconfigured
// kernel cannot wedge the doctor command.
const canaryTimeout = 15 * time.Second

// canaryTargetPath is the file the canary attempts to read under a deny-all
// policy. It is well-known on every supported host.
const canaryTargetPath = "/etc/hostname"

// canarySandboxFactory builds the sandbox driver under test. Separated from the
// probe body so tests can stub it.
type canarySandboxFactory func() (sandbox.Sandbox, error)

// canaryCommandFactory builds the command the canary attempts to run. Stubbed
// in tests; defaults to `cat /etc/hostname`.
type canaryCommandFactory func(ctx context.Context) *exec.Cmd

func defaultCanaryCommand(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, "cat", canaryTargetPath)
}

// denyAllCanaryPolicy returns a minimal valid policy that denies read access to
// the canary target. ValidateResolved requires at least one rule; the deny on
// canaryTargetPath satisfies that and unambiguously asserts the sandbox is
// blocking the read.
func denyAllCanaryPolicy() *sandbox.SandboxPolicy {
	return &sandbox.SandboxPolicy{
		Name:            "pmg-canary",
		Description:     "deny-all canary probe",
		PackageManagers: []string{"npm", "pip", "uv", "pypi"},
		Filesystem: sandbox.FilesystemPolicy{
			DenyRead: []string{canaryTargetPath},
		},
		AllowGitConfig:   utils.PtrTo(false),
		AllowPTY:         utils.PtrTo(false),
		AllowNetworkBind: utils.PtrTo(false),
	}
}

// runCanary executes the canary smoke test. On success, the sandbox prevents
// the canary read and the command exits non-zero — that is the OK path.
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
			log.Warnf("canary probe: failed to read baseline %s: %v", canaryTargetPath, readErr)
		}
	}
	var stdout, stderr bytes.Buffer
	if cmd.Stdout == nil {
		cmd.Stdout = &stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = &stderr
	}
	policy := denyAllCanaryPolicy()

	result, err := sb.Execute(ctx, cmd, policy)
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
