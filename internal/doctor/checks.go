package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/internal/shim"
	"github.com/safedep/pmg/internal/ui"
)

type ProtectionTestCase struct {
	PackageManager string
	// Fallbacks are alternate binaries to run the test through when the primary
	// is absent (e.g. Homebrew and Debian ship pip3 without a bare pip). Each
	// entry must also be a pmg subcommand.
	Fallbacks   []string
	Package     string
	InstallArgs []string
	NeedsVenv   bool
}

func ProtectionTestCases() []ProtectionTestCase {
	return []ProtectionTestCase{
		{
			PackageManager: "npm",
			Package:        "safedep-test-pkg@0.1.3",
			InstallArgs:    []string{"install", "--no-cache", "--prefer-online", "safedep-test-pkg@0.1.3"},
		},
		{
			PackageManager: "pip",
			Fallbacks:      []string{"pip3"},
			Package:        "safedep-test-pkg==0.0.4",
			InstallArgs:    []string{"install", "--no-cache-dir", "safedep-test-pkg==0.0.4"},
			NeedsVenv:      true,
		},
	}
}

func (tc ProtectionTestCase) binaries() []string {
	return append([]string{tc.PackageManager}, tc.Fallbacks...)
}

// resolveProtectionBinary picks the first candidate with a real binary,
// resolved the same way the runner does — PATH with PMG shim dirs stripped.
// A plain exec.LookPath would find the PMG shim on PATH and report the
// manager as available even when the real binary is absent.
func resolveProtectionBinary(tc ProtectionTestCase) (string, bool) {
	for _, name := range tc.binaries() {
		if _, err := shim.ResolveRealBinary(name); err == nil {
			return name, true
		}
	}
	return "", false
}

func RunProtectionCheck(tc ProtectionTestCase, pmgBinary string) CheckResult {
	binary, found := resolveProtectionBinary(tc)
	if !found {
		if !tc.NeedsVenv {
			return CheckResult{
				Status:  StatusWarn,
				Message: fmt.Sprintf("%s not available — skipping protection test for %s", strings.Join(tc.binaries(), "/"), tc.Package),
			}
		}
		// Venv-based tests supply their own binary: python3 -m venv bootstraps
		// pip into the venv, whose bin dir is prepended to PATH for the pmg run.
		binary = tc.PackageManager
	}

	tmpDir, err := os.MkdirTemp("", "pmg-doctor-*")
	if err != nil {
		return CheckResult{
			Status:  StatusWarn,
			Message: fmt.Sprintf("Could not create temp dir for %s test: %v", tc.PackageManager, err),
		}
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Warnf("failed to clean up temp dir %s: %v", tmpDir, err)
		}
	}()

	env := os.Environ()

	if tc.NeedsVenv {
		venvDir, venvErr := setupVenv(tmpDir)
		if venvErr != nil {
			return CheckResult{
				Status:  StatusWarn,
				Message: fmt.Sprintf("Could not create venv for %s test: %v", tc.PackageManager, venvErr),
			}
		}
		pipPath, pipErr := venvPipPath(venvDir)
		if pipErr != nil {
			return CheckResult{
				Status:  StatusWarn,
				Message: fmt.Sprintf("Could not find pip in the temporary environment: %v", pipErr),
			}
		}
		binary = "pip"
		env = prependPath(env, filepath.Dir(pipPath))
	}

	args := append([]string{binary}, tc.InstallArgs...)
	cmd := exec.Command(pmgBinary, args...)
	cmd.Dir = tmpDir
	cmd.Env = env

	output, runErr := cmd.CombinedOutput()
	return evaluateProtectionResult(binary, tc.Package, string(output), runErr)
}

func setupVenv(baseDir string) (string, error) {
	venvDir := filepath.Join(baseDir, "venv")
	cmd := exec.Command("python3", "-m", "venv", venvDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("venv creation failed: %w\n%s", err, string(output))
	}
	return venvDir, nil
}

func venvPipPath(venvDir string) (string, error) {
	path := platform.VenvPipPath(venvDir)
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	return path, nil
}

func prependPath(env []string, dir string) []string {
	var result []string
	found := false
	for _, e := range env {
		key, value, ok := strings.Cut(e, "=")
		if ok && platform.IsPathEnvKey(key) {
			e = fmt.Sprintf("%s=%s%c%s", key, dir, filepath.ListSeparator, value)
			found = true
		}
		result = append(result, e)
	}
	if !found {
		result = append(result, "PATH="+dir)
	}
	return result
}

func evaluateProtectionResult(pm string, pkg string, output string, err error) CheckResult {
	if err == nil {
		return CheckResult{
			Status:  StatusFail,
			Message: fmt.Sprintf("Failed to block %s/%s — package was installed instead of blocked", pm, pkg),
		}
	}

	if isExecutableNotFound(err) {
		return CheckResult{
			Status:  StatusWarn,
			Message: fmt.Sprintf("%s not available — skipping protection test for %s", pm, pkg),
		}
	}

	// A non-zero exit alone is not proof of a block: PackageManagerNotFound,
	// proxy/CA setup failures, and config errors all exit non-zero too. Require
	// PMG's block headline in the output before declaring protection working.
	// The headline is emitted only for malware blocks, not cooldown-only blocks.
	if strings.Contains(output, ui.MalwareBlockedHeadline) {
		return CheckResult{
			Status:  StatusPass,
			Message: fmt.Sprintf("Malicious package blocked (%s/%s)", pm, pkg),
		}
	}

	return CheckResult{
		Status:  StatusWarn,
		Message: fmt.Sprintf("Install failed without a malware block (%v)", err),
	}
}

func isExecutableNotFound(err error) bool {
	if execErr, ok := err.(*exec.Error); ok {
		return execErr.Err == exec.ErrNotFound
	}
	return false
}
