package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/log"
)

type ProtectionTestCase struct {
	PackageManager string
	Package        string
	InstallArgs    []string
	NeedsVenv      bool
}

func ProtectionTestCases() []ProtectionTestCase {
	return []ProtectionTestCase{
		{
			PackageManager: "npm",
			Package:        "safedep-test-pkg@0.1.3",
			InstallArgs:    []string{"npm", "install", "--no-cache", "--prefer-online", "safedep-test-pkg@0.1.3"},
		},
		{
			PackageManager: "pip",
			Package:        "safedep-test-pkg==0.1.4",
			InstallArgs:    []string{"pip", "install", "--no-cache-dir", "safedep-test-pkg==0.1.4"},
			NeedsVenv:      true,
		},
	}
}

func RunProtectionCheck(tc ProtectionTestCase, pmgBinary string) CheckResult {
	if _, err := exec.LookPath(tc.PackageManager); err != nil {
		return CheckResult{
			Status:  StatusWarn,
			Message: fmt.Sprintf("%s not available — skipping protection test for %s", tc.PackageManager, tc.Package),
		}
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
		venvBin := filepath.Join(venvDir, "bin")
		env = prependPath(env, venvBin)
	}

	cmd := exec.Command(pmgBinary, tc.InstallArgs...)
	cmd.Dir = tmpDir
	cmd.Env = env

	_, runErr := cmd.CombinedOutput()
	return evaluateProtectionResult(tc.PackageManager, tc.Package, runErr)
}

func setupVenv(baseDir string) (string, error) {
	venvDir := filepath.Join(baseDir, "venv")
	cmd := exec.Command("python3", "-m", "venv", venvDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("venv creation failed: %w\n%s", err, string(output))
	}
	return venvDir, nil
}

func prependPath(env []string, dir string) []string {
	result := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			e = fmt.Sprintf("PATH=%s%c%s", dir, filepath.ListSeparator, e[5:])
		}
		result = append(result, e)
	}
	return result
}

func evaluateProtectionResult(pm string, pkg string, err error) CheckResult {
	if err != nil {
		if isExecutableNotFound(err) {
			return CheckResult{
				Status:  StatusWarn,
				Message: fmt.Sprintf("%s not available — skipping protection test for %s", pm, pkg),
			}
		}
		return CheckResult{
			Status:  StatusPass,
			Message: fmt.Sprintf("Malicious package blocked (%s/%s)", pm, pkg),
		}
	}
	return CheckResult{
		Status:  StatusFail,
		Message: fmt.Sprintf("Failed to block %s/%s — package was installed instead of blocked", pm, pkg),
	}
}

func isExecutableNotFound(err error) bool {
	if execErr, ok := err.(*exec.Error); ok {
		return execErr.Err == exec.ErrNotFound
	}
	return false
}

func CheckShimScripts(shimDir string, managers []string) (found []string, missing []string) {
	for _, pm := range managers {
		shimPath := filepath.Join(shimDir, pm)
		info, err := os.Stat(shimPath)
		if err != nil || info.Mode()&0o111 == 0 {
			missing = append(missing, pm)
			continue
		}
		found = append(found, pm)
	}
	return found, missing
}
