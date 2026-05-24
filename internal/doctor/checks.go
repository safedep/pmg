package doctor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

func CheckConfigFile(path string) CheckResult {
	_, err := os.Stat(path)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Message: "Config file not found → run 'pmg setup install'",
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: fmt.Sprintf("Config file: %s", path),
	}
}

func CheckBinaryInPath(name string) CheckResult {
	path, err := exec.LookPath(name)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Message: fmt.Sprintf("Binary %s not found in PATH", name),
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: fmt.Sprintf("Binary %s found: %s", name, path),
	}
}

func CheckDirectoryWritable(dir string, label string) CheckResult {
	info, err := os.Stat(dir)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Message: fmt.Sprintf("%s directory not found: %s → run 'pmg setup install'", label, dir),
		}
	}
	if !info.IsDir() {
		return CheckResult{
			Status:  StatusFail,
			Message: fmt.Sprintf("%s path is not a directory: %s", label, dir),
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: fmt.Sprintf("%s directory: %s", label, dir),
	}
}

func CheckSandbox(enabled bool, available bool, driverName string) CheckResult {
	if !enabled {
		return CheckResult{
			Status:  StatusWarn,
			Message: "Sandbox disabled → enable in config for defense-in-depth",
		}
	}
	if !available {
		return CheckResult{
			Status:  StatusFail,
			Message: "Sandbox enabled but no driver available on this platform",
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: fmt.Sprintf("Sandbox enabled (%s)", driverName),
	}
}

func CheckSecurityFeature(feature string, enabled bool) CheckResult {
	if enabled {
		return CheckResult{
			Status:  StatusPass,
			Message: fmt.Sprintf("%s is enabled", feature),
		}
	}
	return CheckResult{
		Status:  StatusWarn,
		Message: fmt.Sprintf("%s is disabled", feature),
	}
}

func CheckProxyMode(enabled bool) CheckResult {
	if enabled {
		return CheckResult{
			Status:  StatusPass,
			Message: "Proxy Mode is enabled",
		}
	}
	return CheckResult{
		Status:  StatusFail,
		Message: "Proxy Mode is disabled → required for package interception",
	}
}

func CheckAliasInstalled(installed bool, err error) CheckResult {
	if err != nil {
		return CheckResult{
			Status:  StatusWarn,
			Message: fmt.Sprintf("Could not determine alias status: %v", err),
		}
	}
	if !installed {
		return CheckResult{
			Status:  StatusFail,
			Message: "Aliases not installed → run 'pmg setup install'",
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: "Shell aliases installed",
	}
}

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
	defer os.RemoveAll(tmpDir)

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

func CheckShimDirectory(shimDir string) CheckResult {
	info, err := os.Stat(shimDir)
	if err != nil || !info.IsDir() {
		return CheckResult{
			Status:  StatusFail,
			Message: fmt.Sprintf("Shim directory not found: %s → run 'pmg setup install'", shimDir),
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: fmt.Sprintf("Shim directory: %s", shimDir),
	}
}

func CheckShimInPath(shimDir string, pathEnv string) CheckResult {
	if slices.Contains(filepath.SplitList(pathEnv), shimDir) {
		return CheckResult{
			Status:  StatusPass,
			Message: fmt.Sprintf("%s is in PATH", shimDir),
		}
	}
	return CheckResult{
		Status:  StatusFail,
		Message: fmt.Sprintf("%s not in PATH → restart shell or source config", shimDir),
	}
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

func CheckPackageManagers(managers []string) (found []string, notFound []string) {
	for _, pm := range managers {
		if _, err := exec.LookPath(pm); err != nil {
			notFound = append(notFound, pm)
		} else {
			found = append(found, pm)
		}
	}
	return found, notFound
}
