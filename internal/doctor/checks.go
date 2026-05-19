package doctor

import (
	"fmt"
	"os"
	"os/exec"
)

func CheckConfigFile(path string) CheckResult {
	_, err := os.Stat(path)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Message: "config file not found → run 'pmg setup install'",
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: fmt.Sprintf("config file: %s", path),
	}
}

func CheckBinaryInPath(name string) CheckResult {
	path, err := exec.LookPath(name)
	if err != nil {
		return CheckResult{
			Status:  StatusFail,
			Message: fmt.Sprintf("%s not found in PATH", name),
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: fmt.Sprintf("%s found: %s", name, path),
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
			Message: "sandbox disabled → enable in config for defense-in-depth",
		}
	}
	if !available {
		return CheckResult{
			Status:  StatusFail,
			Message: "sandbox enabled but no driver available on this platform",
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: fmt.Sprintf("sandbox enabled (%s)", driverName),
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
			Message: fmt.Sprintf("could not determine alias status: %v", err),
		}
	}
	if !installed {
		return CheckResult{
			Status:  StatusFail,
			Message: "aliases not installed → run 'pmg setup install'",
		}
	}
	return CheckResult{
		Status:  StatusPass,
		Message: "shell aliases installed",
	}
}
