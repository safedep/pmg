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
