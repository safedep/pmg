package utils

import (
	"fmt"
	"os/exec"
)

func GetExecutablePath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("interpreter '%s' not found in PATH: %s", name, err.Error())
	}
	return path, nil
}
