package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

func ExecCmd(name string, args, env []string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running cmd %s: %s\nStderr: %s", name,
			err.Error(), stderr.String())
	}
	return nil
}
