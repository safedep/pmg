package utils

import (
	"fmt"
	"os"
	"os/exec"
)

func ExecCmd(name string, args, env []string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running cmd %s: %s\n", name, err.Error())
	}
	return nil
}
