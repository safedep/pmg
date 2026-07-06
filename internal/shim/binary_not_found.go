package shim

import "fmt"

const commandNotFoundExitCode = 127

// BinaryNotFoundError is returned when a package manager name resolves through
// PMG shims but the real binary is absent from PATH (after shim dirs are stripped).
type BinaryNotFoundError struct {
	Name string
}

func (e *BinaryNotFoundError) Error() string {
	return fmt.Sprintf("%s is not installed", e.Name)
}

func (e *BinaryNotFoundError) ExitCode() int {
	return commandNotFoundExitCode
}
