package platform

import (
	"os/exec"
	"slices"
	"strings"
)

// PythonCommand is one way to start a Python interpreter. Args are the fixed
// arguments that come before the caller's own, such as "-3" for the py
// launcher.
type PythonCommand struct {
	Name string
	Args []string
}

// Command returns an exec.Cmd that runs the interpreter with args after the
// fixed ones.
func (p PythonCommand) Command(args ...string) *exec.Cmd {
	return exec.Command(p.Name, append(slices.Clone(p.Args), args...)...)
}

func (p PythonCommand) String() string {
	return strings.Join(append([]string{p.Name}, p.Args...), " ")
}

// PythonCommands returns the interpreters to try, in order of preference.
func PythonCommands() []PythonCommand { return pythonCommands() }
