package platform

import (
	"context"
	"os"
	"os/exec"
)

// probeEnv abstracts the host environment so probes can be unit-tested without
// touching the real filesystem or PATH. Real probes use defaultProbeEnv; tests
// inject fakes.
type probeEnv interface {
	lookPath(name string) (string, error)
	statExecutable(path string) (os.FileInfo, error)
	readFile(path string) ([]byte, error)
	runCommand(ctx context.Context, name string, args ...string) ([]byte, error)
}

type defaultProbeEnv struct{}

func (defaultProbeEnv) lookPath(name string) (string, error) { return exec.LookPath(name) }

func (defaultProbeEnv) statExecutable(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

func (defaultProbeEnv) readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func (defaultProbeEnv) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}
