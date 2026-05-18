//go:build linux
// +build linux

package platform

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/pmg/sandbox"
)

type fakeProbeEnv struct {
	lookPathFn       func(string) (string, error)
	statExecutableFn func(string) (os.FileInfo, error)
	readFileFn       func(string) ([]byte, error)
	runCommandFn     func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (f *fakeProbeEnv) lookPath(name string) (string, error) { return f.lookPathFn(name) }
func (f *fakeProbeEnv) statExecutable(path string) (os.FileInfo, error) {
	return f.statExecutableFn(path)
}
func (f *fakeProbeEnv) readFile(path string) ([]byte, error) { return f.readFileFn(path) }
func (f *fakeProbeEnv) runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.runCommandFn(ctx, name, args...)
}

func TestBwrapProbe(t *testing.T) {
	tests := []struct {
		name string
		env  *fakeProbeEnv
		want sandbox.ProbeStatus
	}{
		{
			name: "ok",
			env: &fakeProbeEnv{
				lookPathFn:   func(string) (string, error) { return "/usr/bin/bwrap", nil },
				runCommandFn: func(context.Context, string, ...string) ([]byte, error) { return []byte("bubblewrap 0.8.0\n"), nil },
			},
			want: sandbox.ProbeStatusOK,
		},
		{
			name: "not in path",
			env: &fakeProbeEnv{
				lookPathFn: func(string) (string, error) { return "", errors.New("not found") },
			},
			want: sandbox.ProbeStatusFail,
		},
		{
			name: "version failed",
			env: &fakeProbeEnv{
				lookPathFn:   func(string) (string, error) { return "/usr/bin/bwrap", nil },
				runCommandFn: func(context.Context, string, ...string) ([]byte, error) { return []byte("err"), errors.New("exit 1") },
			},
			want: sandbox.ProbeStatusFail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &bwrapProbe{env: tc.env}
			res := p.Run(context.Background())
			assert.Equal(t, sandbox.ProbeBwrapDriver, res.Name)
			assert.Equal(t, tc.want, res.Status)
			if tc.want != sandbox.ProbeStatusOK {
				assert.NotEmpty(t, res.Fixes)
			}
		})
	}
}
