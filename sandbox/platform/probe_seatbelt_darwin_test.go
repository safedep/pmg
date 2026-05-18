//go:build darwin
// +build darwin

package platform

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

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

type fakeFileInfo struct {
	name string
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func TestSeatbeltProbe(t *testing.T) {
	tests := []struct {
		name     string
		env      *fakeProbeEnv
		wantStat sandbox.ProbeStatus
	}{
		{
			name: "ok",
			env: &fakeProbeEnv{
				lookPathFn:       func(string) (string, error) { return "/usr/bin/sandbox-exec", nil },
				statExecutableFn: func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o755}, nil },
			},
			wantStat: sandbox.ProbeStatusOK,
		},
		{
			name: "not in path",
			env: &fakeProbeEnv{
				lookPathFn: func(string) (string, error) { return "", errors.New("not found") },
			},
			wantStat: sandbox.ProbeStatusFail,
		},
		{
			name: "stat fail",
			env: &fakeProbeEnv{
				lookPathFn:       func(string) (string, error) { return "/usr/bin/sandbox-exec", nil },
				statExecutableFn: func(string) (os.FileInfo, error) { return nil, errors.New("denied") },
			},
			wantStat: sandbox.ProbeStatusFail,
		},
		{
			name: "not executable",
			env: &fakeProbeEnv{
				lookPathFn:       func(string) (string, error) { return "/usr/bin/sandbox-exec", nil },
				statExecutableFn: func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o644}, nil },
			},
			wantStat: sandbox.ProbeStatusFail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &seatbeltProbe{env: tc.env}
			res := p.Run(context.Background())
			assert.Equal(t, sandbox.ProbeSeatbeltDriver, res.Name)
			assert.Equal(t, tc.wantStat, res.Status)
			if tc.wantStat != sandbox.ProbeStatusOK {
				assert.NotEmpty(t, res.Fixes)
			}
		})
	}
}
