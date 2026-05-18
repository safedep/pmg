//go:build linux
// +build linux

package platform

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/pmg/sandbox"
)

func TestAppArmorProbe(t *testing.T) {
	tests := []struct {
		name string
		env  *fakeProbeEnv
		want sandbox.ProbeStatus
	}{
		{
			name: "ok unrestricted",
			env:  &fakeProbeEnv{readFileFn: func(string) ([]byte, error) { return []byte("0\n"), nil }},
			want: sandbox.ProbeStatusOK,
		},
		{
			name: "warn restricted",
			env:  &fakeProbeEnv{readFileFn: func(string) ([]byte, error) { return []byte("1\n"), nil }},
			want: sandbox.ProbeStatusWarn,
		},
		{
			name: "skip missing",
			env:  &fakeProbeEnv{readFileFn: func(string) ([]byte, error) { return nil, errors.New("not found") }},
			want: sandbox.ProbeStatusSkipped,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &apparmorProbe{env: tc.env, path: apparmorUsernsSysctlPath}
			res := p.Run(context.Background())
			assert.Equal(t, sandbox.ProbeAppArmorUserns, res.Name)
			assert.Equal(t, tc.want, res.Status)
			if tc.want == sandbox.ProbeStatusWarn {
				assert.NotEmpty(t, res.Fixes)
			}
		})
	}
}
