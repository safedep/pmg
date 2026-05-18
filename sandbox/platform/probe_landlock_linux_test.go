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

func TestLandlockProbe(t *testing.T) {
	tests := []struct {
		name   string
		detect landlockABIDetector
		want   sandbox.ProbeStatus
	}{
		{
			name:   "ok latest",
			detect: func() (int, error) { return 4, nil },
			want:   sandbox.ProbeStatusOK,
		},
		{
			name:   "warn low abi",
			detect: func() (int, error) { return 1, nil },
			want:   sandbox.ProbeStatusWarn,
		},
		{
			name:   "fail zero",
			detect: func() (int, error) { return 0, nil },
			want:   sandbox.ProbeStatusFail,
		},
		{
			name:   "fail error",
			detect: func() (int, error) { return 0, errors.New("ENOSYS") },
			want:   sandbox.ProbeStatusFail,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &landlockProbe{detect: tc.detect}
			res := p.Run(context.Background())
			assert.Equal(t, sandbox.ProbeLandlockDriver, res.Name)
			assert.Equal(t, tc.want, res.Status)
			if tc.want != sandbox.ProbeStatusOK {
				assert.NotEmpty(t, res.Fixes)
			}
		})
	}
}
