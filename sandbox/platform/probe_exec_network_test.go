package platform

import (
	"context"
	"errors"
	"testing"

	"github.com/safedep/pmg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecNetworkProbe(t *testing.T) {
	tests := []struct {
		name       string
		newSandbox func() (sandbox.Sandbox, error)
		want       sandbox.ProbeStatus
		summary    string
	}{
		{
			name:       "landlock confines outbound",
			newSandbox: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: sandbox.DriverLandlock}, nil },
			want:       sandbox.ProbeStatusOK,
			summary:    "confined with network_via_proxy_only (landlock)",
		},
		{
			name:       "seatbelt confines outbound",
			newSandbox: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: sandbox.DriverSeatbelt}, nil },
			want:       sandbox.ProbeStatusOK,
			summary:    "confined with network_via_proxy_only (seatbelt)",
		},
		{
			name:       "bubblewrap is the environment only",
			newSandbox: func() (sandbox.Sandbox, error) { return &fakeSandbox{name: sandbox.DriverBubblewrap}, nil },
			want:       sandbox.ProbeStatusWarn,
			summary:    "proxy by environment only (bubblewrap)",
		},
		{
			name:       "no driver",
			newSandbox: func() (sandbox.Sandbox, error) { return nil, errors.New("unsupported arch") },
			want:       sandbox.ProbeStatusFail,
			summary:    "no sandbox driver",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &execNetworkProbe{newSandbox: tc.newSandbox}
			res := p.Run(context.Background())
			assert.Equal(t, sandbox.ProbeExecNetwork, res.Name)
			assert.Equal(t, tc.want, res.Status)
			assert.Contains(t, res.Summary, tc.summary)
			if tc.want != sandbox.ProbeStatusOK {
				assert.NotEmpty(t, res.Fixes)
			}
		})
	}
}

func TestExecNetworkProbeClosesTheSandbox(t *testing.T) {
	sb := &fakeSandbox{name: sandbox.DriverLandlock}
	p := &execNetworkProbe{newSandbox: func() (sandbox.Sandbox, error) { return sb, nil }}
	res := p.Run(context.Background())
	require.Equal(t, sandbox.ProbeStatusOK, res.Status)
	assert.True(t, sb.closed)
}
