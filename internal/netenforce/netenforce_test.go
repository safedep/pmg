package netenforce

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyValidate(t *testing.T) {
	cases := []struct {
		name    string
		policy  Policy
		wantErr string
	}{
		{"default policy is valid", DefaultPolicy(), ""},
		{"port zero is rejected", Policy{Ports: []uint16{0}}, "port 0"},
		{"zero prefix is rejected", Policy{SkipDestinations: []netip.Prefix{{}}}, "not a valid prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestDefaultPolicyIsACopy(t *testing.T) {
	p := DefaultPolicy()
	p.Ports[0] = 1
	assert.Equal(t, uint16(80), DefaultPorts[0])
	assert.True(t, p.DenyUDP)
}

func TestProbeResultErr(t *testing.T) {
	assert.NoError(t, ProbeResult{Supported: true}.Err())

	err := ProbeResult{Missing: []string{"CAP_BPF is missing", "kernel BTF is missing"}}.Err()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CAP_BPF is missing")
	assert.Contains(t, err.Error(), "kernel BTF is missing")
}
