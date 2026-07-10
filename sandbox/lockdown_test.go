package sandbox

import (
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateLockdown(t *testing.T) {
	lockdownPolicy := &SandboxPolicy{
		Name:                "lockdown",
		NetworkViaProxyOnly: utils.PtrTo(true),
	}

	tests := []struct {
		name     string
		policy   *SandboxPolicy
		rt       *ExecutionContext
		wantPort string
		wantErr  string
	}{
		{
			name:   "lockdown off returns empty port and no error",
			policy: &SandboxPolicy{Name: "plain"},
			rt:     nil,
		},
		{
			name:    "nil execution context",
			policy:  lockdownPolicy,
			rt:      nil,
			wantErr: "requires the PMG proxy",
		},
		{
			name:    "empty proxy address",
			policy:  lockdownPolicy,
			rt:      &ExecutionContext{},
			wantErr: "requires the PMG proxy",
		},
		{
			name:    "non-loopback proxy address",
			policy:  lockdownPolicy,
			rt:      &ExecutionContext{ProxyAddr: "192.168.1.5:9999"},
			wantErr: "loopback",
		},
		{
			name:    "unparseable proxy address",
			policy:  lockdownPolicy,
			rt:      &ExecutionContext{ProxyAddr: "not-an-address"},
			wantErr: "loopback",
		},
		{
			name:    "service-name proxy port",
			policy:  lockdownPolicy,
			rt:      &ExecutionContext{ProxyAddr: "127.0.0.1:http"},
			wantErr: "non-numeric or out-of-range proxy port",
		},
		{
			name:    "zero proxy port",
			policy:  lockdownPolicy,
			rt:      &ExecutionContext{ProxyAddr: "127.0.0.1:0"},
			wantErr: "non-numeric or out-of-range proxy port",
		},
		{
			name:    "out-of-range proxy port",
			policy:  lockdownPolicy,
			rt:      &ExecutionContext{ProxyAddr: "127.0.0.1:70000"},
			wantErr: "non-numeric or out-of-range proxy port",
		},
		{
			name:     "loopback ipv4 proxy address",
			policy:   lockdownPolicy,
			rt:       &ExecutionContext{ProxyAddr: "127.0.0.1:54321"},
			wantPort: "54321",
		},
		{
			name:     "loopback ipv6 proxy address",
			policy:   lockdownPolicy,
			rt:       &ExecutionContext{ProxyAddr: "[::1]:54321"},
			wantPort: "54321",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, err := ValidateLockdown(tt.policy, tt.rt)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}
