package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBindAddress(t *testing.T) {
	cases := []struct {
		entry         string
		want          BindAddress
		loopback      bool
		allInterfaces bool
		errContains   string
	}{
		{entry: "localhost:5173", want: BindAddress{"localhost", "5173"}, loopback: true},
		{entry: "127.0.0.1:5173", want: BindAddress{"127.0.0.1", "5173"}, loopback: true},
		{entry: "[::1]:5173", want: BindAddress{"::1", "5173"}, loopback: true},
		{entry: "LOCALHOST:*", want: BindAddress{"localhost", "*"}, loopback: true},
		{entry: "0.0.0.0:3000", want: BindAddress{"0.0.0.0", "3000"}, allInterfaces: true},
		{entry: "[::]:3000", want: BindAddress{"::", "3000"}, allInterfaces: true},
		{entry: "192.168.1.5:3000", errContains: "must be loopback"},
		{entry: "devbox.local:3000", errContains: "must be loopback"},
		{entry: "::1:3000", errContains: "IPv6 host in brackets"},
		{entry: "localhost", errContains: "expected host:port"},
		{entry: ":3000", errContains: "missing host"},
		{entry: "*:3000", errContains: "host wildcards are not allowed"},
		{entry: "*:*", errContains: "host wildcards are not allowed"},
		{entry: "localhost:http", errContains: "must be a number from 1 to 65535"},
		{entry: "localhost:0", errContains: "must be a number from 1 to 65535"},
		{entry: "localhost:70000", errContains: "must be a number from 1 to 65535"},
	}

	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			got, err := ParseBindAddress(tc.entry)
			if tc.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.loopback, got.IsLoopback())
			assert.Equal(t, tc.allInterfaces, got.IsAllInterfaces())
		})
	}
}
