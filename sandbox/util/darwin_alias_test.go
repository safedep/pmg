package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDarwinPathAliases(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"/var/db/safedep/gryph/hook.sock", []string{"/var/db/safedep/gryph/hook.sock", "/private/var/db/safedep/gryph/hook.sock"}},
		{"/private/var/run/mDNSResponder", []string{"/private/var/run/mDNSResponder", "/var/run/mDNSResponder"}},
		{"/tmp/a.sock", []string{"/tmp/a.sock", "/private/tmp/a.sock"}},
		{"/etc/hosts", []string{"/etc/hosts", "/private/etc/hosts"}},
		{"/var", []string{"/var", "/private/var"}},
		{"/variable/a.sock", []string{"/variable/a.sock"}},
		{"/Users/dev/a.sock", []string{"/Users/dev/a.sock"}},
		{"/private/other", []string{"/private/other"}},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, DarwinPathAliases(tc.path))
		})
	}
}
