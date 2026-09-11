//go:build unix

package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const privilegeRemedyWord = "sudo pmg setup install --system"

func TestIsSudoCountsTheMarkerOnlyWhenPrivileged(t *testing.T) {
	tests := []struct {
		name       string
		privileged bool
		sudoUser   string
		want       bool
	}{
		{name: "sudo from a person", privileged: true, sudoUser: "alice", want: true},
		{name: "root without sudo", privileged: true, sudoUser: "", want: false},
		{name: "a user who set the marker", privileged: false, sudoUser: "alice", want: false},
		{name: "a user", privileged: false, sudoUser: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withPrivilege(t, tt.privileged)
			t.Setenv("SUDO_USER", tt.sudoUser)
			assert.Equal(t, tt.want, IsSudo())
		})
	}
}
