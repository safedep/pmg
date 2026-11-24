package cloud

import (
	"errors"
	"testing"
	"time"

	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/stretchr/testify/assert"
)

func TestCredentialWriteHelp(t *testing.T) {
	expiresAt := time.Date(2026, 11, 23, 18, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "revoked",
			err:  &cloudauth.CredentialWriteError{Err: errors.New("disk full"), ExpiresAt: expiresAt},
			want: "pmg revoked the credential. Check the --output path",
		},
		{
			name: "not revoked",
			err:  &cloudauth.CredentialWriteError{Err: errors.New("disk full"), RevokeErr: errors.New("down"), ExpiresAt: expiresAt},
			want: "pmg could not revoke the credential. It stays valid until 2026-11-23T18:00:00Z. Check the --output path",
		},
		{
			name: "not revoked with no expiry",
			err:  &cloudauth.CredentialWriteError{Err: errors.New("disk full"), RevokeErr: errors.New("down")},
			want: "pmg could not revoke the credential. It stays valid until it expires. Check the --output path",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, credentialWriteHelp(tc.err))
		})
	}
}
