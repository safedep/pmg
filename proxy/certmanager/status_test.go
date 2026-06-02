package certmanager

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectCAAbsent(t *testing.T) {
	st, err := InspectCA(t.TempDir())
	require.NoError(t, err)
	assert.False(t, st.KeyPresent)
	assert.False(t, st.CertPresent)
}

func TestInspectCAPresent(t *testing.T) {
	dir := t.TempDir()
	ca, err := GenerateCA(PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, SaveCA(dir, ca))

	st, err := InspectCA(dir)
	require.NoError(t, err)
	assert.True(t, st.KeyPresent)
	assert.True(t, st.CertPresent)
	assert.False(t, st.Expired)
	assert.NotEmpty(t, st.Fingerprint)
	assert.WithinDuration(t, ca.X509Cert.NotAfter, st.NotAfter, time.Second)
}

func TestCAStatusDrift(t *testing.T) {
	cases := []struct {
		name      string
		status    CAStatus
		wantDrift bool
	}{
		{"healthy", CAStatus{KeyPresent: true, CertPresent: true}, false},
		{"cert without key", CAStatus{CertPresent: true}, true},
		{"key without cert", CAStatus{KeyPresent: true}, true},
		{"expired", CAStatus{KeyPresent: true, CertPresent: true, Expired: true}, true},
		{"expiring soon is not drift", CAStatus{KeyPresent: true, CertPresent: true, ExpiringSoon: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drift, reason := tc.status.Drift()
			assert.Equal(t, tc.wantDrift, drift)
			if tc.wantDrift {
				assert.NotEmpty(t, reason)
			}
		})
	}
}

func TestCAStatusTrusted(t *testing.T) {
	assert.True(t, CAStatus{UserTrusted: true}.Trusted())
	assert.True(t, CAStatus{SystemTrusted: true}.Trusted())
	assert.False(t, CAStatus{}.Trusted())
}
