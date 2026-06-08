package certmanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeWithSystemCAContainsInput(t *testing.T) {
	ca, err := GenerateCA(DefaultCertManagerConfig())
	require.NoError(t, err)

	merged := MergeWithSystemCA(ca.Certificate)

	// The input cert must always be a prefix of the merged output, regardless
	// of whether a system bundle was found.
	assert.True(t, len(merged) >= len(ca.Certificate))
	assert.Equal(t, ca.Certificate, merged[:len(ca.Certificate)])
}

func TestGenerateCAWithSystemCAStillWorks(t *testing.T) {
	ca, err := GenerateCAWithSystemCA(DefaultCertManagerConfig())
	require.NoError(t, err)
	require.NotNil(t, ca.X509Cert)
	require.NotNil(t, ca.PrivKey)
	assert.NotEmpty(t, ca.Certificate)
}
