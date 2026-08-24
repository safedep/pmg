package analyzer

import (
	"errors"
	"testing"

	"github.com/safedep/dry/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMalysisAnalyzer_CommunityWhenCredentialsUnavailable(t *testing.T) {
	resolver := func() (*cloud.Credentials, func() error, error) {
		return nil, func() error { return nil }, errors.New("no credentials")
	}

	an, err := newMalysisAnalyzer(MalysisQueryAnalyzerConfig{}, resolver)
	require.NoError(t, err)

	retry, ok := an.(*malysisRetryAnalyzer)
	require.True(t, ok, "must be wrapped in the retry decorator, got %T", an)

	community, ok := retry.next.(*malysisQueryAnalyzer)
	require.True(t, ok, "must be the plain community analyzer, got %T", retry.next)
	assert.False(t, community.honorExclusions)
}

func TestNewMalysisAnalyzer_FallbackWrappedWhenCredentialsAvailable(t *testing.T) {
	creds, err := cloud.NewAPIKeyCredential("test-key", "test-tenant")
	require.NoError(t, err)

	resolverClosed := false
	resolver := func() (*cloud.Credentials, func() error, error) {
		return creds, func() error { resolverClosed = true; return nil }, nil
	}

	an, err := newMalysisAnalyzer(MalysisQueryAnalyzerConfig{}, resolver)
	require.NoError(t, err)

	retry, ok := an.(*malysisRetryAnalyzer)
	require.True(t, ok, "credentialed analyzer must be wrapped in the retry decorator, got %T", an)

	fb, ok := retry.next.(*malysisFallbackAnalyzer)
	require.True(t, ok, "credentialed analyzer must carry a community fallback, got %T", retry.next)

	primary, ok := fb.primary.(*malysisQueryAnalyzer)
	require.True(t, ok)
	assert.True(t, primary.honorExclusions, "primary must be the authenticated analyzer")

	fallback, ok := fb.fallback.(*malysisQueryAnalyzer)
	require.True(t, ok)
	assert.False(t, fallback.honorExclusions, "fallback must be the community analyzer")

	assert.True(t, resolverClosed, "credential resolver must be closed after analyzer creation")
}
