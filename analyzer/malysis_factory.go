package analyzer

import (
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/cloudauth"
)

type credentialsResolver func() (*cloud.Credentials, func() error, error)

// NewMalysisAnalyzer creates the malysis query analyzer best suited for the
// current environment. When SafeDep Cloud credentials are available (via
// keychain or environment), it returns an authenticated analyzer that queries
// api.safedep.io and honors tenant-specific package exclusions, degrading to
// the unauthenticated community analyzer if the API rejects the credentials.
// When no credentials are available, it returns the community analyzer.
func NewMalysisAnalyzer(config MalysisQueryAnalyzerConfig) (PackageVersionAnalyzer, error) {
	return newMalysisAnalyzer(config, cloudauth.ResolveCredentials)
}

func newMalysisAnalyzer(config MalysisQueryAnalyzerConfig,
	resolveCredentials credentialsResolver) (PackageVersionAnalyzer, error) {
	community, err := NewMalysisQueryAnalyzer(config)
	if err != nil {
		return nil, err
	}

	creds, closeResolver, err := resolveCredentials()
	if err != nil {
		log.Debugf("SafeDep Cloud credentials unavailable, using community malysis analyzer: %v", err)
		return withCache(community, config), nil
	}
	defer func() {
		if closeErr := closeResolver(); closeErr != nil {
			log.Warnf("failed to close credential resolver: %v", closeErr)
		}
	}()

	authenticated, err := NewMalysisAuthenticatedQueryAnalyzer(config, creds)
	if err != nil {
		return nil, err
	}

	log.Debugf("SafeDep Cloud credentials found, using authenticated malysis analyzer with community fallback")
	return withCache(newMalysisFallbackAnalyzer(authenticated, community), config), nil
}

// withCache wraps a in a read-through cache decorator when one is configured.
func withCache(a PackageVersionAnalyzer, config MalysisQueryAnalyzerConfig) PackageVersionAnalyzer {
	if config.Cache == nil {
		return a
	}
	return newMalysisCachingAnalyzer(a, config.Cache)
}
