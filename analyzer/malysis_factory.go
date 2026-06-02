package analyzer

import (
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/cloudauth"
)

// NewMalysisAnalyzer creates the malysis query analyzer best suited for the
// current environment. When SafeDep Cloud credentials are available (via
// keychain or environment), it returns an authenticated analyzer that queries
// api.safedep.io and honors tenant-specific package exclusions. Otherwise it
// falls back to the unauthenticated community analyzer.
func NewMalysisAnalyzer(config MalysisQueryAnalyzerConfig) (PackageVersionAnalyzer, error) {
	creds, closeResolver, err := cloudauth.ResolveCredentials()
	if err != nil {
		log.Debugf("SafeDep Cloud credentials unavailable, using community malysis analyzer: %v", err)
		return NewMalysisQueryAnalyzer(config)
	}
	defer func() {
		if closeErr := closeResolver(); closeErr != nil {
			log.Warnf("failed to close credential resolver: %v", closeErr)
		}
	}()

	log.Debugf("SafeDep Cloud credentials found, using authenticated malysis analyzer")
	return NewMalysisAuthenticatedQueryAnalyzer(config, creds)
}
