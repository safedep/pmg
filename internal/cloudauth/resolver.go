// Package cloudauth provides shared helpers for resolving SafeDep Cloud
// credentials from the local keychain or environment. It centralizes the
// credential resolver chain used by both audit sync and authenticated
// analyzers so the resolution behavior stays consistent.
package cloudauth

import (
	"fmt"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
)

// ResolveCredentials resolves SafeDep Cloud API key credentials using a
// keychain-first, environment-fallback chain. It returns the resolved
// credentials and a close function that releases keychain resources. The
// close function is always non-nil and safe to call regardless of the error.
//
// An error is returned when no credentials are available, which callers can
// use to decide whether authenticated cloud features should be enabled.
func ResolveCredentials() (*cloud.Credentials, func() error, error) {
	var resolvers []cloud.CredentialResolver
	var keychainResolver cloud.CloseableCredentialResolver

	keychainResolver, err := cloud.NewKeychainCredentialResolver(cloud.CredentialTypeAPIKey)
	if err != nil {
		log.Debugf("Keychain credential resolver not available, skipping: %v", err)
	} else {
		resolvers = append(resolvers, keychainResolver)
	}

	envResolver, err := cloud.NewEnvCredentialResolver()
	if err != nil {
		log.Debugf("Env credential resolver not available, skipping: %v", err)
	} else {
		resolvers = append(resolvers, envResolver)
	}

	closeFn := func() error {
		if keychainResolver != nil {
			return keychainResolver.Close()
		}
		return nil
	}

	if len(resolvers) == 0 {
		if err := closeFn(); err != nil {
			log.Warnf("failed to close keychain resolver: %v", err)
		}
		return nil, func() error { return nil }, fmt.Errorf("no credential resolvers available")
	}

	chain := cloud.NewChainCredentialResolver(resolvers...)
	creds, err := chain.Resolve()
	if err != nil {
		if closeErr := closeFn(); closeErr != nil {
			log.Warnf("failed to close keychain resolver: %v", closeErr)
		}
		return nil, func() error { return nil }, fmt.Errorf("failed to resolve cloud credentials: %w", err)
	}

	return creds, closeFn, nil
}
