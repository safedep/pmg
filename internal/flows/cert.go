package flows

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/safedep/pmg/truststore"
)

// SetupCACertificate loads the persisted CA from configDir or generates an
// ephemeral one, merges it with the system CA bundle, and writes the result
// to outputPath. Returns the certificate, whether it was ephemeral, and any
// error. The caller is responsible for cleaning up outputPath when ephemeral.
func SetupCACertificate(configDir, outputPath string) (*certmanager.Certificate, bool, error) {
	caCert, persisted := loadPersistedCA(configDir)
	ephemeral := !persisted

	if persisted {
		log.Debugf("Using persisted CA certificate from %s", configDir)
		warnIfCANotTrusted()
	} else {
		log.Debugf("Generating ephemeral CA certificate for proxy MITM")
		generated, err := certmanager.GenerateCA(certmanager.DefaultCertManagerConfig())
		if err != nil {
			return nil, false, fmt.Errorf("generate CA certificate: %w", err)
		}
		caCert = generated
	}

	merged := certmanager.MergeWithSystemCA(caCert.Certificate)
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		return nil, false, fmt.Errorf("create CA certificate directory: %w", err)
	}
	if err := os.WriteFile(outputPath, merged, 0o600); err != nil {
		return nil, false, fmt.Errorf("write CA certificate to %s: %w", outputPath, err)
	}

	log.Debugf("CA certificate written to %s", outputPath)
	return caCert, ephemeral, nil
}

func loadPersistedCA(dir string) (*certmanager.Certificate, bool) {
	caCert, err := certmanager.LoadCA(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("Failed to load persisted CA, using ephemeral: %v", err)
		}
		return nil, false
	}

	if caCert.IsExpired(time.Hour) {
		log.Warnf("Persisted CA is expired; using ephemeral. Re-run `pmg setup cert install`")
		return nil, false
	}

	return caCert, true
}

func warnIfCANotTrusted() {
	user, system, err := truststore.Status(certmanager.CACommonName)
	if err != nil {
		log.Debugf("Could not determine CA trust status: %v", err)
		return
	}

	if !user && !system {
		log.Warnf("Persisted CA is not trusted in the OS store; native tools may reject TLS. Run `pmg setup cert install`.")
	}
}
