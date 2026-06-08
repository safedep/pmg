package certmanager

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// ExpiryWarnWindow is how close to NotAfter a CA must be before status/doctor
// surface an expiry warning.
const ExpiryWarnWindow = 30 * 24 * time.Hour

// CAStatus is the reusable status model shared by `cert status`, `setup doctor`,
// and `setup info`. Disk-side fields are filled by InspectCA; trust fields are
// filled by the caller from the truststore package (kept here so certmanager
// stays free of any OS/trust-store import).
type CAStatus struct {
	KeyPresent    bool
	CertPresent   bool
	NotAfter      time.Time
	Expired       bool
	ExpiringSoon  bool
	Fingerprint   string
	UserTrusted   bool
	SystemTrusted bool
}

func (s CAStatus) Trusted() bool { return s.UserTrusted || s.SystemTrusted }

// Drift reports on-disk integrity / expiry problems independent of OS trust
// policy. Trust-store presence is intentionally NOT evaluated here: "not in a
// store" is normal on Linux (Go honors SSL_CERT_FILE), so consumers interpret
// trust state per platform.
func (s CAStatus) Drift() (bool, string) {
	if s.CertPresent && !s.KeyPresent {
		return true, "CA certificate on disk but private key missing"
	}
	if s.KeyPresent && !s.CertPresent {
		return true, "CA private key on disk but certificate missing"
	}
	if s.KeyPresent && s.Expired {
		return true, "CA expired; re-run `pmg setup cert install`"
	}
	return false, ""
}

// InspectCA gathers disk-side CA facts from dir. Absence of the files is not an
// error; the returned CAStatus simply reports them as not present.
func InspectCA(dir string) (CAStatus, error) {
	var st CAStatus

	if _, err := os.Stat(CAKeyPath(dir)); err == nil {
		st.KeyPresent = true
	}

	certPEM, err := os.ReadFile(CACertPath(dir))
	if err != nil {
		return st, nil
	}
	st.CertPresent = true

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return st, fmt.Errorf("failed to decode CA certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return st, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	st.NotAfter = x509Cert.NotAfter
	st.Expired = time.Now().After(x509Cert.NotAfter)
	st.ExpiringSoon = !st.Expired && time.Until(x509Cert.NotAfter) < ExpiryWarnWindow

	sum := sha256.Sum256(x509Cert.Raw)
	st.Fingerprint = hex.EncodeToString(sum[:])

	return st, nil
}
