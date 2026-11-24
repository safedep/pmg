package cloudauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	drygrpc "github.com/safedep/dry/adapters/grpc"
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/internal/platform"
	"github.com/safedep/pmg/internal/version"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CredentialFileEnv names a file that holds a workload credential. The
// GitHub Action sets it for a proxy daemon that runs as root. That daemon
// cannot exchange a token itself, because the action keeps the ID token
// request token out of its environment.
const CredentialFileEnv = "PMG_CLOUD_CREDENTIAL_FILE"

const (
	toolName = "pmg"

	exchangeAttempts = 2

	// The WorkloadIdentityService runs on the data plane. dry reads the same
	// variable and default for its own exchange connection.
	dataPlaneAddrEnv     = "SAFEDEP_CLOUD_DATA_ADDR"
	defaultDataPlaneAddr = "api.safedep.io:443"
)

// callTimeout bounds one exchange, with its retry, and one revoke. A server
// that takes a call and never answers would otherwise hold the action step,
// and the post step would not remove the credential copies. Tests set it
// shorter.
var callTimeout = 30 * time.Second

// exchangeRetryDelay is the wait before the second exchange attempt. Tests
// set it shorter.
var exchangeRetryDelay = time.Second

// ErrCredentialFileUnsupported is returned on Windows for every use of a
// credential file. pmg checks the owner and the mode of the file, and
// Windows has neither. Only the GitHub Action uses the file, and it runs on
// Linux only.
var ErrCredentialFileUnsupported = errors.New(CredentialFileEnv + " is not supported on Windows")

func credentialFileSupported() error {
	if !platform.Supports(platform.OwnerOnlyFiles) {
		return ErrCredentialFileUnsupported
	}
	return nil
}

// ErrExchangeRefused marks an exchange that SafeDep Cloud refused. For
// example, no trust rule matches the token, the tenant has no usable provider
// or feature, or the tenant is over its cap. pmg then runs with its local
// config.
var ErrExchangeRefused = errors.New("SafeDep Cloud refused the workload identity exchange")

// ExchangeWorkloadIdentity trades the workload identity token of the
// environment for a workload credential of tenantDomain. It asks for the
// maximum life that the trust rule allows, because a proxy daemon that holds
// the credential cannot refresh it. The error wraps
// cloud.ErrNoWorkloadIdentity when the environment has no workload identity,
// and ErrExchangeRefused when SafeDep Cloud refused the exchange.
func ExchangeWorkloadIdentity(ctx context.Context, tenantDomain string) (cloud.WorkloadCredential, error) {
	source, err := cloud.DetectWorkloadIdentitySource()
	if err != nil {
		return cloud.WorkloadCredential{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	var cred cloud.WorkloadCredential
	for attempt := 1; ; attempt++ {
		var attemptTimedOut bool
		err = withExchangeClient(func(client *cloud.WorkloadExchangeClient) error {
			// Each attempt gets its part of the timeout. An attempt that
			// reaches its own deadline is tried again, so a hung first
			// attempt does not use the time of the retry.
			attemptCtx, cancelAttempt := context.WithTimeout(ctx, callTimeout/exchangeAttempts)
			defer cancelAttempt()
			var err error
			cred, err = client.Exchange(attemptCtx, source, cloud.WorkloadExchangeRequest{
				TenantDomain: tenantDomain,
				ToolName:     toolName,
				ToolVersion:  version.Version,
			})
			attemptTimedOut = errors.Is(attemptCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
			return err
		})
		// The exchange gets a new ID token for each attempt, because the
		// server can spend a token before it fails.
		retry := err != nil && (status.Code(err) == codes.Unavailable || attemptTimedOut)
		if attempt == exchangeAttempts || !retry {
			break
		}
		log.Warnf("SafeDep Cloud did not answer the workload identity exchange, pmg tries again: %v", err)
		select {
		case <-ctx.Done():
			// The last attempt's error keeps its gRPC status. ctx.Err() has none.
			return cloud.WorkloadCredential{}, err
		case <-time.After(exchangeRetryDelay):
		}
	}
	if refused(err) {
		return cloud.WorkloadCredential{}, fmt.Errorf("%w: %w", ErrExchangeRefused, err)
	}
	return cred, err
}

// ExchangeToFile runs ExchangeWorkloadIdentity and writes the credential to
// a new file at path with WriteCredentialFile. When the write fails, it
// revokes the credential, because no caller can revoke a credential that it
// does not hold. It then returns a *CredentialWriteError.
func ExchangeToFile(ctx context.Context, tenantDomain, path string) (cloud.WorkloadCredential, error) {
	if err := credentialFileSupported(); err != nil {
		return cloud.WorkloadCredential{}, err
	}
	cred, err := ExchangeWorkloadIdentity(ctx, tenantDomain)
	if err != nil {
		return cloud.WorkloadCredential{}, err
	}
	if err := WriteCredentialFile(path, cred); err != nil {
		writeErr := &CredentialWriteError{Err: err, ExpiresAt: cred.ExpiresAt}
		writeErr.RevokeErr = RevokeWorkloadCredential(ctx, cred)
		if writeErr.RevokeErr != nil {
			log.Warnf("revoke the workload credential that pmg could not write: %v", writeErr.RevokeErr)
		}
		return cloud.WorkloadCredential{}, writeErr
	}
	return cred, nil
}

// ErrCredentialFileWrite marks a credential that pmg got and could not write.
var ErrCredentialFileWrite = errors.New("cannot write the workload credential file")

// CredentialWriteError is a credential that pmg got and could not write.
// RevokeErr is nil when pmg revoked the credential. Otherwise the credential
// stays valid until ExpiresAt.
type CredentialWriteError struct {
	Err       error
	RevokeErr error
	ExpiresAt time.Time
}

func (e *CredentialWriteError) Error() string {
	return fmt.Sprintf("%v: %v", ErrCredentialFileWrite, e.Err)
}

func (e *CredentialWriteError) Unwrap() []error {
	return []error{ErrCredentialFileWrite, e.Err}
}

// RevokeWorkloadCredential revokes cred at once.
func RevokeWorkloadCredential(ctx context.Context, cred cloud.WorkloadCredential) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	return withExchangeClient(func(client *cloud.WorkloadExchangeClient) error {
		return client.Revoke(ctx, cred)
	})
}

// refused reports whether SafeDep Cloud answered the exchange with a denial.
// Any other error, such as a network failure, is not a refusal.
func refused(err error) bool {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.FailedPrecondition, codes.ResourceExhausted, codes.Unauthenticated:
		return true
	default:
		return false
	}
}

// withExchangeClient opens a keyless connection for one call. The
// WorkloadIdentityService refuses a call that carries an API key, and the
// dry adapter sends none for an empty token.
func withExchangeClient(fn func(*cloud.WorkloadExchangeClient) error) error {
	host, port := dataPlaneAddr()
	conn, err := drygrpc.GrpcClient(toolName, host, port, "", http.Header{}, nil)
	if err != nil {
		return fmt.Errorf("connect to SafeDep Cloud at %s: %w", net.JoinHostPort(host, port), err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Warnf("close the workload identity connection: %v", err)
		}
	}()

	return fn(cloud.NewWorkloadExchangeClient(conn))
}

func dataPlaneAddr() (host, port string) {
	addr := os.Getenv(dataPlaneAddrEnv)
	if addr == "" {
		addr = defaultDataPlaneAddr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, "443"
	}
	return host, port
}

// WriteCredentialFile writes cred to a new file that only the current user
// can read. It fails when the file exists, so it never follows a link that
// another user placed.
func WriteCredentialFile(path string, cred cloud.WorkloadCredential) error {
	if err := credentialFileSupported(); err != nil {
		return err
	}
	data, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("encode the workload credential: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create the credential file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		closeErr := f.Close()
		return errors.Join(fmt.Errorf("write the credential file: %w", err), closeErr)
	}
	return f.Close()
}

// ReadCredentialFile reads a file that WriteCredentialFile wrote. The file
// must belong to the current user and give no access to other users. A root
// daemon then never takes a credential from a file that a job step wrote.
func ReadCredentialFile(path string) (cloud.WorkloadCredential, error) {
	if err := credentialFileSupported(); err != nil {
		return cloud.WorkloadCredential{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return cloud.WorkloadCredential{}, fmt.Errorf("open the credential file: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Warnf("close the credential file: %v", err)
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return cloud.WorkloadCredential{}, fmt.Errorf("stat the credential file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return cloud.WorkloadCredential{}, fmt.Errorf("the credential file %s is not a regular file", path)
	}
	uid, ok := platform.FileOwnerUID(info)
	if !ok {
		return cloud.WorkloadCredential{}, fmt.Errorf("cannot read the owner of the credential file %s", path)
	}
	if int64(uid) != int64(os.Geteuid()) {
		return cloud.WorkloadCredential{}, fmt.Errorf("the credential file %s belongs to uid %d, not to uid %d", path, uid, os.Geteuid())
	}
	if info.Mode().Perm()&0o077 != 0 {
		return cloud.WorkloadCredential{}, fmt.Errorf("the credential file %s has mode %v, other users must have no access", path, info.Mode().Perm())
	}

	var cred cloud.WorkloadCredential
	if err := json.NewDecoder(f).Decode(&cred); err != nil {
		return cloud.WorkloadCredential{}, fmt.Errorf("decode the credential file: %w", err)
	}
	if cred.AccessToken == "" || cred.TenantDomain == "" {
		return cloud.WorkloadCredential{}, fmt.Errorf("the credential file %s holds no access token or no tenant", path)
	}
	return cred, nil
}

// credentialFileResolver resolves the workload credential that
// CredentialFileEnv names. SafeDep Cloud takes the access token of a
// workload credential as an API key.
type credentialFileResolver struct {
	path string
}

func (r credentialFileResolver) Resolve() (*cloud.Credentials, error) {
	cred, err := ReadCredentialFile(r.path)
	if err != nil {
		return nil, err
	}
	return cloud.NewAPIKeyCredential(cred.AccessToken, cred.TenantDomain)
}
