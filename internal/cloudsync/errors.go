package cloudsync

import (
	"errors"
	"fmt"

	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/internal/cloudpolicy"
)

// ErrNoPolicy means that no cloud policy applies after the fetch. It wraps
// the error of the fetch when the fetch failed.
var ErrNoPolicy = errors.New("no cloud policy applies")

// ErrPolicyRejected means that pmg got a policy from the cloud and did not
// accept it.
var ErrPolicyRejected = errors.New("pmg did not accept the cloud policy")

// PolicyWarning is a failed policy fetch that does not stop the command.
// Revision is the revision of the cached policy that still applies. It is 0
// when the plan of the tenant has no policy management.
type PolicyWarning struct {
	Revision uint64
	Err      error
}

func (w *PolicyWarning) Error() string {
	return fmt.Sprintf("fetch cloud policy (revision %d applies): %v", w.Revision, w.Err)
}

func (w *PolicyWarning) Unwrap() error { return w.Err }

// checkPolicy turns the result of the fetch into the decision of
// RequirePolicy: nil, a *PolicyWarning, or an error that wraps ErrNoPolicy.
func checkPolicy(fetchErr error, st *cloudpolicy.Status) error {
	if st != nil && st.Applied != nil {
		if fetchErr != nil {
			return &PolicyWarning{Revision: st.Applied.Revision, Err: fetchErr}
		}
		return nil
	}

	// A tenant whose plan has no policy management cannot have a policy, so
	// a missing policy is expected there and does not stop the command.
	if usefulErr, ok := usefulerror.AsUsefulError(fetchErr); ok && usefulErr.Code() == usefulerror.ErrMissingEntitlements {
		return &PolicyWarning{Err: fetchErr}
	}

	switch {
	case fetchErr == nil:
		return fmt.Errorf("%w: %w", ErrNoPolicy, ErrPolicyRejected)
	case isRejectedPolicy(fetchErr):
		return fmt.Errorf("%w: %w: %w", ErrNoPolicy, ErrPolicyRejected, fetchErr)
	default:
		return fmt.Errorf("%w: %w", ErrNoPolicy, fetchErr)
	}
}

// isRejectedPolicy reports whether pmg got a policy from the cloud and did
// not accept it.
func isRejectedPolicy(err error) bool {
	for _, rejected := range []error{
		configsync.ErrRejected, configsync.ErrDigestMismatch, configsync.ErrInvalidDigest,
		configsync.ErrLowerRevision, configsync.ErrTooLarge, configsync.ErrTenantMismatch,
	} {
		if errors.Is(err, rejected) {
			return true
		}
	}
	return false
}
