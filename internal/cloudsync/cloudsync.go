// Package cloudsync runs one sync of pmg with SafeDep Cloud under
// cloud-sync.lock: the policy fetch, the event drain and the check-in. The
// background child, `pmg cloud sync` and the proxy daemon share it, so the
// three steps run in one order everywhere.
package cloudsync

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
	"github.com/safedep/pmg/internal/cloudauth"
	"github.com/safedep/pmg/internal/cloudpolicy"
)

// Step says when a step of a sync runs.
type Step int

const (
	// StepOff skips the step.
	StepOff Step = iota

	// StepDue runs the step when its switch is on and its pacing passed. The
	// sync checks the pacing again under the lock.
	StepDue

	// StepForce runs the step when its switch is on, with no pacing.
	StepForce
)

// Plan says which steps a sync runs.
type Plan struct {
	// Policy is the policy fetch. Its switch is cloud.policy.
	Policy Step

	// Events is the event drain. Its switch is cloud.auto_sync.enabled for
	// StepDue. StepForce drains also with auto_sync off, as `pmg cloud sync`
	// does.
	Events Step

	// LockTimeout bounds the wait for cloud-sync.lock. Zero tries once.
	LockTimeout time.Duration

	// Timeout bounds the steps after the lock.
	Timeout time.Duration

	// AfterPolicy runs after the policy step and before the check-in. The
	// proxy daemon reloads the cache there, so the check-in never reports a
	// revision that the daemon does not yet enforce.
	AfterPolicy func()
}

// Result is what a sync did.
type Result struct {
	// PolicyRan is true when the policy fetch ran. Policy is its result and
	// PolicyErr its error.
	PolicyRan bool
	Policy    *configsync.FetchResult
	PolicyErr error

	// EventsRan is true when the event drain ran. Synced counts the events
	// and EventsErr is its error.
	EventsRan bool
	Synced    int
	EventsErr error

	// CheckInErr is the error of the check-in, or the error that kept pmg
	// from sending it.
	CheckInErr error
}

// steps are the cloud calls of a sync. A test replaces them.
type steps struct {
	resolveCredentials func() (*cloud.Credentials, func() error, error)
	fetchPolicy        func(ctx context.Context, cfg *config.RuntimeConfig, creds *cloud.Credentials) (*configsync.FetchResult, error)
	newEventClient     func(cfg *config.RuntimeConfig, creds *cloud.Credentials) (eventClient, error)
}

type eventClient interface {
	Sync(ctx context.Context) (int, error)
	CheckIn(ctx context.Context, opts ...endpointsync.CheckInOption) error
	Close() error
}

var defaultSteps = steps{
	resolveCredentials: cloudauth.ResolveCredentials,
	fetchPolicy:        cloudpolicy.Fetch,
	newEventClient: func(cfg *config.RuntimeConfig, creds *cloud.Credentials) (eventClient, error) {
		return audit.NewSyncClientBundleWithCredentials(cfg, creds)
	},
}

// Run takes cloud-sync.lock and runs the steps of plan:
//  1. The policy fetch, when cloud.policy applies. It runs also when
//     cloud.auto_sync.enabled is false.
//  2. The event drain.
//  3. The check-in with the cloud policy state, when step 1 or step 2
//     succeeded, with the rate limit of cloud-checkin.lastrun.
//
// It returns audit.ErrSyncInProgress when another process holds the lock,
// and an error when pmg cannot reach the cloud at all. A failure of one step
// is in the Result.
func Run(ctx context.Context, cfg *config.RuntimeConfig, plan Plan) (*Result, error) {
	return defaultSteps.run(ctx, cfg, plan)
}

func (s steps) run(ctx context.Context, cfg *config.RuntimeConfig, plan Plan) (*Result, error) {
	if !cfg.Config.Cloud.Enabled {
		return &Result{}, nil
	}

	lock := audit.NewSyncLock(cfg.CloudSyncLockPath())
	var locked bool
	var err error
	if plan.LockTimeout > 0 {
		lockCtx, cancel := context.WithTimeout(ctx, plan.LockTimeout)
		defer cancel()
		locked, err = lock.TryLockContext(lockCtx, 250*time.Millisecond)
	} else {
		locked, err = lock.TryLock()
	}
	if err != nil {
		return nil, fmt.Errorf("acquire cloud sync lock: %w", err)
	}
	if !locked {
		return nil, audit.ErrSyncInProgress
	}
	defer func() {
		if err := lock.Unlock(); err != nil {
			log.Warnf("failed to release cloud sync lock: %v", err)
		}
	}()

	// The pacing is checked again under the lock, so two processes that
	// both saw a due step do not both run it.
	runPolicy := cfg.CloudPolicyEnabled() &&
		(plan.Policy == StepForce || (plan.Policy == StepDue && audit.PolicyFetchDue(cfg)))
	runEvents := plan.Events == StepForce || (plan.Events == StepDue && audit.EventSyncDue(cfg))
	if !runPolicy && !runEvents {
		log.Debugf("cloud sync: no step is due")
		return &Result{}, nil
	}

	creds, closeResolver, err := s.resolveCredentials()
	if err != nil {
		if runEvents {
			recordEventAttempt(cfg)
		}
		if runPolicy {
			recordPolicyAttempt(cfg)
		}
		return nil, err
	}
	defer func() {
		if err := closeResolver(); err != nil {
			log.Warnf("failed to close keychain resolver: %v", err)
		}
	}()

	runCtx := ctx
	if plan.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, plan.Timeout)
		defer cancel()
	}

	res := &Result{}
	if runPolicy {
		res.PolicyRan = true
		res.Policy, res.PolicyErr = s.fetchPolicy(runCtx, cfg, creds)
	}
	if plan.AfterPolicy != nil {
		plan.AfterPolicy()
	}

	client, err := s.newEventClient(cfg, creds)
	if err != nil {
		err = fmt.Errorf("init cloud sync client: %w", err)
		log.Warnf("cloud sync: %v", err)
		if runEvents {
			recordEventAttempt(cfg)
			res.EventsRan = true
			res.EventsErr = err
		}
		res.CheckInErr = err
		return res, nil
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Warnf("failed to close cloud sync client: %v", err)
		}
	}()

	if runEvents {
		res.EventsRan = true
		res.Synced, res.EventsErr = client.Sync(runCtx)
		// Record the attempt on every outcome, so a stuck endpoint does not
		// make the next invocation retry at once.
		recordEventAttempt(cfg)
	}

	policyOK := res.PolicyRan && res.PolicyErr == nil
	eventsOK := res.EventsRan && res.EventsErr == nil
	if policyOK || eventsOK {
		res.CheckInErr = client.CheckIn(runCtx, checkInOptions(cfg, creds)...)
		if res.CheckInErr != nil {
			log.Warnf("cloud check-in failed: %v", res.CheckInErr)
		}
	}
	return res, nil
}

// checkInOptions adds the cloud policy state of pmg and the reported labels
// to the check-in.
func checkInOptions(cfg *config.RuntimeConfig, creds *cloud.Credentials) []endpointsync.CheckInOption {
	tenant, err := creds.GetTenantDomain()
	if err != nil {
		tenant = ""
	}
	return []endpointsync.CheckInOption{
		endpointsync.WithToolPolicy(cloudpolicy.CheckInState(cfg, tenant)),
		endpointsync.WithLabels(endpointsync.ReportedLabels()),
	}
}

func recordEventAttempt(cfg *config.RuntimeConfig) {
	if err := audit.WriteLastSyncAttempt(cfg.CloudSyncLastRunPath()); err != nil {
		log.Warnf("failed to update cloud sync lastrun: %v", err)
	}
}

func recordPolicyAttempt(cfg *config.RuntimeConfig) {
	if err := audit.WriteLastSyncAttempt(cfg.CloudPolicyLastRunPath()); err != nil {
		log.Warnf("failed to update cloud policy lastrun: %v", err)
	}
}

// Err returns the first error of the steps that ran, so `pmg cloud sync` can
// report it.
func (r *Result) Err() error {
	return errors.Join(r.PolicyErr, r.EventsErr)
}
