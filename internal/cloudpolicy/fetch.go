package cloudpolicy

import (
	"context"
	"fmt"
	"time"

	specv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/policy/spec/v1"
	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/cloud/configsync"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/policy/project"
	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/audit"
)

// FetchInterval is the pacing of the policy fetch, the cadence of the daemon
// in M2. Most replies are NOT_MODIFIED and carry no policy.
const FetchInterval = 5 * time.Minute

// ToolName is the tool name that the fetch and the check-in send.
const ToolName = "pmg"

// FetchDue reports whether the policy pacing passed since the last fetch
// attempt.
func FetchDue(cfg *config.RuntimeConfig) bool {
	return audit.SyncCooldownElapsed(cfg.CloudPolicyLastRunPath(), FetchInterval)
}

// Fetch fetches the resolved policy of this endpoint into the cache of pmg.
// The caller holds cloud-sync.lock, so no other pmg process writes the cache
// at the same time. A failed fetch keeps the cache. Fetch records each
// attempt in cloud-policy.lastrun, so a failing server does not get a fetch
// from each command.
func Fetch(ctx context.Context, cfg *config.RuntimeConfig, creds *cloud.Credentials) (*configsync.FetchResult, error) {
	return fetchAndRecord(ctx, cfg, creds, func(*configsync.Store) (configsync.Transport, func(), error) {
		client, err := cloud.NewDataPlaneClient(ToolName, creds)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create data plane client: %w", err)
		}
		closeClient := func() {
			if err := client.Close(); err != nil {
				log.Warnf("cloud policy: failed to close the cloud client: %v", err)
			}
		}
		return configsync.NewGrpcTransport(client.Connection()), closeClient, nil
	})
}

func fetchAndRecord(ctx context.Context, cfg *config.RuntimeConfig, creds *cloud.Credentials, newTransport transportFactory) (*configsync.FetchResult, error) {
	start := time.Now()
	if err := audit.WriteLastSyncAttempt(cfg.CloudPolicyLastRunPath()); err != nil {
		log.Warnf("cloud policy: failed to update the fetch lastrun: %v", err)
	}

	res, err := fetch(ctx, cfg, creds, newTransport)
	duration := time.Since(start).Round(time.Millisecond)
	if err != nil {
		log.Warnf("cloud policy: fetch failed after %s: %v", duration, err)
		return nil, err
	}
	log.Infof("cloud policy: fetch %s, revision %d, digest %s, in %s", res.Status, res.Revision, res.Digest, duration)
	return res, nil
}

// transportFactory gives the fetch its transport. Tests pass a stub.
type transportFactory func(store *configsync.Store) (configsync.Transport, func(), error)

func fetch(ctx context.Context, cfg *config.RuntimeConfig, creds *cloud.Credentials, newTransport transportFactory) (*configsync.FetchResult, error) {
	tenant, err := creds.GetTenantDomain()
	if err != nil {
		return nil, fmt.Errorf("cloud policy: the login has no tenant: %w", err)
	}

	endpoint, err := audit.NewEndpointIdentityResolver(cfg).Resolve()
	if err != nil {
		return nil, fmt.Errorf("cloud policy: cannot resolve the endpoint identity: %w", err)
	}

	store, err := configsync.NewStore(cfg.CloudPolicyCacheDir(), configsync.WithTenant(tenant))
	if err != nil {
		return nil, err
	}

	transport, closeTransport, err := newTransport(store)
	if err != nil {
		return nil, err
	}
	if closeTransport != nil {
		defer closeTransport()
	}

	fetcher, err := configsync.NewFetcher(store, transport)
	if err != nil {
		return nil, err
	}

	expect := project.Expect{
		Tenant:      tenant,
		SubjectKind: specv1.SubjectKind_SUBJECT_KIND_ENDPOINT,
		MachineID:   endpoint.GetMachineId(),
	}
	return fetcher.Fetch(ctx, configsync.FetchRequest{
		Endpoint:    endpoint,
		Labels:      endpointsync.ReportedLabels(),
		ToolName:    ToolName,
		ToolVersion: audit.ToolVersion(),
		Validate:    fetchValidator(store, expect),
	})
}

// fetchValidator is the header check and the projection of pmg. It returns
// in Accepted the capabilities that come from an older file, so the commit
// records them with the policy. A capability that fails in the new policy
// comes from the file that capability_sources names for it, or else from
// the current file when that file applied it.
func fetchValidator(store *configsync.Store, expect project.Expect) configsync.Validator {
	return func(raw []byte) (configsync.Accepted, error) {
		proj, err := project.Decode(raw, expect)
		if err != nil {
			return configsync.Accepted{}, err
		}
		if len(proj.FailedCapabilities) == 0 {
			return configsync.Accepted{}, nil
		}

		state, err := store.State()
		if err != nil || state.Tenant != expect.Tenant {
			return configsync.Accepted{}, nil
		}

		sources := map[string]string{}
		for _, capability := range proj.FailedCapabilities {
			digest, ok := state.CapabilitySources[capability]
			if !ok {
				digest = state.Digest
			}
			if appliesCapability(store, digest, capability, expect) {
				sources[capability] = digest
			}
		}
		return configsync.Accepted{CapabilitySources: sources}, nil
	}
}

// appliesCapability reports whether the policy file of digest holds a valid
// value of capability.
func appliesCapability(store *configsync.Store, digest, capability string, expect project.Expect) bool {
	if digest == "" {
		return false
	}
	raw, err := store.ReadPolicy(digest)
	if err != nil {
		return false
	}
	proj, err := project.Decode(raw, expect)
	if err != nil {
		return false
	}
	for _, failed := range proj.FailedCapabilities {
		if failed == capability {
			return false
		}
	}
	return true
}
