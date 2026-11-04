package cloudpolicy

import (
	"os"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

// Apply runs the binding table over target, the config of cfg or a copy of
// it. Under global_lockdown a whole row does not apply when the managed file
// sets any key of it, so a file that sets dependency_cooldown.days also
// keeps dependency_cooldown.enabled.
func Apply(cfg *config.RuntimeConfig, target *config.Config, st *Status) {
	st.Keys = nil
	st.Locked = nil
	st.cooldownCitation = nil
	if st.Projection == nil || st.Applied == nil {
		return
	}

	for _, row := range bindings {
		if row.apply == nil {
			continue
		}

		value, ok := st.Projection.Values[row.path]
		if !ok {
			continue
		}

		if locked := cfg.ManagedFileLockedKeys(row.keys); len(locked) > 0 {
			log.Debugf("cloud policy: global_lockdown keeps %s from the managed config", strings.Join(locked, ", "))
			st.Locked = append(st.Locked, row.path)
			continue
		}

		if err := row.apply(target, value); err != nil {
			log.Warnf("cloud policy: cannot apply %s: %v", row.path, err)
			continue
		}

		for _, key := range row.keys {
			logIgnoredEnv(key)
			st.Keys = append(st.Keys, config.CloudKey{
				Key:      key,
				Path:     row.path,
				Label:    row.label,
				Revision: st.Applied.Revision,
			})
		}

		if row.path == PathMinAge {
			st.cooldownCitation = fieldCitation(st.Applied, row.path, st.Projection)
		}
	}
}

// logIgnoredEnv logs at debug that the cloud value of key wins over its
// environment variable. Each field that pmg maps is mandatory.
func logIgnoredEnv(key string) {
	name := "PMG_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
	if _, set := os.LookupEnv(name); set {
		log.Debugf("cloud policy: %s is ignored, the policy of the tenant sets %s", name, key)
	}
}

// LoadAtStart loads the policy cache and applies the cloud layer to the
// config of cfg. The root command calls it after the config loads and before
// the flags are final, so a flag on a key that the cloud set can fail. It
// resolves the cloud login only when cloud.policy applies.
func (r *Runtime) LoadAtStart(cfg *config.RuntimeConfig) *Status {
	tenant := ""
	if cfg.CloudPolicyEnabled() {
		tenant = loginTenant()
	}
	return r.LoadAtStartForTenant(cfg, tenant)
}

// LoadAtStartForTenant is LoadAtStart for a caller that knows the tenant of
// the login, or "" for no login. It does not touch the keychain.
func (r *Runtime) LoadAtStartForTenant(cfg *config.RuntimeConfig, tenant string) *Status {
	r.baseline = cfg.Config.DependencyCooldown

	st := Load(cfg, tenant)
	Apply(cfg, &cfg.Config, st)
	cfg.SetCloudKeys(st.Keys)
	r.status.Store(st)
	return st
}

// Publish makes the policy of the last load the current policy, with the
// cooldown of cfg after the flags. The root command calls it once the flags
// are final.
func (r *Runtime) Publish(cfg *config.RuntimeConfig) {
	st := r.status.Load()
	if st == nil {
		// An internal command, such as a sandbox helper, loads no cache. It
		// runs for each sandboxed process, so it applies only
		// blocked_packages.
		r.current.Store(FromConfig(cfg))
		return
	}
	r.current.Store(newPolicy(st, cfg.Config.DependencyCooldown))
}

// Reload loads the cache again and swaps in the new policy. The proxy daemon
// calls it after a fetch commits a new policy, so a new min_age applies with
// no restart. It applies the cloud layer to a copy of the config, on top of
// the cooldown from before the first cloud layer.
func (r *Runtime) Reload(cfg *config.RuntimeConfig) *Status {
	tenant := ""
	if cfg.CloudPolicyEnabled() {
		tenant = loginTenant()
	}

	st := Load(cfg, tenant)

	target := cfg.Config
	target.DependencyCooldown = r.baseline
	if config.SkipDependencyCooldownRequested() {
		target.DependencyCooldown.Enabled = false
	}
	Apply(cfg, &target, st)

	r.status.Store(st)
	r.current.Store(newPolicy(st, target.DependencyCooldown))
	return st
}

func newPolicy(st *Status, cooldown config.DependencyCooldownConfig) *Policy {
	return &Policy{
		index:            st.index,
		Cooldown:         cooldown,
		cooldownCitation: st.cooldownCitation,
		applied:          st.Applied,
	}
}
