package config

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/spf13/cobra"
)

// CloudKey is a pmg key that the cloud policy of the tenant sets.
type CloudKey struct {
	// Key is the dotted pmg key, as "dependency_cooldown.days".
	Key string

	// Path is the contract path of the policy field, as
	// "package_admission.cooldown.min_age".
	Path string

	// Label names the setting for people, as "the dependency cooldown".
	Label string

	// Revision is the tenant policy revision that set the key.
	Revision uint64
}

// SetCloudKeys records the keys that the cloud layer set. Only the cloud
// policy loader calls it. A flag on one of these keys then fails.
func (r *RuntimeConfig) SetCloudKeys(keys []CloudKey) {
	r.cloudKeys = keys
}

// CloudKeys returns the keys that the cloud layer set.
func (r *RuntimeConfig) CloudKeys() []CloudKey {
	return r.cloudKeys
}

// cloudKey returns the record of a key that the cloud layer set.
func (r *RuntimeConfig) cloudKey(key string) (CloudKey, bool) {
	for _, k := range r.cloudKeys {
		if k.Key == key {
			return k, true
		}
	}
	return CloudKey{}, false
}

// ManagedFileLockedKeys returns each key of keys that the managed file sets
// under global_lockdown. The cloud layer does not change such a key. It
// returns nil when no lockdown is in force. A managed file that pmg cannot
// read locks every key, so the cloud never overrides a file that IT wrote.
func (r *RuntimeConfig) ManagedFileLockedKeys(keys []string) []string {
	if !r.IsLocked() {
		return nil
	}

	raw, err := readConfigFileKeys(r.configFilePath)
	if err != nil {
		log.Warnf("could not read the managed config %q to find its keys (%v); the cloud policy keeps every key of it", r.configFilePath, err)
		return keys
	}

	var locked []string
	for _, key := range keys {
		if mapHasDottedKey(raw, key) {
			locked = append(locked, key)
		}
	}
	return locked
}

// mapHasDottedKey reports whether the YAML mapping m sets the dotted key.
func mapHasDottedKey(m map[string]any, key string) bool {
	head, rest, nested := strings.Cut(key, ".")
	value, ok := m[head]
	if !ok {
		return false
	}
	if !nested {
		return true
	}
	child, ok := value.(map[string]any)
	if !ok {
		return false
	}
	return mapHasDottedKey(child, rest)
}

// RejectCloudPolicyFlagOverrides fails when the user set a flag on a key that
// the cloud policy sets. Each field of the policy that pmg maps is
// mandatory, so a flag must not override it. Call it after the cloud layer
// applied and after flag parsing.
func RejectCloudPolicyFlagOverrides(cmd *cobra.Command) error {
	for _, f := range configFlagSpecs {
		if !cmd.Flags().Changed(f.name) {
			continue
		}
		for _, key := range f.keys {
			if cloud, ok := Get().cloudKey(key); ok {
				return newCloudPolicyFlagError(f.name, cloud)
			}
		}
	}
	return nil
}

func newCloudPolicyFlagError(flag string, cloud CloudKey) error {
	message := fmt.Sprintf("--%s is not allowed. The policy of your tenant sets %s (%s, policy revision %d)",
		flag, cloud.Label, cloud.Path, cloud.Revision)
	return usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError(message).
		WithHelp("Ask your security admin to change the policy, or remove the flag.").
		Wrap(fmt.Errorf("%s", message))
}
