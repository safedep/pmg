package cloudpolicy

import (
	"testing"
	"time"

	"github.com/safedep/dry/policy/project"
	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The test of dry/policy/bind replaces this test when vet arrives.
func TestBindingTableCoversTheContract(t *testing.T) {
	fields := map[string]project.Field{}
	for _, f := range project.Fields() {
		fields[f.Path] = f
	}

	rows := map[string]bool{PathPackageRules: true}
	for _, row := range bindings {
		rows[row.path] = true
	}

	for _, f := range fields {
		if f.BindingRequired && implementedCapabilities[f.Capability] {
			assert.Truef(t, rows[f.Path], "the binding table has no row for %s, which the contract marks binding_required", f.Path)
		}
	}
	for path := range rows {
		assert.Containsf(t, fields, path, "the binding table names %s, which the contract does not have", path)
	}
}

func TestApplyMinAge(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		wantEnabled bool
		wantDays    int
		wantErr     bool
	}{
		{name: "whole days", value: 72 * time.Hour, wantEnabled: true, wantDays: 3},
		{name: "part of a day rounds up", value: 25 * time.Hour, wantEnabled: true, wantDays: 2},
		{name: "less than a day is one day", value: time.Minute, wantEnabled: true, wantDays: 1},
		{name: "zero turns the cooldown off", value: time.Duration(0), wantEnabled: false, wantDays: 0},
		{name: "a negative value fails", value: -time.Hour, wantErr: true},
		{name: "another type fails", value: int64(3), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{DependencyCooldown: config.DependencyCooldownConfig{Enabled: true, Days: 9}}
			err := applyMinAge(&cfg, tt.value)
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, config.DependencyCooldownConfig{Enabled: true, Days: 9}, cfg.DependencyCooldown)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantEnabled, cfg.DependencyCooldown.Enabled)
			assert.Equal(t, tt.wantDays, cfg.DependencyCooldown.Days)
		})
	}
}
