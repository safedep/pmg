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
	withoutRow := func(path string) []binding {
		var rows []binding
		for _, row := range bindings {
			if row.path != path {
				rows = append(rows, row)
			}
		}
		return rows
	}

	tests := []struct {
		name     string
		rows     []binding
		wantGaps []string
	}{
		{
			name: "the binding table of pmg",
			rows: bindings,
		},
		{
			name:     "a table without the package rules",
			rows:     withoutRow(PathPackageRules),
			wantGaps: []string{"no row for binding_required field " + PathPackageRules},
		},
		{
			name:     "a row for a path that the contract does not have",
			rows:     append(withoutRow(""), binding{path: "core.no_such_field"}),
			wantGaps: []string{"row for unknown field core.no_such_field"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ElementsMatch(t, tt.wantGaps, bindingGaps(tt.rows, project.Fields()))
		})
	}
}

// bindingGaps returns each binding_required field of an implemented
// capability that has no row, and each row whose path is not in the contract.
func bindingGaps(rows []binding, fields []project.Field) []string {
	known := map[string]bool{}
	for _, f := range fields {
		known[f.Path] = true
	}
	bound := map[string]bool{}
	for _, row := range rows {
		bound[row.path] = true
	}

	var gaps []string
	for _, f := range fields {
		if f.BindingRequired && implementedCapabilities[f.Capability] && !bound[f.Path] {
			gaps = append(gaps, "no row for binding_required field "+f.Path)
		}
	}
	for _, row := range rows {
		if !known[row.path] {
			gaps = append(gaps, "row for unknown field "+row.path)
		}
	}
	return gaps
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
