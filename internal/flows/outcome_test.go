package flows

import (
	"errors"
	"testing"

	"github.com/safedep/pmg/internal/ui"
)

func TestInferOutcome(t *testing.T) {
	tests := []struct {
		name               string
		insecureMode       bool
		dryRun             bool
		blockedCount       int
		userCancelledCount int
		err                error
		expectedOutcome    ui.ExecutionOutcome
	}{
		{
			name:               "success - no issues",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       0,
			userCancelledCount: 0,
			err:                nil,
			expectedOutcome:    ui.OutcomeSuccess,
		},
		{
			name:               "error with no blocked packages",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       0,
			userCancelledCount: 0,
			err:                errors.New("execution failed"),
			expectedOutcome:    ui.OutcomeError,
		},
		{
			name:               "error with blocked packages - blocked takes precedence",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       2,
			userCancelledCount: 0,
			err:                errors.New("execution failed"),
			expectedOutcome:    ui.OutcomeBlocked,
		},
		{
			name:               "insecure mode - bypasses all checks",
			insecureMode:       true,
			dryRun:             false,
			blockedCount:       0,
			userCancelledCount: 0,
			err:                nil,
			expectedOutcome:    ui.OutcomeInsecureBypass,
		},
		{
			name:               "insecure mode with error - error takes precedence when blockedCount is 0",
			insecureMode:       true,
			dryRun:             false,
			blockedCount:       0,
			userCancelledCount: 0,
			err:                errors.New("some error"),
			expectedOutcome:    ui.OutcomeError,
		},
		{
			name:               "insecure mode with blocked packages",
			insecureMode:       true,
			dryRun:             false,
			blockedCount:       3,
			userCancelledCount: 0,
			err:                nil,
			expectedOutcome:    ui.OutcomeInsecureBypass,
		},
		{
			name:               "dry run mode",
			insecureMode:       false,
			dryRun:             true,
			blockedCount:       0,
			userCancelledCount: 0,
			err:                nil,
			expectedOutcome:    ui.OutcomeDryRun,
		},
		{
			name:               "dry run with error - error takes precedence when blockedCount is 0",
			insecureMode:       false,
			dryRun:             true,
			blockedCount:       0,
			userCancelledCount: 0,
			err:                errors.New("some error"),
			expectedOutcome:    ui.OutcomeError,
		},
		{
			name:               "dry run with user cancelled",
			insecureMode:       false,
			dryRun:             true,
			blockedCount:       0,
			userCancelledCount: 1,
			err:                nil,
			expectedOutcome:    ui.OutcomeDryRun,
		},
		{
			name:               "user cancelled",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       0,
			userCancelledCount: 1,
			err:                nil,
			expectedOutcome:    ui.OutcomeUserCancelled,
		},
		{
			name:               "user cancelled with error - error takes precedence when blockedCount is 0",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       0,
			userCancelledCount: 1,
			err:                errors.New("some error"),
			expectedOutcome:    ui.OutcomeError,
		},
		{
			name:               "blocked packages",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       1,
			userCancelledCount: 0,
			err:                nil,
			expectedOutcome:    ui.OutcomeBlocked,
		},
		{
			name:               "blocked packages with user cancelled - user cancelled takes precedence for UX",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       2,
			userCancelledCount: 2,
			err:                nil,
			expectedOutcome:    ui.OutcomeUserCancelled,
		},
		{
			name:               "precedence test - insecure overrides dry run",
			insecureMode:       true,
			dryRun:             true,
			blockedCount:       0,
			userCancelledCount: 0,
			err:                nil,
			expectedOutcome:    ui.OutcomeInsecureBypass,
		},
		{
			name:               "precedence test - insecure overrides user cancelled",
			insecureMode:       true,
			dryRun:             false,
			blockedCount:       0,
			userCancelledCount: 1,
			err:                nil,
			expectedOutcome:    ui.OutcomeInsecureBypass,
		},
		{
			name:               "precedence test - insecure overrides blocked",
			insecureMode:       true,
			dryRun:             false,
			blockedCount:       5,
			userCancelledCount: 0,
			err:                nil,
			expectedOutcome:    ui.OutcomeInsecureBypass,
		},
		{
			name:               "precedence test - dry run overrides user cancelled",
			insecureMode:       false,
			dryRun:             true,
			blockedCount:       0,
			userCancelledCount: 1,
			err:                nil,
			expectedOutcome:    ui.OutcomeDryRun,
		},
		{
			name:               "precedence test - error overrides user cancelled when blockedCount is 0",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       0,
			userCancelledCount: 1,
			err:                errors.New("execution failed"),
			expectedOutcome:    ui.OutcomeError,
		},
		{
			name:               "precedence test - user cancelled overrides blocked",
			insecureMode:       false,
			dryRun:             false,
			blockedCount:       1,
			userCancelledCount: 1,
			err:                nil,
			expectedOutcome:    ui.OutcomeUserCancelled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome := inferOutcome(tt.insecureMode, tt.dryRun, tt.blockedCount, tt.userCancelledCount, tt.err)

			if outcome != tt.expectedOutcome {
				t.Errorf("inferOutcome() = %v, want %v", outcome, tt.expectedOutcome)
			}
		})
	}
}

// TestInferOutcomePrecedence specifically tests the precedence order documented in the function
func TestInferOutcomePrecedence(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() (insecureMode, dryRun bool, blockedCount, userCancelledCount int, err error)
		expected    ui.ExecutionOutcome
		description string
	}{
		{
			name: "1. error takes precedence when no blocks",
			setup: func() (bool, bool, int, int, error) {
				return false, false, 0, 0, errors.New("error")
			},
			expected:    ui.OutcomeError,
			description: "Error should be returned when blockedCount is 0",
		},
		{
			name: "2. insecure mode overrides everything",
			setup: func() (bool, bool, int, int, error) {
				return true, true, 5, 2, errors.New("error")
			},
			expected:    ui.OutcomeInsecureBypass,
			description: "Insecure mode is highest priority after error check",
		},
		{
			name: "3. dry run overrides user actions",
			setup: func() (bool, bool, int, int, error) {
				return false, true, 0, 1, nil
			},
			expected:    ui.OutcomeDryRun,
			description: "Dry run takes precedence over user cancellation",
		},
		{
			name: "4. error overrides user cancelled when blockedCount is 0",
			setup: func() (bool, bool, int, int, error) {
				return false, false, 0, 1, errors.New("error")
			},
			expected:    ui.OutcomeError,
			description: "Error takes precedence when blockedCount is 0, even with user cancellation",
		},
		{
			name: "5. blocked packages override everything below",
			setup: func() (bool, bool, int, int, error) {
				return false, false, 3, 0, nil
			},
			expected:    ui.OutcomeBlocked,
			description: "Blocked packages take precedence when count > 0",
		},
		{
			name: "6. success is default",
			setup: func() (bool, bool, int, int, error) {
				return false, false, 0, 0, nil
			},
			expected:    ui.OutcomeSuccess,
			description: "Success when no conditions are met",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insecureMode, dryRun, blockedCount, userCancelledCount, err := tt.setup()
			outcome := inferOutcome(insecureMode, dryRun, blockedCount, userCancelledCount, err)

			if outcome != tt.expected {
				t.Errorf("%s: got %v, want %v", tt.description, outcome, tt.expected)
			}
		})
	}
}
