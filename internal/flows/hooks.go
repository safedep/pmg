package flows

import (
	"context"
	"fmt"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/packagemanager"
)

type Hook interface {
	BeforeFlow(context.Context, *packagemanager.ParsedCommand) (context.Context, error)
}

type hook func(context.Context, *packagemanager.ParsedCommand) (context.Context, error)

var _ Hook = hook(nil)

func (h hook) BeforeFlow(ctx context.Context, pc *packagemanager.ParsedCommand) (context.Context, error) {
	return h(ctx, pc)
}

func NewSandboxPolicyHook() Hook {
	return hook(func(ctx context.Context, pc *packagemanager.ParsedCommand) (context.Context, error) {
		config := config.Get()

		if pc == nil {
			return ctx, fmt.Errorf("error while executing sandbox hook: got nil parsed command")
		}

		// Only proceed if sandbox is enabled
		if config.Config.Sandbox.Enabled {
			// Apply sandbox to all commands if EnforceAlways=true, otherwise only to installation commands
			config.Config.Sandbox.Enabled = config.Config.Sandbox.EnforceAlways || pc.IsInstallationCommand()
		}

		return ctx, nil
	})
}
