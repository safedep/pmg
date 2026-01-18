package flows

import (
	"context"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/packagemanager"
)

type Hook interface {
	BeforeFlow(context.Context, packagemanager.ParsedCommand) (context.Context, error)
}

type hook func(context.Context, packagemanager.ParsedCommand) (context.Context, error)

func (h hook) BeforeFlow(ctx context.Context, pc packagemanager.ParsedCommand) (context.Context, error) {
	return h(ctx, pc)
}

func NewSandboxPolicyHook(ctx context.Context, pc packagemanager.ParsedCommand) Hook {
	return hook(func(ctx context.Context, pc packagemanager.ParsedCommand) (context.Context, error) {
		config := config.Get()
		config.Config.Sandbox.Enabled = config.Config.Sandbox.EnforceAlways || pc.IsInstallationCommand()

		return ctx, nil
	})
}
