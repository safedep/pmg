package config

import (
	"context"
	"fmt"
)

type configKey struct{}
type contextValue struct {
	Config Config
}

// Global configuration
type Config struct {
	Transitive             bool
	TransitiveDepth        int
	IncludeDevDependencies bool
}

// Inject config into context while protecting against context poisoning
func (c Config) Inject(ctx context.Context) context.Context {
	return context.WithValue(ctx, configKey{}, &contextValue{Config: c})
}

// Extract config from context
func FromContext(ctx context.Context) (Config, error) {
	c, ok := ctx.Value(configKey{}).(*contextValue)
	if !ok {
		return Config{}, fmt.Errorf("config not found in context")
	}

	return c.Config, nil
}
