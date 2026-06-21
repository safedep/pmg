package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer/malysiscache"
	"github.com/safedep/pmg/config"
	"github.com/spf13/cobra"
)

// NewCacheCommand returns the `pmg setup cache` command tree.
func NewCacheCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache",
		Short: "Inspect and clear PMG's persistent analysis cache",
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newCacheStatusCommand())
	cmd.AddCommand(newCacheClearCommand())
	return cmd
}

func newCacheStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "status",
		Short:        "Show analysis cache path, state, TTL, and entry count",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCacheStatus(cmd.Context(), config.Get(), os.Stdout)
		},
	}
}

func newCacheClearCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "clear",
		Short:        "Delete all cached analysis verdicts",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCacheClear(cmd.Context(), config.Get(), os.Stdout)
		},
	}
}

// openCache opens the shared localdb and the malysis cache module. exists is
// false when the DB file is absent (nothing cached yet); the caller decides how
// to report that without creating the file.
func openCache(ctx context.Context, cfg *config.RuntimeConfig) (cache *malysiscache.Cache, closeFn func(), exists bool, err error) {
	dbPath := filepath.Join(cfg.LocalDBDir(), cfg.LocalDBFileName())
	if _, statErr := os.Stat(dbPath); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil, func() {}, false, nil
		}
		return nil, func() {}, false, statErr
	}

	mgr := localdb.New(localdb.Config{Dir: cfg.LocalDBDir(), FileName: cfg.LocalDBFileName()})
	store, serr := mgr.Store(ctx, malysiscache.Descriptor())
	if serr != nil {
		if cerr := mgr.Close(); cerr != nil {
			log.Warnf("failed to close localdb: %v", cerr)
		}
		return nil, func() {}, true, serr
	}
	closeFn = func() {
		if cerr := mgr.Close(); cerr != nil {
			log.Warnf("failed to close localdb: %v", cerr)
		}
	}
	return malysiscache.New(store, cfg.Config.AnalysisCache.Malysis), closeFn, true, nil
}

func runCacheStatus(ctx context.Context, cfg *config.RuntimeConfig, out io.Writer) error {
	mc := cfg.Config.AnalysisCache.Malysis
	dbPath := filepath.Join(cfg.LocalDBDir(), cfg.LocalDBFileName())

	cache, closeFn, exists, err := openCache(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open analysis cache: %w", err)
	}
	defer closeFn()

	count := 0
	if exists {
		stats, serr := cache.Stats(ctx)
		if serr != nil {
			return fmt.Errorf("read analysis cache: %w", serr)
		}
		count = stats.Count
	}

	if _, err := fmt.Fprintf(out, "Path:    %s\nEnabled: %v\nTTL:     %s\nEntries: %d\n",
		dbPath, mc.Enabled, mc.TTL, count); err != nil {
		return err
	}
	return nil
}

func runCacheClear(ctx context.Context, cfg *config.RuntimeConfig, out io.Writer) error {
	cache, closeFn, exists, err := openCache(ctx, cfg)
	if err != nil {
		return fmt.Errorf("open analysis cache: %w", err)
	}
	defer closeFn()

	if !exists {
		if _, werr := fmt.Fprintln(out, "Analysis cache is already empty."); werr != nil {
			return werr
		}
		return nil
	}

	if err := cache.Clear(ctx); err != nil {
		return fmt.Errorf("clear analysis cache: %w", err)
	}
	if _, werr := fmt.Fprintln(out, "Analysis cache cleared."); werr != nil {
		return werr
	}
	return nil
}
