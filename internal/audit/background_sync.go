package audit

import (
	"os"
	"os/exec"

	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/config"
)

// SyncBackgroundSubcommand is the cobra `Use` of the hidden child command
// that MaybeSpawnBackgroundSync forks. Shared with cmd/cloud so renaming the
// command can't desync the spawn args from the cobra registration.
const SyncBackgroundSubcommand = "sync-background"

// isBackgroundSyncChild gates MaybeSpawnBackgroundSync against a respawn
// chain when an early-exit child (e.g. losing the lock race) leaves
// cloud-sync.lastrun stale.
var isBackgroundSyncChild bool

func MarkBackgroundSyncChild() {
	isBackgroundSyncChild = true
}

// backgroundSyncSuppressed lets a command opt out of the detached auto-sync
// spawn for its process. The proxy daemon uses this: it delivers events itself
// (periodic sync + shutdown flush), so the detached child would be redundant
// and, from `pmg proxy stop`, would route cloud traffic through the now-stopped
// proxy.
var backgroundSyncSuppressed bool

// SuppressBackgroundSync disables MaybeSpawnBackgroundSync for the current
// process.
func SuppressBackgroundSync() {
	backgroundSyncSuppressed = true
}

// detachedSpawner forks a detached child running `name` with `args`. Pulled
// behind a package var so tests can intercept without actually forking the
// test binary into the background.
type detachedSpawner func(name string, args ...string) error

var spawnDetached detachedSpawner = spawnDetachedExec

// MaybeSpawnBackgroundSync forks a detached `pmg cloud sync-background` child
// when auto-sync is enabled and the cooldown has elapsed. The call returns as
// soon as `cmd.Start()` finishes (~milliseconds), so it must only be called
// after audit.Close() has released the parent's SQLite handle on the WAL.
//
// All failures are logged and swallowed: auto-sync is opportunistic and must
// never affect the parent PMG invocation's exit behavior or user-visible
// output.
func MaybeSpawnBackgroundSync(cfg *config.RuntimeConfig) {
	if cfg == nil {
		return
	}
	if isBackgroundSyncChild || backgroundSyncSuppressed {
		return
	}
	if !cfg.Config.Cloud.Enabled || !cfg.Config.Cloud.AutoSync.Enabled {
		return
	}

	if !SyncCooldownElapsed(cfg.CloudSyncLastRunPath(), cfg.Config.Cloud.AutoSync.MinInterval) {
		log.Debugf("Auto-sync cooldown not elapsed; skipping spawn")
		return
	}

	pmgPath, err := os.Executable()
	if err != nil {
		log.Warnf("Auto-sync: failed to resolve pmg binary path: %v", err)
		return
	}

	// This may seem like a pollution of concerns because the internal audit package
	// is aware of the CLI cmd layer. We mitigate the risk by having SSOT for sub-command
	// definition. We gain simplicity of the API that can be plugged in to appropriate
	// hook point in the main command handler.
	if err := spawnDetached(pmgPath, "cloud", SyncBackgroundSubcommand); err != nil {
		log.Warnf("Auto-sync: failed to spawn background sync child: %v", err)
	}
}

// spawnDetachedExec is the production implementation of detachedSpawner. It
// redirects stdio to /dev/null, applies platform-specific detach attributes,
// and starts the child without waiting on it.
func spawnDetachedExec(name string, args ...string) error {
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	// We hand the fd to exec, which dup's it onto the child's stdio; we can
	// close our own copy as soon as Start returns.
	defer func() {
		if closeErr := devNull.Close(); closeErr != nil {
			log.Warnf("Auto-sync: failed to close %s handle: %v", os.DevNull, closeErr)
		}
	}()

	cmd := exec.Command(name, args...)
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	applyDetachAttrs(cmd)

	if err := cmd.Start(); err != nil {
		return err
	}

	// On Unix, Setsid already orphans the child to init; Release just drops
	// our os.Process reference so we don't accumulate a zombie if the parent
	// process group is reused.
	if err := cmd.Process.Release(); err != nil {
		log.Warnf("Auto-sync: failed to release background sync child: %v", err)
	}
	return nil
}
