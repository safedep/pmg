package audit

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

// NewSyncLock returns an unlocked file lock at the given path. The same path
// must be used by manual `pmg cloud sync` and the auto-sync background child
// so they serialize against each other.
func NewSyncLock(path string) *flock.Flock {
	return flock.New(path)
}

// ReadLastSyncAttempt returns the timestamp of the most recent sync attempt
// (success or failure). A missing or unparseable file resolves to the zero
// time so callers can treat "never attempted" as "infinitely old".
func ReadLastSyncAttempt(path string) time.Time {
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}

	secs, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(secs, 0)
}

// WriteLastSyncAttempt records the current time as the latest sync attempt.
// Both the success and failure code paths must call this so a failing cloud
// endpoint does not trigger an attempt on every PMG invocation.
func WriteLastSyncAttempt(path string) error {
	contents := []byte(strconv.FormatInt(time.Now().Unix(), 10))
	return os.WriteFile(path, contents, 0o600)
}

// SyncCooldownElapsed reports whether enough time has passed since the last
// recorded sync attempt to allow a new one.
func SyncCooldownElapsed(path string, minInterval time.Duration) bool {
	last := ReadLastSyncAttempt(path)
	if last.IsZero() {
		return true
	}
	return time.Since(last) >= minInterval
}
