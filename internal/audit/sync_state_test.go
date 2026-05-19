package audit

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadLastSyncAttempt(t *testing.T) {
	t.Run("missing file returns zero time", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "does-not-exist")
		assert.True(t, ReadLastSyncAttempt(path).IsZero())
	})

	t.Run("empty file returns zero time", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lastrun")
		require.NoError(t, os.WriteFile(path, []byte(""), 0o600))
		assert.True(t, ReadLastSyncAttempt(path).IsZero())
	})

	t.Run("unparseable contents return zero time", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lastrun")
		require.NoError(t, os.WriteFile(path, []byte("not-a-number"), 0o600))
		assert.True(t, ReadLastSyncAttempt(path).IsZero())
	})

	t.Run("valid epoch with trailing whitespace is parsed", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lastrun")
		want := time.Unix(1700000000, 0)
		require.NoError(t, os.WriteFile(path, []byte("1700000000\n"), 0o600))
		assert.True(t, ReadLastSyncAttempt(path).Equal(want))
	})
}

func TestWriteLastSyncAttempt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lastrun")

	before := time.Now()
	require.NoError(t, WriteLastSyncAttempt(path))
	after := time.Now()

	got := ReadLastSyncAttempt(path)
	require.False(t, got.IsZero())

	// Allow 1s slack on both ends to absorb second-level truncation by
	// WriteLastSyncAttempt's Unix() serialization.
	assert.False(t, got.Before(before.Add(-time.Second)), "got=%s before=%s", got, before)
	assert.False(t, got.After(after.Add(time.Second)), "got=%s after=%s", got, after)
}

func TestSyncCooldownElapsed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lastrun")

	t.Run("missing lastrun is treated as old enough", func(t *testing.T) {
		assert.True(t, SyncCooldownElapsed(path, time.Hour))
	})

	t.Run("recent lastrun blocks", func(t *testing.T) {
		require.NoError(t, WriteLastSyncAttempt(path))
		assert.False(t, SyncCooldownElapsed(path, time.Hour))
	})

	t.Run("old lastrun allows", func(t *testing.T) {
		old := time.Now().Add(-2 * time.Hour).Unix()
		require.NoError(t, os.WriteFile(path, []byte(strconv.FormatInt(old, 10)), 0o600))
		assert.True(t, SyncCooldownElapsed(path, time.Hour))
	})
}

func TestSyncLockSerializes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sync.lock")

	first := NewSyncLock(path)
	ok, err := first.TryLock()
	require.NoError(t, err)
	require.True(t, ok)
	defer func() {
		require.NoError(t, first.Unlock())
	}()

	t.Run("TryLock from a sibling lock fails while first is held", func(t *testing.T) {
		second := NewSyncLock(path)
		ok, err := second.TryLock()
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("TryLockContext from a sibling times out while first is held", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		second := NewSyncLock(path)
		ok, err := second.TryLockContext(ctx, 25*time.Millisecond)
		// On context cancel TryLockContext can return either (false, nil) or
		// (false, context.DeadlineExceeded) depending on timing; both satisfy
		// the "did not acquire" assertion.
		if err != nil {
			assert.ErrorIs(t, err, context.DeadlineExceeded)
		}
		assert.False(t, ok)
	})
}

func TestSyncLockAllowsSecondAcquisitionAfterRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.lock")

	wg := sync.WaitGroup{}
	wg.Add(1)
	first := NewSyncLock(path)
	ok, err := first.TryLock()
	require.NoError(t, err)
	require.True(t, ok)

	go func() {
		defer wg.Done()
		// assert (not require) is safe from a goroutine. require.NoError
		// calls t.FailNow which is not goroutine-safe.
		time.Sleep(50 * time.Millisecond)
		assert.NoError(t, first.Unlock())
	}()

	wg.Wait()

	second := NewSyncLock(path)
	ok, err = second.TryLock()
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, second.Unlock())
}
