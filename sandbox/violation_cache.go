package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ViolationCacheSchemaVersion is bumped when the on-disk JSON layout changes incompatibly.
const ViolationCacheSchemaVersion = 1

// DefaultViolationCacheRetention is the default number of reports retained in the cache.
const DefaultViolationCacheRetention = 10

const (
	violationCacheFilePrefix = "violation-"
	violationCacheFileSuffix = ".json"
)

// ViolationCacheRecord is the on-disk representation of a ViolationReport.
type ViolationCacheRecord struct {
	SchemaVersion int              `json:"schema_version"`
	RecordedAt    time.Time        `json:"recorded_at"`
	Report        *ViolationReport `json:"report"`
}

// ViolationCacheEntry is a cache entry returned by readers.
type ViolationCacheEntry struct {
	Path   string
	Record ViolationCacheRecord
}

// ViolationCache writes and reads violation reports under dir.
type ViolationCache struct {
	dir       string
	retention int
	now       func() time.Time
}

// ViolationCacheOption customizes a ViolationCache.
type ViolationCacheOption func(*ViolationCache)

// WithRetention overrides the default retention.
func WithRetention(n int) ViolationCacheOption {
	return func(c *ViolationCache) {
		if n > 0 {
			c.retention = n
		}
	}
}

// WithClock injects a clock for tests.
func WithClock(now func() time.Time) ViolationCacheOption {
	return func(c *ViolationCache) {
		if now != nil {
			c.now = now
		}
	}
}

// NewViolationCache returns a ViolationCache rooted at dir. The directory is
// created lazily on Write.
func NewViolationCache(dir string, opts ...ViolationCacheOption) *ViolationCache {
	c := &ViolationCache{
		dir:       dir,
		retention: DefaultViolationCacheRetention,
		now:       time.Now,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Write persists report to the cache and prunes older entries beyond
// retention. Returns the path of the written file.
func (c *ViolationCache) Write(report *ViolationReport) (string, error) {
	if report == nil {
		return "", errors.New("violationcache: nil report")
	}

	if c.dir == "" {
		return "", errors.New("violationcache: empty cache directory")
	}

	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return "", fmt.Errorf("violationcache: create dir: %w", err)
	}

	ts := c.now().UTC()
	id, err := violationCacheShortID()
	if err != nil {
		return "", fmt.Errorf("violationcache: generate id: %w", err)
	}

	name := fmt.Sprintf("%s%s-%s%s", violationCacheFilePrefix, ts.Format("20060102T150405.000000000Z"), id, violationCacheFileSuffix)
	path := filepath.Join(c.dir, name)

	rec := ViolationCacheRecord{
		SchemaVersion: ViolationCacheSchemaVersion,
		RecordedAt:    ts,
		Report:        report,
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", fmt.Errorf("violationcache: marshal: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("violationcache: write: %w", err)
	}

	if err := c.prune(); err != nil {
		return path, fmt.Errorf("violationcache: prune: %w", err)
	}

	return path, nil
}

// List returns entries newest first. Corrupt or unreadable files are skipped.
func (c *ViolationCache) List() ([]ViolationCacheEntry, error) {
	if c.dir == "" {
		return nil, errors.New("violationcache: empty cache directory")
	}

	dirents, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, fmt.Errorf("violationcache: read dir: %w", err)
	}

	files := violationCacheMatchingFiles(dirents)
	violationCacheSortFilesNewestFirst(files)

	entries := make([]ViolationCacheEntry, 0, len(files))
	for _, name := range files {
		path := filepath.Join(c.dir, name)

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var rec ViolationCacheRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		if rec.SchemaVersion != ViolationCacheSchemaVersion {
			continue
		}

		entries = append(entries, ViolationCacheEntry{Path: path, Record: rec})
	}

	return entries, nil
}

// Latest returns the most recent entry, or nil if the cache is empty.
func (c *ViolationCache) Latest() (*ViolationCacheEntry, error) {
	entries, err := c.List()
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, nil
	}

	e := entries[0]
	return &e, nil
}

func (c *ViolationCache) prune() error {
	dirents, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}

	files := violationCacheMatchingFiles(dirents)
	if len(files) <= c.retention {
		return nil
	}

	violationCacheSortFilesNewestFirst(files)

	var firstErr error
	for _, name := range files[c.retention:] {
		if err := os.Remove(filepath.Join(c.dir, name)); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func violationCacheMatchingFiles(dirents []os.DirEntry) []string {
	files := make([]string, 0, len(dirents))
	for _, d := range dirents {
		if d.IsDir() {
			continue
		}

		name := d.Name()
		if len(name) <= len(violationCacheFilePrefix)+len(violationCacheFileSuffix) {
			continue
		}

		if !strings.HasPrefix(name, violationCacheFilePrefix) || !strings.HasSuffix(name, violationCacheFileSuffix) {
			continue
		}

		files = append(files, name)
	}

	return files
}

func violationCacheSortFilesNewestFirst(files []string) {
	sort.Slice(files, func(i, j int) bool { return files[i] > files[j] })
}

func violationCacheShortID() (string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}

	return hex.EncodeToString(buf[:]), nil
}
