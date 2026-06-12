package interceptors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
)

// persistentCacheSchemaVersion is bumped whenever the on-disk record format
// changes so records written by an older PMG are ignored (treated as a miss)
// rather than mis-parsed.
const persistentCacheSchemaVersion = 1

// persistentCacheRecord is the on-disk JSON representation of a cached verdict.
// Only clean (ALLOW) verdicts are ever written, so the action is implicit and
// not stored. The package coordinates are stored both to reconstruct the
// PackageVersion on read and to detect (extremely unlikely) key-hash collisions.
type persistentCacheRecord struct {
	SchemaVersion int       `json:"schema_version"`
	Ecosystem     string    `json:"ecosystem"`
	Name          string    `json:"name"`
	Version       string    `json:"version"`
	CachedAt      time.Time `json:"cached_at"`
	AnalysisID    string    `json:"analysis_id"`
	ReferenceURL  string    `json:"reference_url"`
	Summary       string    `json:"summary"`
}

// persistentAnalysisCache is a two-tier analysis cache: an in-memory L1 (per
// run) backed by an on-disk L2 that survives across runs. Only ALLOW verdicts
// are persisted; everything else is re-evaluated on every run.
type persistentAnalysisCache struct {
	l1  *inMemoryAnalysisCache
	dir string
	ttl time.Duration
}

var _ AnalysisCache = (*persistentAnalysisCache)(nil)

// NewPersistentAnalysisCache creates a cross-run analysis cache rooted at dir.
// Verdicts older than ttl are ignored. A non-positive ttl makes every disk
// lookup a miss (and skips writes), so the cache behaves like the in-memory one.
func NewPersistentAnalysisCache(dir string, ttl time.Duration) (*persistentAnalysisCache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create analysis cache directory %s: %w", dir, err)
	}

	return &persistentAnalysisCache{
		l1:  NewInMemoryAnalysisCache(),
		dir: dir,
		ttl: ttl,
	}, nil
}

// recordPath maps a package key to its on-disk record path. The key is hashed
// so scoped names (e.g. @scope/pkg) and version strings never produce invalid
// or traversing path segments.
func (c *persistentAnalysisCache) recordPath(ecosystem, name, version string) string {
	sum := sha256.Sum256([]byte(ecosystem + ":" + name + ":" + version))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:])+".json")
}

// Get returns a cached ALLOW verdict for the package, checking the in-memory
// tier first and falling back to disk. A disk hit repopulates the in-memory
// tier. Expired, corrupt, or schema-mismatched records are treated as a miss.
func (c *persistentAnalysisCache) Get(ecosystem, name, version string) (*analyzer.PackageVersionAnalysisResult, bool) {
	if result, ok := c.l1.Get(ecosystem, name, version); ok {
		return result, true
	}

	if c.ttl <= 0 {
		return nil, false
	}

	path := c.recordPath(ecosystem, name, version)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Debugf("Analysis cache: failed to read %s: %v", path, err)
		}
		return nil, false
	}

	var record persistentCacheRecord
	if err := json.Unmarshal(data, &record); err != nil {
		log.Debugf("Analysis cache: corrupt record %s, ignoring: %v", path, err)
		c.remove(path)
		return nil, false
	}

	// Guard against stale formats and (theoretical) hash collisions: a record
	// whose stored coordinates don't match the requested key is not ours.
	if record.SchemaVersion != persistentCacheSchemaVersion ||
		record.Ecosystem != ecosystem || record.Name != name || record.Version != version {
		c.remove(path)
		return nil, false
	}

	if time.Since(record.CachedAt) > c.ttl {
		c.remove(path)
		return nil, false
	}

	result := &analyzer.PackageVersionAnalysisResult{
		PackageVersion: &packagev1.PackageVersion{
			Package: &packagev1.Package{
				Ecosystem: packagev1.Ecosystem(packagev1.Ecosystem_value[ecosystem]),
				Name:      name,
			},
			Version: version,
		},
		Action:       analyzer.ActionAllow,
		AnalysisID:   record.AnalysisID,
		ReferenceURL: record.ReferenceURL,
		Summary:      record.Summary,
	}

	c.l1.Set(ecosystem, name, version, result)
	return result, true
}

// Set always records the verdict in the in-memory tier and additionally
// persists it to disk only when it is a clean ALLOW. Suspicious, malicious, and
// tenant-excluded verdicts are never persisted so they are always re-evaluated.
func (c *persistentAnalysisCache) Set(ecosystem, name, version string, result *analyzer.PackageVersionAnalysisResult) {
	c.l1.Set(ecosystem, name, version, result)

	if c.ttl <= 0 || result == nil {
		return
	}
	if result.Action != analyzer.ActionAllow || result.IsMalware || result.IsExcluded {
		return
	}

	record := persistentCacheRecord{
		SchemaVersion: persistentCacheSchemaVersion,
		Ecosystem:     ecosystem,
		Name:          name,
		Version:       version,
		CachedAt:      time.Now(),
		AnalysisID:    result.AnalysisID,
		ReferenceURL:  result.ReferenceURL,
		Summary:       result.Summary,
	}

	data, err := json.Marshal(record)
	if err != nil {
		log.Debugf("Analysis cache: failed to marshal record for %s/%s@%s: %v", ecosystem, name, version, err)
		return
	}

	if err := c.writeAtomic(c.recordPath(ecosystem, name, version), data); err != nil {
		log.Debugf("Analysis cache: failed to persist %s/%s@%s: %v", ecosystem, name, version, err)
	}
}

// writeAtomic writes data to a sibling temp file and renames it into place, so a
// concurrent reader (or a crash mid-write) never observes a partial record.
func (c *persistentAnalysisCache) writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		c.remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		c.remove(tmpName)
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		c.remove(tmpName)
		return err
	}
	return nil
}

func (c *persistentAnalysisCache) remove(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Debugf("Analysis cache: failed to remove %s: %v", path, err)
	}
}
