// Package malysiscache provides concrete implementations of the
// analyzer.MalysisCache contract. The sqlite implementation persists clean
// analysis verdicts across runs so repeat installs of an unchanged dependency
// graph skip re-screening.
package malysiscache

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/pmg/analyzer"

	_ "modernc.org/sqlite"
)

// schemaVersion is embedded in the table name so an incompatible record format
// in a future version starts a fresh table instead of mis-reading old rows.
const schemaVersion = 1

// SQLiteCache is a sqlite-backed analyzer.MalysisCache. It is safe for
// concurrent use; the underlying *sql.DB manages its own connection pool and
// sqlite serializes writes.
type SQLiteCache struct {
	db    *sql.DB
	ttl   time.Duration
	table string
}

var _ analyzer.MalysisCache = (*SQLiteCache)(nil)

// NewSQLiteCache opens (creating if needed) a sqlite cache at path. Entries
// older than ttl are treated as a miss. The caller owns the returned cache and
// must Close it.
func NewSQLiteCache(path string, ttl time.Duration) (*SQLiteCache, error) {
	// WAL + busy_timeout keep concurrent PMG invocations from erroring on lock
	// contention; foreign_keys is irrelevant here but harmless.
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open analysis cache db: %w", err)
	}

	c := &SQLiteCache{
		db:    db,
		ttl:   ttl,
		table: fmt.Sprintf("malysis_cache_v%d", schemaVersion),
	}

	if err := c.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}

	return c, nil
}

func (c *SQLiteCache) init(ctx context.Context) error {
	_, err := c.db.ExecContext(ctx, fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			key          TEXT PRIMARY KEY,
			cached_at    INTEGER NOT NULL,
			action       INTEGER NOT NULL,
			analysis_id  TEXT,
			reference_url TEXT,
			summary      TEXT
		)`, c.table))
	if err != nil {
		return fmt.Errorf("failed to initialize analysis cache schema: %w", err)
	}
	return nil
}

// Close releases the underlying database handle.
func (c *SQLiteCache) Close() error {
	return c.db.Close()
}

// key derives a stable cache key from a package version. The ecosystem enum
// name is used (not the numeric value) so keys remain stable across proto
// regenerations.
func key(pkg *packagev1.PackageVersion) string {
	return pkg.GetPackage().GetEcosystem().String() + ":" +
		pkg.GetPackage().GetName() + ":" + pkg.GetVersion()
}

// Get returns a cached verdict for pkg if present and not expired. The returned
// result carries the queried pkg as its PackageVersion.
func (c *SQLiteCache) Get(ctx context.Context, pkg *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, bool, error) {
	if pkg == nil {
		return nil, false, nil
	}
	if c.ttl <= 0 {
		return nil, false, nil
	}

	var (
		cachedAt     int64
		action       int
		analysisID   sql.NullString
		referenceURL sql.NullString
		summary      sql.NullString
	)

	row := c.db.QueryRowContext(ctx,
		fmt.Sprintf("SELECT cached_at, action, analysis_id, reference_url, summary FROM %s WHERE key = ?", c.table),
		key(pkg))
	switch err := row.Scan(&cachedAt, &action, &analysisID, &referenceURL, &summary); err {
	case nil:
		// found
	case sql.ErrNoRows:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("failed to read analysis cache: %w", err)
	}

	if time.Since(time.Unix(cachedAt, 0)) > c.ttl {
		// Expired. Best-effort delete; ignore failure.
		_, _ = c.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE key = ?", c.table), key(pkg))
		return nil, false, nil
	}

	return &analyzer.PackageVersionAnalysisResult{
		PackageVersion: pkg,
		Action:         analyzer.Action(action),
		AnalysisID:     analysisID.String,
		ReferenceURL:   referenceURL.String,
		Summary:        summary.String,
	}, true, nil
}

// Set stores a verdict for pkg, overwriting any existing entry.
func (c *SQLiteCache) Set(ctx context.Context, pkg *packagev1.PackageVersion, result *analyzer.PackageVersionAnalysisResult) error {
	if pkg == nil || result == nil {
		return nil
	}
	if c.ttl <= 0 {
		return nil
	}

	_, err := c.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (key, cached_at, action, analysis_id, reference_url, summary)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			cached_at = excluded.cached_at,
			action = excluded.action,
			analysis_id = excluded.analysis_id,
			reference_url = excluded.reference_url,
			summary = excluded.summary`, c.table),
		key(pkg), time.Now().Unix(), int(result.Action),
		result.AnalysisID, result.ReferenceURL, result.Summary)
	if err != nil {
		return fmt.Errorf("failed to write analysis cache: %w", err)
	}
	return nil
}
