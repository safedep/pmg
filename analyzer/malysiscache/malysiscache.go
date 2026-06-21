// Package malysiscache is a localdb-backed persistent cache of benign Malysis
// verdicts. It implements analyzer.MalysisCache. It owns only its localdb
// module schema; the DB file location is owned by the config package and the
// Manager lifecycle by the composition root.
package malysiscache

import (
	"context"
	"database/sql"
	"errors"
	"time"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/log"
	"github.com/safedep/pmg/analyzer"
	"github.com/safedep/pmg/config"
)

var _ analyzer.MalysisCache = (*Cache)(nil)

const moduleName = "malysis_cache"

// Descriptor is the localdb module contract: the verdicts table. Migrations are
// append-only — never edit or reorder an existing entry.
func Descriptor() localdb.Descriptor {
	return localdb.Descriptor{
		Name: moduleName,
		Migrations: []string{
			`CREATE TABLE malysis_cache_verdicts (
				ecosystem     TEXT    NOT NULL,
				name          TEXT    NOT NULL,
				version       TEXT    NOT NULL,
				analysis_id   TEXT,
				reference_url TEXT,
				summary       TEXT,
				created_at    INTEGER NOT NULL,
				expires_at    INTEGER,
				PRIMARY KEY (ecosystem, name, version)
			)`,
		},
	}
}

type Cache struct {
	db  *sql.DB
	cfg config.MalysisCacheConfig
	now func() time.Time
}

func New(store *localdb.Store, cfg config.MalysisCacheConfig) *Cache {
	return &Cache{db: store.DB(), cfg: cfg, now: time.Now}
}

type Stats struct {
	Count  int
	Oldest time.Time
	Newest time.Time
}

func (c *Cache) Stats(ctx context.Context) (Stats, error) {
	var s Stats
	var oldest, newest sql.NullInt64
	err := c.db.QueryRowContext(ctx,
		`SELECT COUNT(*), MIN(created_at), MAX(created_at) FROM malysis_cache_verdicts`).
		Scan(&s.Count, &oldest, &newest)
	if err != nil {
		return Stats{}, err
	}
	if oldest.Valid {
		s.Oldest = time.Unix(oldest.Int64, 0)
	}
	if newest.Valid {
		s.Newest = time.Unix(newest.Int64, 0)
	}
	return s, nil
}

func (c *Cache) Clear(ctx context.Context) error {
	_, err := c.db.ExecContext(ctx, `DELETE FROM malysis_cache_verdicts`)
	return err
}

func (c *Cache) Get(ctx context.Context, pkg *packagev1.PackageVersion) (*analyzer.PackageVersionAnalysisResult, bool, error) {
	eco, name, version := packageKey(pkg)

	var analysisID, referenceURL, summary string
	var createdAt int64
	var expiresAt sql.NullInt64
	err := c.db.QueryRowContext(ctx,
		`SELECT analysis_id, reference_url, summary, created_at, expires_at
		 FROM malysis_cache_verdicts WHERE ecosystem=? AND name=? AND version=?`,
		eco, name, version).
		Scan(&analysisID, &referenceURL, &summary, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	if c.expired(createdAt, expiresAt) {
		if _, derr := c.db.ExecContext(ctx,
			`DELETE FROM malysis_cache_verdicts WHERE ecosystem=? AND name=? AND version=?`,
			eco, name, version); derr != nil {
			log.Warnf("malysiscache: failed to delete expired entry: %v", derr)
		}
		return nil, false, nil
	}

	result, ok := reconstruct(eco, name, version, analysisID, referenceURL, summary)
	if !ok {
		return nil, false, nil
	}
	return result, true, nil
}

func (c *Cache) Set(ctx context.Context, pkg *packagev1.PackageVersion, result *analyzer.PackageVersionAnalysisResult) error {
	if !cacheable(result) {
		return nil
	}
	// Non-positive TTL disables persistence (MalysisCacheConfig.TTL contract).
	if c.cfg.TTL <= 0 {
		return nil
	}
	eco, name, version := packageKey(pkg)

	// expires_at stays NULL in v1; a future backend hint populates it.
	_, err := c.db.ExecContext(ctx,
		`INSERT INTO malysis_cache_verdicts
		   (ecosystem, name, version, analysis_id, reference_url, summary, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(ecosystem, name, version) DO UPDATE SET
		   analysis_id   = excluded.analysis_id,
		   reference_url = excluded.reference_url,
		   summary       = excluded.summary,
		   created_at    = excluded.created_at,
		   expires_at    = excluded.expires_at`,
		eco, name, version, result.AnalysisID, result.ReferenceURL, result.Summary, c.now().Unix())
	return err
}

func (c *Cache) expired(createdAt int64, expiresAt sql.NullInt64) bool {
	exp := createdAt + int64(c.cfg.TTL.Seconds())
	if expiresAt.Valid {
		exp = expiresAt.Int64
	}
	return c.now().Unix() >= exp
}
