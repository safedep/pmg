package flows

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/safedep/dry/localdb"
	"github.com/safedep/pmg/config"
	"github.com/stretchr/testify/assert"
)

type fakeLocalDBManager struct {
	storeCalls int
	storeErr   error
}

func (f *fakeLocalDBManager) Store(context.Context, localdb.Descriptor) (*localdb.Store, error) {
	f.storeCalls++
	return nil, f.storeErr
}

func (f *fakeLocalDBManager) Close() error {
	return nil
}

func TestBuildMalysisCacheDisabledDoesNotOpenLocalDB(t *testing.T) {
	db := &fakeLocalDBManager{}

	cache := buildMalysisCache(context.Background(), db, config.MalysisCacheConfig{
		Enabled: false,
		TTL:     time.Hour,
	})

	assert.Nil(t, cache)
	assert.Equal(t, 0, db.storeCalls)
}

func TestBuildMalysisCacheStoreErrorDegradesToNil(t *testing.T) {
	db := &fakeLocalDBManager{storeErr: errors.New("db unavailable")}

	cache := buildMalysisCache(context.Background(), db, config.MalysisCacheConfig{
		Enabled: true,
		TTL:     time.Hour,
	})

	assert.Nil(t, cache)
	assert.Equal(t, 1, db.storeCalls)
}
