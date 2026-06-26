package localstore

import (
	"github.com/safedep/dry/localdb"
	"github.com/safedep/pmg/config"
)

func NewManager(cfg *config.RuntimeConfig) localdb.Manager {
	return localdb.New(localdb.Config{
		Dir:      cfg.LocalDBDir(),
		FileName: cfg.LocalDBFileName(),
	})
}
