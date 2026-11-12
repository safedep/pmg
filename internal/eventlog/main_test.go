package eventlog

import (
	"testing"

	"github.com/safedep/pmg/config"
	"github.com/safedep/pmg/internal/testenv"
)

func TestMain(m *testing.M) {
	testenv.Main(m, config.Reload)
}
