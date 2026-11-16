package config

import (
	"testing"

	"github.com/safedep/pmg/internal/testenv"
)

func TestMain(m *testing.M) {
	testenv.Main(m, initConfig)
}
