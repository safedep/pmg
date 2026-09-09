//go:build windows

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Most profile paths hold a space, so an unquoted path breaks the command
// for the case it targets.
func TestUnwritableConfigDirRemedyQuotesThePath(t *testing.T) {
	t.Setenv("PMG_CONFIG_DIR", "")
	withCurrentUserHome(t, `C:\Users\John Doe`)

	dir := `C:\Users\John Doe\AppData\Roaming\safedep\pmg`
	help, fix := UnwritableConfigDirRemedy(dir)

	assert.Contains(t, fix, `takeown /R /D Y /F "`+dir+`"`)
	assert.Contains(t, fix, `icacls "`+dir+`" /grant "%USERNAME%":(OI)(CI)F /T`)
	assert.Contains(t, help, "elevated prompt")
}
