package setup

import (
	"testing"

	"github.com/safedep/pmg/internal/doctor"
	"github.com/safedep/pmg/proxy/certmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCACheckAbsentIsWarn(t *testing.T) {
	res := evaluateCACheck(t.TempDir(), false, false, true)
	assert.Equal(t, doctor.StatusWarn, res.Status)
}

func TestCACheckTrustedIsPass(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	res := evaluateCACheck(dir, true, false, true)
	assert.Equal(t, doctor.StatusPass, res.Status)
}

func TestCACheckOnDiskNotTrustedMacWinIsFail(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	res := evaluateCACheck(dir, false, false, true) // userScopeSupported=true (mac/win)
	assert.Equal(t, doctor.StatusFail, res.Status)
}

func TestCACheckOnDiskNotTrustedLinuxIsWarn(t *testing.T) {
	dir := t.TempDir()
	ca, err := certmanager.GenerateCA(certmanager.PersistentCACertManagerConfig())
	require.NoError(t, err)
	require.NoError(t, certmanager.SaveCA(dir, ca))

	res := evaluateCACheck(dir, false, false, false) // userScopeSupported=false (linux)
	assert.Equal(t, doctor.StatusWarn, res.Status)
}
