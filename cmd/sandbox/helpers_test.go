package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/safedep/pmg/errcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapUsefulPreservesContextForConvertibleErrors(t *testing.T) {
	help := "Could not create the user profile directory. Check filesystem permissions for /var/root/pmg-repro/sandbox/profiles."
	err := wrapUseful(
		fmt.Errorf("failed to create user profile directory /var/root/pmg-repro/sandbox/profiles: %w", fs.ErrPermission),
		errcodes.PermissionDenied,
		help,
	)

	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.PermissionDenied, usefulErr.Code())
	assert.Equal(t, help, usefulErr.Help())
	assert.Contains(t, usefulErr.HumanError(), "failed to create user profile directory")
}

func TestWrapUsefulLeavesExistingUsefulErrorsUnchanged(t *testing.T) {
	original := usefulerror.NewUsefulError().
		WithCode(errcodes.InvalidArgument).
		WithHumanError("already classified").
		WithHelp("existing help").
		Wrap(errors.New("root"))

	err := wrapUseful(original, errcodes.PermissionDenied, "new help")

	assert.Same(t, original, err)
	usefulErr, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok)
	assert.Equal(t, errcodes.InvalidArgument, usefulErr.Code())
	assert.Equal(t, "existing help", usefulErr.Help())
}
