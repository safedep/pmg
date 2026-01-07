//go:build windows
// +build windows

package flows

import (
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPlatformPauseResumeProcess(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	cmd := exec.Command("ping", "127.0.0.1", "-n", "60")
	err := cmd.Start()
	assert.NoError(t, err)

	defer cmd.Process.Kill()

	time.Sleep(100 * time.Millisecond)

	err = platformPauseProcess(cmd)
	assert.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	err = platformResumeProcess(cmd)
	assert.NoError(t, err)
}

func TestPlatformPauseProcessNil(t *testing.T) {
	err := platformPauseProcess(nil)
	assert.NoError(t, err)
}

func TestPlatformResumeProcessNil(t *testing.T) {
	err := platformResumeProcess(nil)
	assert.NoError(t, err)
}

func TestPlatformPauseProcessNilProcess(t *testing.T) {
	cmd := exec.Command("ping", "127.0.0.1")
	err := platformPauseProcess(cmd)
	assert.NoError(t, err)
}

func TestPlatformResumeProcessNilProcess(t *testing.T) {
	cmd := exec.Command("ping", "127.0.0.1")

	err := platformResumeProcess(cmd)
	assert.NoError(t, err)
}

func TestPlatformPauseProcessExited(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	cmd := exec.Command("cmd", "/c", "exit 0")
	err := cmd.Start()
	assert.NoError(t, err)

	defer cmd.Process.Kill()

	err = platformPauseProcess(cmd)
	assert.NoError(t, err)
}

func TestPlatformResumeProcessExited(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	cmd := exec.Command("cmd", "/c", "exit 0")
	err := cmd.Start()
	assert.NoError(t, err)

	defer cmd.Process.Kill()

	err = platformResumeProcess(cmd)
	assert.NoError(t, err)
}

func TestPlatformPauseResumeMultipleTimes(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-only test")
	}

	cmd := exec.Command("ping", "127.0.0.1", "-n", "60")
	err := cmd.Start()
	assert.NoError(t, err)

	defer cmd.Process.Kill()

	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 3; i++ {
		err = platformPauseProcess(cmd)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		err = platformResumeProcess(cmd)
		assert.NoError(t, err)

		time.Sleep(100 * time.Millisecond)
	}
}
