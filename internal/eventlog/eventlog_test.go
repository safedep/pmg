package eventlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetDefaultLogDir(t *testing.T) {
	logDir, err := GetDefaultLogDir()
	assert.NoError(t, err, "failed to get default log directory")

	assert.NotEmpty(t, logDir, "log directory should not be empty")
	assert.Contains(t, logDir, "safedep/pmg/logs")
}

func TestLoggerInitialization(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "pmg", "logs")

	// Initialize logger
	err := InitializeWithDir(logDir)
	assert.NoError(t, err, "Failed to initialize logger")
	defer func() {
		err := Close()
		assert.NoError(t, err)
	}()

	// Check that directory was created
	_, err = os.Stat(logDir)
	assert.False(t, os.IsNotExist(err), "Log directory was not created: %s", logDir)

	// Check that log file was created
	expectedLogFile := filepath.Join(logDir, time.Now().Format("20060102")+"-pmg.log")
	_, err = os.Stat(expectedLogFile)
	assert.False(t, os.IsNotExist(err), "Log file was not created: %s", expectedLogFile)
}

func TestLogEvent(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, ".pmg", "logs")

	// Initialize logger
	err := reinitializeForTest(logDir)
	assert.NoError(t, err, "Failed to initialize logger")
	defer func() {
		err := Close()
		assert.NoError(t, err)
	}()

	// Log an event
	event := Event{
		EventType:   EventTypeMalwareBlocked,
		Message:     "Test malware blocked",
		PackageName: "evil-package",
		Version:     "1.0.0",
		Ecosystem:   "npm",
		Details: map[string]interface{}{
			"reason": "Known malicious",
		},
	}

	err = LogEvent(event)
	assert.NoError(t, err, "Failed to log event")

	// Read the log file and verify the event was written
	logFilePath := filepath.Join(logDir, time.Now().Format("20060102")+"-pmg.log")
	data, err := os.ReadFile(logFilePath)
	assert.NoError(t, err, "Failed to read log file")

	// Parse the JSON
	var loggedEvent Event
	err = json.Unmarshal(data, &loggedEvent)
	assert.NoError(t, err, "Failed to parse logged event")

	// Verify the event
	assert.Equal(t, EventTypeMalwareBlocked, loggedEvent.EventType)
	assert.Equal(t, "evil-package", loggedEvent.PackageName)
}

func TestLogMalwareBlocked(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, ".pmg", "logs")

	// Initialize logger
	err := reinitializeForTest(logDir)
	assert.NoError(t, err, "Failed to initialize logger")
	defer func() {
		err := Close()
		assert.NoError(t, err)
	}()

	// Log malware blocked event
	LogMalwareBlocked("malicious-pkg", "2.0.0", "pypi", "Contains known malware", nil)

	// Read and verify
	logFilePath := filepath.Join(logDir, time.Now().Format("20060102")+"-pmg.log")
	data, err := os.ReadFile(logFilePath)
	assert.NoError(t, err, "Failed to read log file")

	var event Event
	err = json.Unmarshal(data, &event)
	assert.NoError(t, err, "Failed to parse event")

	assert.Equal(t, EventTypeMalwareBlocked, event.EventType)
	assert.Equal(t, "malicious-pkg", event.PackageName)
	assert.Equal(t, "pypi", event.Ecosystem)
}

func TestInitializeWithFile(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "custom.log")

	// Initialize logger with custom file
	err := reinitializeForTest("")
	if err == nil {
		_ = Close()
	}

	// Reset for custom file
	once = sync.Once{}
	err = InitializeWithFile(logFile)
	assert.NoError(t, err, "Failed to initialize logger with file")
	defer func() {
		err := Close()
		assert.NoError(t, err)
	}()

	// Log an event
	event := Event{
		EventType:   EventTypeMalwareBlocked,
		Message:     "Test custom file logging",
		PackageName: "test-package",
		Version:     "1.0.0",
		Ecosystem:   "npm",
	}

	err = LogEvent(event)
	assert.NoError(t, err, "Failed to log event")

	// Verify the custom log file was created and contains the event
	_, err = os.Stat(logFile)
	assert.False(t, os.IsNotExist(err), "Custom log file was not created: %s", logFile)

	data, err := os.ReadFile(logFile)
	assert.NoError(t, err, "Failed to read custom log file")
	assert.NotEmpty(t, data, "Custom log file is empty")

	var loggedEvent Event
	err = json.Unmarshal(data, &loggedEvent)
	assert.NoError(t, err, "Failed to parse logged event")
	assert.Equal(t, "test-package", loggedEvent.PackageName)
}

func TestCleanupOldLogs(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, ".pmg", "logs")
	err := os.MkdirAll(logDir, 0755)
	assert.NoError(t, err, "Failed to create log directory")

	// Create old log files
	oldDate := time.Now().AddDate(0, 0, -10)
	oldLogFile := filepath.Join(logDir, oldDate.Format("20060102")+"-pmg.log")
	err = os.WriteFile(oldLogFile, []byte("old log"), 0644)
	assert.NoError(t, err, "Failed to create old log file")

	// Change the modification time to make it appear old
	oldTime := time.Now().AddDate(0, 0, -10)
	err = os.Chtimes(oldLogFile, oldTime, oldTime)
	assert.NoError(t, err, "Failed to change file time")

	// Create a recent log file
	recentLogFile := filepath.Join(logDir, time.Now().Format("20060102")+"-pmg.log")
	err = os.WriteFile(recentLogFile, []byte("recent log"), 0644)
	assert.NoError(t, err, "Failed to create recent log file")

	// Initialize logger (which triggers cleanup)
	logger := &fileWithRotationLogger{}
	err = logger.init(logDir)
	assert.NoError(t, err, "Failed to initialize logger")

	defer func() {
		err := logger.Close()
		assert.NoError(t, err)
	}()

	// Give cleanup goroutine time to run
	time.Sleep(100 * time.Millisecond)

	// Check that old file was deleted
	_, err = os.Stat(oldLogFile)
	assert.True(t, os.IsNotExist(err), "Old log file should have been deleted")

	// Check that recent file still exists
	_, err = os.Stat(recentLogFile)
	assert.False(t, os.IsNotExist(err), "Recent log file should still exist")
}
