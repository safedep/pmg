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
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}
	defer Close()

	// Check that directory was created
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		t.Errorf("Log directory was not created: %s", logDir)
	}

	// Check that log file was created
	expectedLogFile := filepath.Join(logDir, time.Now().Format("20060102")+"-pmg.log")
	if _, err := os.Stat(expectedLogFile); os.IsNotExist(err) {
		t.Errorf("Log file was not created: %s", expectedLogFile)
	}
}

func TestLogEvent(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, ".pmg", "logs")

	// Initialize logger
	err := reinitializeForTest(logDir)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}
	defer Close()

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
	if err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}

	// Read the log file and verify the event was written
	logFilePath := filepath.Join(logDir, time.Now().Format("20060102")+"-pmg.log")
	data, err := os.ReadFile(logFilePath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	// Parse the JSON
	var loggedEvent Event
	err = json.Unmarshal(data, &loggedEvent)
	if err != nil {
		t.Fatalf("Failed to parse logged event: %v", err)
	}

	// Verify the event
	if loggedEvent.EventType != EventTypeMalwareBlocked {
		t.Errorf("Expected event type %s, got %s", EventTypeMalwareBlocked, loggedEvent.EventType)
	}
	if loggedEvent.PackageName != "evil-package" {
		t.Errorf("Expected package name 'evil-package', got '%s'", loggedEvent.PackageName)
	}
}

func TestLogMalwareBlocked(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, ".pmg", "logs")

	// Initialize logger
	err := reinitializeForTest(logDir)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}
	defer Close()

	// Log malware blocked event
	LogMalwareBlocked("malicious-pkg", "2.0.0", "pypi", "Contains known malware", nil)

	// Read and verify
	logFilePath := filepath.Join(logDir, time.Now().Format("20060102")+"-pmg.log")
	data, err := os.ReadFile(logFilePath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var event Event
	err = json.Unmarshal(data, &event)
	if err != nil {
		t.Fatalf("Failed to parse event: %v", err)
	}

	if event.EventType != EventTypeMalwareBlocked {
		t.Errorf("Expected event type %s, got %s", EventTypeMalwareBlocked, event.EventType)
	}
	if event.PackageName != "malicious-pkg" {
		t.Errorf("Expected package 'malicious-pkg', got '%s'", event.PackageName)
	}
	if event.Ecosystem != "pypi" {
		t.Errorf("Expected ecosystem 'pypi', got '%s'", event.Ecosystem)
	}
}

func TestInitializeWithFile(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "custom.log")

	// Initialize logger with custom file
	err := reinitializeForTest("")
	if err == nil {
		Close()
	}

	// Reset for custom file
	once = sync.Once{}
	err = InitializeWithFile(logFile)
	if err != nil {
		t.Fatalf("Failed to initialize logger with file: %v", err)
	}
	defer Close()

	// Log an event
	event := Event{
		EventType:   EventTypeMalwareBlocked,
		Message:     "Test custom file logging",
		PackageName: "test-package",
		Version:     "1.0.0",
		Ecosystem:   "npm",
	}

	err = LogEvent(event)
	if err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}

	// Verify the custom log file was created and contains the event
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("Custom log file was not created: %s", logFile)
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read custom log file: %v", err)
	}

	if len(data) == 0 {
		t.Error("Custom log file is empty")
	}

	var loggedEvent Event
	err = json.Unmarshal(data, &loggedEvent)
	if err != nil {
		t.Fatalf("Failed to parse logged event: %v", err)
	}

	if loggedEvent.PackageName != "test-package" {
		t.Errorf("Expected package 'test-package', got '%s'", loggedEvent.PackageName)
	}
}

func TestCleanupOldLogs(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, ".pmg", "logs")
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create log directory: %v", err)
	}

	// Create old log files
	oldDate := time.Now().AddDate(0, 0, -10)
	oldLogFile := filepath.Join(logDir, oldDate.Format("20060102")+"-pmg.log")
	err = os.WriteFile(oldLogFile, []byte("old log"), 0644)
	if err != nil {
		t.Fatalf("Failed to create old log file: %v", err)
	}

	// Change the modification time to make it appear old
	oldTime := time.Now().AddDate(0, 0, -10)
	err = os.Chtimes(oldLogFile, oldTime, oldTime)
	if err != nil {
		t.Fatalf("Failed to change file time: %v", err)
	}

	// Create a recent log file
	recentLogFile := filepath.Join(logDir, time.Now().Format("20060102")+"-pmg.log")
	err = os.WriteFile(recentLogFile, []byte("recent log"), 0644)
	if err != nil {
		t.Fatalf("Failed to create recent log file: %v", err)
	}

	// Initialize logger (which triggers cleanup)
	logger := &fileWithRotationLogger{}
	err = logger.init(logDir)
	if err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	defer logger.Close()

	// Give cleanup goroutine time to run
	time.Sleep(100 * time.Millisecond)

	// Check that old file was deleted
	if _, err := os.Stat(oldLogFile); !os.IsNotExist(err) {
		t.Error("Old log file should have been deleted")
	}

	// Check that recent file still exists
	if _, err := os.Stat(recentLogFile); os.IsNotExist(err) {
		t.Error("Recent log file should still exist")
	}
}
